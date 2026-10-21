from __future__ import annotations

import html
import json
import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

from .artifacts import discover_artifacts
from .attack_mapper import apply_attack_mapping, build_attack_navigator_layer, load_attack_techniques
from .case_store import MemoryCaseStore
from .citations import (
    catalog_from_citations,
    citation_for_binary,
    citation_from_event,
    drop_uncited,
    file_citation,
)
from .event_detectors import findings_from_artifact_events
from .ioc_pipeline import extract_iocs
from .llama_workflow import LlamaWorkflow, MockLlamaWorkflow, heuristic_fallback, prompt_template_text
from .manifest import (
    build_run_manifest,
    canonical_report_sha256,
    hash_input_tree,
    prompt_template_sha256,
    write_run_manifest,
)
from .models import ArtifactEvent, BinaryFeature, CaseReport, Citation, Finding, TimelineEvent, utc_now_iso
from .pdf_report import write_pdf_report
from .plugins import PluginRegistry
from .security import stays_in_tree
from .sigma_rules import evaluate_sigma_rules
from .stix_export import build_stix_bundle
from .timeline import normalize_timeline
from .timeline_imports import findings_from_imported_timelines
from .tools import ToolRegistry
from .verifier import MockClaimJudge, resolve_verifier_mode, verifier_limit_name, verify_findings
from .workers import PIPELINE_WORKER
from .yara_detector import scan_paths_with_yara


@dataclass(slots=True)
class PipelineConfig:
    case_id: str
    input_dir: Path
    output_dir: Path
    enable_llama: bool = True
    llama_endpoint: str = "http://localhost:11434"
    llama_model: str = "llama3.1:8b"
    plugin_registry: PluginRegistry | None = None
    max_text_bytes: int = 4 * 1024 * 1024
    rules_dir: Path | None = None
    sigma_rules_dir: Path | None = None
    attack_stix_path: Path | None = None
    openai_compatible_endpoint: str | None = None
    openai_api_key: str | None = None
    llm_provider: str | None = None
    seed: int = 0
    verifier_judge: str | None = None


def _severity_rank(value: str) -> int:
    mapping = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    return mapping.get(value.lower(), 0)


def _build_summary(
    findings: list[Finding],
    timeline: list[TimelineEvent],
    iocs_count: int,
    model_summary: dict[str, Any] | None,
) -> dict[str, Any]:
    top = sorted(findings, key=lambda f: (_severity_rank(f.severity), f.confidence), reverse=True)[:5]
    severities: dict[str, int] = {}
    for f in findings:
        severities[f.severity] = severities.get(f.severity, 0) + 1
    base = {
        "total_findings": len(findings),
        "severity_breakdown": severities,
        "attack_technique_coverage": len({f.technique_id for f in findings if f.technique_id}),
        "ioc_count": iocs_count,
        "top_findings": [
            {
                "id": f.finding_id,
                "title": f.title,
                "severity": f.severity,
                "confidence": f.confidence,
            }
            for f in top
        ],
        "timeline_events": len(timeline),
    }
    if model_summary:
        base["llama_summary"] = model_summary
    return base


def _to_markdown(report: CaseReport) -> str:
    lines: list[str] = []
    lines.append(f"# Case Report: {report.case_id}")
    lines.append("")
    lines.append(f"- Generated at: {report.generated_at}")
    lines.append(f"- Total findings: {report.summary.get('total_findings', 0)}")
    lines.append(f"- Timeline events: {report.summary.get('timeline_events', 0)}")
    lines.append(f"- IOCs extracted: {report.summary.get('ioc_count', 0)}")
    lines.append("")
    lines.append("## Binary Features")
    for binary in report.binary_features:
        lines.append(f"- `{binary.path}`")
        lines.append(f"  - SHA256: `{binary.sha256}`")
        lines.append(f"  - Entropy: `{binary.entropy}`")
        lines.append(f"  - Suspicious score: `{binary.suspicious_score}`")
        if binary.rationale:
            lines.append(f"  - Rationale: {'; '.join(binary.rationale)}")
    lines.append("")
    lines.append("## Findings")
    if not report.findings:
        lines.append("- No findings produced.")
    for item in report.findings:
        lines.append(f"- [{item.severity.upper()}] {item.title} ({item.confidence:.2f})")
        if item.evidence:
            lines.append(f"  - Evidence: {'; '.join(item.evidence)}")
        if item.recommendation:
            lines.append(f"  - Recommendation: {item.recommendation}")
        lines.append(f"  - Status: {_review_label(item)}")
        if item.verification:
            lines.append(f"  - Verification: {item.verification}")
        if item.citations:
            for citation in item.citations:
                lines.append(f"  - Citation: {_format_citation(citation)}")
        else:
            lines.append("  - Citation: none")
    lines.append("")
    lines.append("## Verifier")
    verdicts = report.summary.get("verification") or []
    if not verdicts:
        lines.append("- No verdicts recorded.")
    for item in verdicts:
        if isinstance(item, dict):
            lines.append(
                f"- {item.get('verdict')}: `{item.get('finding_id')}` "
                f"({item.get('judge')}) {item.get('reason')}"
            )
    lines.append("")
    lines.append("## IOCs")
    if not report.iocs:
        lines.append("- No IOCs extracted.")
    for ioc in report.iocs[:200]:
        lines.append(f"- `{ioc.ioc_type}` `{ioc.value}` (sources={','.join(ioc.sources[:3])})")
    lines.append("")
    lines.append("## Timeline")
    for event in report.timeline:
        ts = event.timestamp or "unknown-time"
        lines.append(f"- `{ts}` | `{event.event_type}` | {event.description}")
    return "\n".join(lines)


def _to_html(report: CaseReport) -> str:
    payload = json.dumps(report.to_dict())
    escaped_case = html.escape(report.case_id)
    return f"""<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>Auto Forensics Report - {escaped_case}</title>
  <style>
    :root {{
      --bg: #f4f6f3;
      --panel: #ffffff;
      --ink: #17201a;
      --muted: #4f5e54;
      --line: #ced7d0;
      --accent: #0f6f58;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; font-family: "IBM Plex Sans", "Segoe UI", sans-serif; color: var(--ink); background: linear-gradient(180deg, #f9fcf8, var(--bg)); }}
    main {{ max-width: 1200px; margin: 0 auto; padding: 1.2rem; display: grid; gap: 0.9rem; }}
    .card {{ background: var(--panel); border: 1px solid var(--line); border-radius: 14px; padding: 1rem; box-shadow: 0 5px 16px rgba(14, 35, 26, 0.08); }}
    .meta {{ display: flex; flex-wrap: wrap; gap: 0.8rem; color: var(--muted); }}
    .kpi {{ border: 1px solid var(--line); border-radius: 10px; padding: 0.5rem 0.7rem; background: #f8fbf7; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.93rem; }}
    th, td {{ text-align: left; border-bottom: 1px solid var(--line); padding: 0.5rem; vertical-align: top; }}
    th {{ color: var(--muted); font-weight: 600; }}
    .chip {{ display: inline-block; font-size: 0.8rem; border-radius: 999px; padding: 0.14rem 0.55rem; border: 1px solid var(--line); background: #f3faf6; }}
    .sev-critical {{ background: #ffe6df; border-color: #f2b9a7; }}
    .sev-high {{ background: #fff0da; border-color: #edc28a; }}
    .sev-medium {{ background: #f7f3d5; border-color: #d8cb88; }}
    .sev-low {{ background: #e7f3e7; border-color: #bad8b8; }}
    .toolbar {{ display: flex; gap: 0.6rem; flex-wrap: wrap; align-items: center; }}
    input, select {{ border: 1px solid var(--line); border-radius: 8px; padding: 0.4rem 0.6rem; }}
    @media (max-width: 900px) {{ table, thead, tbody, th, td, tr {{ display: block; }} th {{ display: none; }} td {{ border: none; border-bottom: 1px solid var(--line); }} }}
  </style>
</head>
<body>
  <main>
    <section class=\"card\">
      <h1>Case Report: {escaped_case}</h1>
      <p class=\"meta\">Generated at <strong>{html.escape(report.generated_at)}</strong></p>
      <div class=\"meta\" id=\"kpis\"></div>
    </section>
    <section class=\"card\">
      <h2>Findings</h2>
      <table id=\"findings\"></table>
    </section>
    <section class=\"card\">
      <h2>Timeline</h2>
      <div class=\"toolbar\">
        <label>Filter event type <input id=\"typeFilter\" placeholder=\"e.g. dns_query\" /></label>
      </div>
      <table id=\"timeline\"></table>
    </section>
    <section class=\"card\">
      <h2>IOCs</h2>
      <table id=\"iocs\"></table>
    </section>
  </main>
  <script>
    const report = {payload};
    function esc(value) {{
      return String(value === undefined || value === null ? "" : value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");
    }}
    document.getElementById("kpis").innerHTML = [
      `<span class=\"kpi\">Findings: <strong>${{report.summary.total_findings || 0}}</strong></span>`,
      `<span class=\"kpi\">Timeline: <strong>${{report.summary.timeline_events || 0}}</strong></span>`,
      `<span class=\"kpi\">IOCs: <strong>${{report.summary.ioc_count || 0}}</strong></span>`,
      `<span class=\"kpi\">ATT&CK techniques: <strong>${{report.summary.attack_technique_coverage || 0}}</strong></span>`
    ].join("");

    function renderFindings() {{
      const rows = report.findings.map(item =>
        `<tr>` +
        `<td><span class=\"chip sev-${{esc(item.severity)}}\">${{esc(item.severity)}}</span></td>` +
        `<td>${{esc(item.title)}}</td>` +
        `<td>${{esc(item.tactic)}}</td>` +
        `<td>${{esc(item.technique_id || "")}}</td>` +
        `<td>${{esc(item.confidence)}}</td>` +
        `<td>${{esc(item.review_status || "unverified")}}${{item.verification ? " · " + esc(item.verification) : ""}}</td>` +
        `<td>${{esc(citeLabel(item))}}</td>` +
        `</tr>`
      ).join("");
      document.getElementById("findings").innerHTML =
        `<thead><tr><th>Severity</th><th>Title</th><th>Tactic</th><th>Technique</th><th>Confidence</th><th>Review</th><th>Citation</th></tr></thead>` +
        `<tbody>${{rows || "<tr><td colspan='7'>No findings.</td></tr>"}}</tbody>`;
    }}

    function citeLabel(item) {{
      const cites = item.citations || [];
      if (!cites.length) return "uncited";
      const first = cites[0];
      const loc = first.row !== null && first.row !== undefined ? "row " + first.row : "offset " + first.offset;
      const extra = cites.length > 1 ? " +" + (cites.length - 1) : "";
      return loc + extra;
    }}

    function renderTimeline(filterValue) {{
      const rows = report.timeline
        .filter(item => !filterValue || String(item.event_type || "").toLowerCase().includes(filterValue.toLowerCase()))
        .map(item =>
          `<tr>` +
          `<td>${{esc(item.timestamp || "")}}</td>` +
          `<td>${{esc(item.event_type)}}</td>` +
          `<td>${{esc(item.source)}}</td>` +
          `<td>${{esc(item.description)}}</td>` +
          `</tr>`
        ).join("");
      document.getElementById("timeline").innerHTML =
        `<thead><tr><th>Timestamp</th><th>Type</th><th>Source</th><th>Description</th></tr></thead>` +
        `<tbody>${{rows || "<tr><td colspan='4'>No timeline events.</td></tr>"}}</tbody>`;
    }}

    function renderIocs() {{
      const rows = (report.iocs || []).map(item =>
        `<tr>` +
        `<td>${{esc(item.ioc_type)}}</td>` +
        `<td>${{esc(item.value)}}</td>` +
        `<td>${{esc((item.sources || []).join(", "))}}</td>` +
        `</tr>`
      ).join("");
      document.getElementById("iocs").innerHTML =
        `<thead><tr><th>Type</th><th>Value</th><th>Sources</th></tr></thead>` +
        `<tbody>${{rows || "<tr><td colspan='3'>No IOCs.</td></tr>"}}</tbody>`;
    }}

    renderFindings();
    renderTimeline("");
    renderIocs();
    document.getElementById("typeFilter").addEventListener("input", (event) => renderTimeline(event.target.value));
  </script>
</body>
</html>
"""


def resolve_llm_provider(config: PipelineConfig) -> str:
    """Choose mock, ollama, openai_compatible, or off."""
    if not config.enable_llama or config.llm_provider == "off":
        return "off"
    if config.llm_provider in {"mock", "ollama", "openai_compatible"}:
        return config.llm_provider
    if config.openai_compatible_endpoint:
        return "openai_compatible"
    return "ollama"


def _review_label(item: Finding) -> str:
    who = "LLM-generated" if item.origin == "llm" else item.origin
    return f"worker {item.worker}; {who}, analyst-{item.review_status}"


def _format_citation(citation: Citation) -> str:
    if citation.row is not None:
        location = f"row {citation.row}"
    else:
        location = f"offset {citation.offset}"
    return f"`{citation.artifact_id}` `{citation.source_file}` {location} `{citation.sha256}`"


def _evidence_catalog(
    input_dir: Path,
    artifacts: list[ArtifactEvent],
    binary_features: list[BinaryFeature],
) -> dict[tuple[str, str], Citation]:
    pointers: list[Citation] = []
    for event in artifacts:
        pointer = citation_from_event(event)
        if pointer is not None:
            pointers.append(pointer)
    for binary in binary_features:
        pointers.append(citation_for_binary(binary))
    root = input_dir.resolve()
    for path in sorted(root.rglob("*")):
        if not stays_in_tree(path, root) or len(path.relative_to(root).parts) > 20:
            continue
        pointers.append(file_citation(path, root=root))
    return catalog_from_citations(pointers)


class _LlamaJudge:
    """Adapter so the verifier can call a live model without importing it."""

    name = "llm"

    def __init__(self, workflow: LlamaWorkflow) -> None:
        self._workflow = workflow

    def judge(self, claim: str, cited_text: str) -> str | None:
        return self._workflow.judge_claim(claim, cited_text)


def _claim_judge(mode: str, workflow: LlamaWorkflow | MockLlamaWorkflow | None) -> MockClaimJudge | _LlamaJudge | None:
    if mode == "mock":
        return MockClaimJudge()
    if mode == "llm" and isinstance(workflow, LlamaWorkflow):
        return _LlamaJudge(workflow)
    return None


def run_case(config: PipelineConfig) -> CaseReport:
    """Parse a directory, draft findings, drop uncited drafts, and write a manifest.

    This function is the ``pipeline`` worker. It is the only worker that
    runs. Tool stages go through an allow-list, and the case store
    records those calls plus the findings. There is no orchestrator.
    """
    started_at = utc_now_iso()
    store = MemoryCaseStore()
    tools = ToolRegistry(worker=PIPELINE_WORKER, store=store)
    plugin_registry = config.plugin_registry or PluginRegistry()
    plugin_registry.register_defaults()
    provider = resolve_llm_provider(config)
    workflow: LlamaWorkflow | MockLlamaWorkflow | None = None
    if provider == "mock":
        workflow = MockLlamaWorkflow()
    elif provider == "openai_compatible":
        workflow = LlamaWorkflow(
            config.openai_compatible_endpoint or "",
            config.llama_model,
            provider="openai_compatible",
            api_key=config.openai_api_key,
            seed=config.seed,
        )
    elif provider == "ollama":
        workflow = LlamaWorkflow(config.llama_endpoint, config.llama_model, seed=config.seed)

    def parse_artifacts() -> tuple[list[ArtifactEvent], list[Path]]:
        return discover_artifacts(
            config.input_dir,
            max_text_bytes=config.max_text_bytes,
            parser_registry=plugin_registry.artifact_parsers,
        )

    def analyze_binaries(found: list[Path]) -> list[BinaryFeature]:
        with ThreadPoolExecutor(max_workers=4, thread_name_prefix="af-binary") as pool:
            return list(pool.map(plugin_registry.analyze_binary, found))

    def yara_scan(candidates: list[Path]) -> tuple[list[Finding], list[TimelineEvent]]:
        return scan_paths_with_yara(candidates, config.rules_dir)

    def event_findings(parsed: list[ArtifactEvent]) -> list[Finding]:
        return findings_from_artifact_events(parsed) + findings_from_imported_timelines(parsed)

    def draft_findings(
        parsed: list[ArtifactEvent],
        features: list[BinaryFeature],
        catalog_list: list[Citation],
    ) -> tuple[list[Finding], list[TimelineEvent]]:
        drafted: list[Finding] = []
        hints: list[TimelineEvent] = []
        if workflow:
            def analyze_one(binary: BinaryFeature) -> tuple[list[Finding], list[TimelineEvent]]:
                try:
                    related_events = normalize_timeline(parsed, [binary], [])
                    return workflow.analyze_binary(binary, related_events[-10:], catalog_list)
                except Exception as exc:
                    logger.warning("LLM analysis failed for %s: %s — using heuristic fallback", binary.path, exc)
                    return heuristic_fallback(binary, citation_for_binary(binary))

            with ThreadPoolExecutor(max_workers=3, thread_name_prefix="af-llm") as pool:
                for model_findings, model_hints in pool.map(analyze_one, features):
                    drafted.extend(model_findings)
                    hints.extend(model_hints)
        else:
            for binary in features:
                if binary.suspicious_score > 0:
                    model_findings, model_hints = heuristic_fallback(binary, citation_for_binary(binary))
                    drafted.extend(model_findings)
                    hints.extend(model_hints)
        return drafted, hints

    def detector_findings(
        parsed: list[ArtifactEvent],
        features: list[BinaryFeature],
        timeline: list[TimelineEvent],
    ) -> list[Finding]:
        return plugin_registry.detectors.detect(parsed, features, timeline)

    def sigma_findings(timeline: list[TimelineEvent]) -> list[Finding]:
        return evaluate_sigma_rules(timeline, config.sigma_rules_dir or config.rules_dir)

    tools.allow("parse_artifacts", parse_artifacts)
    tools.allow("analyze_binaries", analyze_binaries)
    tools.allow("yara_scan", yara_scan)
    tools.allow("event_detectors", event_findings)
    tools.allow("draft_findings", draft_findings)
    tools.allow("builtin_detectors", detector_findings)
    tools.allow("sigma_rules", sigma_findings)

    artifacts, binaries = tools.call("parse_artifacts")
    binary_features = tools.call("analyze_binaries", binaries)
    # Cap directory traversal depth at 20 to avoid runaway scans on deep trees.
    evidence_root = config.input_dir.resolve()
    scan_candidates = [
        path
        for path in sorted(evidence_root.rglob("*"))
        if stays_in_tree(path, evidence_root) and len(path.relative_to(evidence_root).parts) <= 20
    ]

    findings: list[Finding] = []
    generated_hints: list[TimelineEvent] = []
    try:
        yara_found, yara_hints = tools.call("yara_scan", scan_candidates)
        findings.extend(yara_found)
        generated_hints.extend(yara_hints)
    except Exception as exc:
        logger.warning("YARA scan failed: %s", exc)

    findings.extend(tools.call("event_detectors", artifacts))
    catalog = _evidence_catalog(config.input_dir, artifacts, binary_features)
    drafted, draft_hints = tools.call("draft_findings", artifacts, binary_features, list(catalog.values()))
    findings.extend(drafted)
    generated_hints.extend(draft_hints)

    timeline = normalize_timeline(artifacts, binary_features, generated_hints)
    findings.extend(tools.call("builtin_detectors", artifacts, binary_features, timeline))
    findings.extend(tools.call("sigma_rules", timeline))
    findings, dropped_uncited = drop_uncited(findings, catalog)
    judge_mode = resolve_verifier_mode(provider, config.verifier_judge)
    judge = _claim_judge(judge_mode, workflow)
    live_llm = provider in {"ollama", "openai_compatible"}

    def verify_claims() -> tuple[list[Finding], list[Any]]:
        return verify_findings(findings, config.input_dir, judge, live_llm=live_llm)

    tools.allow("verify_findings", verify_claims)
    findings, verdicts = tools.call("verify_findings")
    verdicts = sorted(verdicts, key=lambda item: item.finding_id)
    dropped_unsupported = sum(1 for item in verdicts if item.verdict == "rejected")
    findings = sorted(findings, key=lambda item: item.finding_id)
    store.add_findings(PIPELINE_WORKER, findings)
    findings = store.findings()

    model_summary: dict[str, Any] | None = None
    if workflow:
        def summarize_case() -> dict[str, Any] | None:
            return workflow.summarize_case(findings, timeline)

        tools.allow("summarize_case", summarize_case)
        model_summary = tools.call("summarize_case")

    attack_techniques = load_attack_techniques(config.attack_stix_path)
    findings = apply_attack_mapping(findings, attack_techniques)
    navigator_layer = build_attack_navigator_layer(config.case_id, findings, attack_techniques)
    iocs = extract_iocs(binary_features, findings, timeline)

    summary = _build_summary(findings, timeline, iocs_count=len(iocs), model_summary=model_summary)
    summary["dropped_uncited"] = dropped_uncited
    summary["dropped_unsupported"] = dropped_unsupported
    summary["verification"] = [item.to_dict() for item in verdicts]
    summary["llm_provider"] = provider
    report = CaseReport(
        case_id=config.case_id,
        generated_at=utc_now_iso(),
        binary_features=binary_features,
        findings=findings,
        timeline=timeline,
        summary=summary,
        iocs=iocs,
    )
    config.output_dir.mkdir(parents=True, exist_ok=True)
    (config.output_dir / "case_report.json").write_text(
        json.dumps(report.to_dict(), indent=2), encoding="utf-8"
    )
    (config.output_dir / "case_report.md").write_text(_to_markdown(report), encoding="utf-8")
    (config.output_dir / "case_report.html").write_text(_to_html(report), encoding="utf-8")
    (config.output_dir / "attack_navigator_layer.json").write_text(
        json.dumps(navigator_layer, indent=2),
        encoding="utf-8",
    )
    (config.output_dir / "case_stix_bundle.json").write_text(
        json.dumps(build_stix_bundle(report), indent=2),
        encoding="utf-8",
    )
    write_pdf_report(report, config.output_dir / "case_report.pdf")
    report_path = config.output_dir / "case_report.json"
    model_name = "none"
    if provider == "mock":
        model_name = MockLlamaWorkflow.model
    elif provider in {"ollama", "openai_compatible"}:
        model_name = config.llama_model
    manifest = build_run_manifest(
        case_id=config.case_id,
        started_at=started_at,
        finished_at=utc_now_iso(),
        input_dir=str(config.input_dir.resolve()),
        input_files=hash_input_tree(config.input_dir),
        provider=provider,
        model_name=model_name,
        endpoint=config.llama_endpoint if provider == "ollama" else config.openai_compatible_endpoint,
        seed=config.seed,
        prompt_sent=provider in {"ollama", "openai_compatible"},
        prompt_template_sha256_value=prompt_template_sha256(prompt_template_text()),
        finding_count=len(findings),
        dropped_uncited=dropped_uncited,
        dropped_unsupported=dropped_unsupported,
        report_name=report_path.name,
        report_sha256=canonical_report_sha256(report.to_dict()),
        workers=store.workers(),
        tool_calls=[call.to_dict() for call in store.tool_calls()],
        verifier=verifier_limit_name(judge_mode),
        verification=[item.to_dict() for item in verdicts],
        rules_dir=str(config.rules_dir) if config.rules_dir else None,
        sigma_rules_dir=str(config.sigma_rules_dir) if config.sigma_rules_dir else None,
        attack_stix_path=str(config.attack_stix_path) if config.attack_stix_path else None,
    )
    write_run_manifest(config.output_dir / "run_manifest.json", manifest)
    return report
