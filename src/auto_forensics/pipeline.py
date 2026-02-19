from __future__ import annotations

import html
import json
import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

from .attack_mapper import apply_attack_mapping, build_attack_navigator_layer, load_attack_techniques
from .artifacts import discover_artifacts
from .event_detectors import findings_from_artifact_events
from .ioc_pipeline import extract_iocs
from .llama_workflow import LlamaWorkflow, heuristic_fallback
from .models import CaseReport, Finding, TimelineEvent, utc_now_iso
from .pdf_report import write_pdf_report
from .plugins import PluginRegistry
from .sigma_rules import evaluate_sigma_rules
from .stix_export import build_stix_bundle
from .timeline import normalize_timeline
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
        `</tr>`
      ).join("");
      document.getElementById("findings").innerHTML =
        `<thead><tr><th>Severity</th><th>Title</th><th>Tactic</th><th>Technique</th><th>Confidence</th></tr></thead>` +
        `<tbody>${{rows || "<tr><td colspan='5'>No findings.</td></tr>"}}</tbody>`;
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


def run_case(config: PipelineConfig) -> CaseReport:
    registry = config.plugin_registry or PluginRegistry()
    registry.register_defaults()
    artifacts, binaries = discover_artifacts(
        config.input_dir,
        max_text_bytes=config.max_text_bytes,
        parser_registry=registry.artifact_parsers,
    )
    with ThreadPoolExecutor(max_workers=4, thread_name_prefix="af-binary") as pool:
        binary_features = list(pool.map(registry.analyze_binary, binaries))
    # Cap directory traversal depth at 20 to avoid runaway scans on deep trees.
    # Use a generator to avoid materialising the full list in memory for large trees.
    scan_candidates = (
        p for p in sorted(config.input_dir.rglob("*"))
        if p.is_file() and len(p.relative_to(config.input_dir).parts) <= 20
    )

    findings: list[Finding] = []
    generated_hints: list[TimelineEvent] = []
    model_summary: dict[str, Any] | None = None
    workflow: LlamaWorkflow | None = None

    try:
        yara_findings, yara_hints = scan_paths_with_yara(scan_candidates, config.rules_dir)
        findings.extend(yara_findings)
        generated_hints.extend(yara_hints)
    except Exception as exc:
        logger.warning("YARA scan failed: %s", exc)

    findings.extend(findings_from_artifact_events(artifacts))

    if config.enable_llama:
        if config.openai_compatible_endpoint:
            workflow = LlamaWorkflow(
                config.openai_compatible_endpoint,
                config.llama_model,
                provider="openai_compatible",
                api_key=config.openai_api_key,
            )
        else:
            workflow = LlamaWorkflow(config.llama_endpoint, config.llama_model)

    if workflow:
        def analyze_one(binary):
            try:
                related_events = normalize_timeline(artifacts, [binary], [])
                return workflow.analyze_binary(binary, related_events[-10:])
            except Exception as exc:
                logger.warning("LLM analysis failed for %s: %s — using heuristic fallback", binary.path, exc)
                return heuristic_fallback(binary)

        with ThreadPoolExecutor(max_workers=3, thread_name_prefix="af-llm") as pool:
            for model_findings, hints in pool.map(analyze_one, binary_features):
                findings.extend(model_findings)
                generated_hints.extend(hints)
    else:
        for binary in binary_features:
            if binary.suspicious_score > 0:
                model_findings, hints = heuristic_fallback(binary)
                findings.extend(model_findings)
                generated_hints.extend(hints)

    timeline = normalize_timeline(artifacts, binary_features, generated_hints)
    findings.extend(registry.detectors.detect(artifacts, binary_features, timeline))
    sigma_findings = evaluate_sigma_rules(timeline, config.sigma_rules_dir or config.rules_dir)
    findings.extend(sigma_findings)

    if workflow:
        model_summary = workflow.summarize_case(findings, timeline)

    attack_techniques = load_attack_techniques(config.attack_stix_path)
    findings = apply_attack_mapping(findings, attack_techniques)
    navigator_layer = build_attack_navigator_layer(config.case_id, findings, attack_techniques)
    iocs = extract_iocs(binary_features, findings, timeline)

    summary = _build_summary(findings, timeline, iocs_count=len(iocs), model_summary=model_summary)
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
    return report
