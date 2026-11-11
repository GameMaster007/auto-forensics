"""Merge agent findings into one cited draft.

The coordinator never reads evidence text. It works from structured
findings, the evidence inventory, and the core report. Before a finding
from a non-core agent is kept, its citation is checked against the
inventory and its cited row is re-read and compared by SHA-256 with the
digest the agent recorded. The row's words are not copied into the draft.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict
from pathlib import Path
from typing import Any

from auto_forensics.models import Finding

from .agents import iter_lines, line_digest

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
KILL_CHAIN = (
    "reconnaissance", "resource-development", "initial-access", "execution", "persistence",
    "privilege-escalation", "defense-evasion", "credential-access", "discovery", "lateral-movement",
    "collection", "command-and-control", "exfiltration", "impact",
)


def attack_chain(findings: list[Finding]) -> list[dict[str, Any]]:
    """Group findings by ATT&CK tactic in kill-chain order; unknown tactics go last."""
    groups: dict[str, list[Finding]] = {}
    for finding in findings:
        if SEVERITY_ORDER.get(finding.severity, 9) > SEVERITY_ORDER["medium"]:
            continue
        groups.setdefault((finding.tactic or "unknown").lower(), []).append(finding)
    order = {name: index for index, name in enumerate(KILL_CHAIN)}
    chain = []
    for tactic in sorted(groups, key=lambda name: (order.get(name, len(order)), name)):
        items = groups[tactic]
        chain.append({
            "tactic": tactic,
            "findings": len(items),
            "top_severity": min((f.severity for f in items), key=lambda sev: SEVERITY_ORDER.get(sev, 9)),
            "techniques": sorted({f.technique_id for f in items if f.technique_id}),
            "titles": sorted({f.title for f in items})[:6],
        })
    return chain
DRAFT_STATUS = "DRAFT - not signed. Do not rely on this until an analyst signs it."


def canonical_sha256(data: Any) -> str:
    raw = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _evidence_value(finding: Finding, key: str) -> str | None:
    prefix = f"{key}="
    for item in finding.evidence:
        if isinstance(item, str) and item.startswith(prefix):
            return item[len(prefix):]
    return None


def verify_agent_finding(
    finding: Finding, input_dir: Path, inventory: dict[str, str], locate: dict[str, Path] | None = None,
) -> str | None:
    """Return None when the finding's citations hold, else the reason it is dropped.

    ``locate`` maps a cited name that is not under ``input_dir`` (an archive
    member) to the extracted copy it was hashed from.
    """
    if not finding.citations:
        return "no citation"
    expected_line = _evidence_value(finding, "line_sha256")
    for citation in finding.citations:
        if not citation.is_complete():
            return "incomplete citation"
        recorded = inventory.get(citation.source_file)
        if recorded is None:
            return "cited file is not in the evidence inventory"
        if recorded != citation.sha256.lower():
            return "cited file hash does not match the inventory"
        if expected_line is None:
            continue
        if citation.row is None:
            return "line digest recorded without a row"
        path = (locate or {}).get(citation.source_file) or input_dir / citation.source_file
        decoding = _evidence_value(finding, "decoding") or "auto"
        line = next((text for number, text in iter_lines(path, decoding=decoding) if number == citation.row), None)
        if line is None:
            return "cited row does not exist"
        if line_digest(line) != expected_line:
            return "cited row does not match the agent's record"
    return None


def check_label(finding: Finding) -> str:
    """What the coordinator could actually confirm for a non-core finding."""
    if _evidence_value(finding, "line_sha256") is not None:
        return "row re-read"
    if finding.worker == "archive":
        # The archive's own core run checked these; the coordinator re-checked only the member's hash.
        return "member hash; row checked by the archive's core run"
    return "file hash only"


def _citation_identity(finding: Finding) -> tuple[Any, ...]:
    return tuple(sorted((c.source_file, c.sha256, c.row, c.offset) for c in finding.citations))


def merge_findings(
    findings: list[Finding],
    input_dir: Path,
    inventory: dict[str, str],
    locate: dict[str, Path] | None = None,
) -> tuple[list[Finding], list[dict[str, str]]]:
    """Verify non-core findings, drop duplicates, and sort by severity."""
    kept: list[Finding] = []
    dropped: list[dict[str, str]] = []
    seen: set[tuple[Any, ...]] = set()
    ids: set[str] = set()
    for finding in findings:
        if finding.worker != "core_pipeline":
            reason = verify_agent_finding(finding, input_dir, inventory, locate)
            if reason:
                dropped.append({"finding_id": finding.finding_id, "worker": finding.worker, "reason": reason})
                continue
            finding.verification = check_label(finding)
        key = (finding.title, _citation_identity(finding))
        if key in seen or finding.finding_id in ids:
            dropped.append({"finding_id": finding.finding_id, "worker": finding.worker, "reason": "duplicate"})
            continue
        seen.add(key)
        ids.add(finding.finding_id)
        kept.append(finding)
    kept.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), -float(f.confidence or 0), f.finding_id))
    return kept, dropped


HOSTILE_WARNING = "model read hostile text: a file this finding cites tries to instruct an AI; verify by hand"


def _finding_entry(finding: Finding, hostile: frozenset[str] = frozenset()) -> dict[str, Any]:
    warnings = []
    if finding.origin == "llm" and any(c.source_file in hostile for c in finding.citations):
        warnings.append(HOSTILE_WARNING)
    return {
        "warnings": warnings,
        "finding_id": finding.finding_id,
        "title": finding.title,
        "severity": finding.severity,
        "confidence": round(float(finding.confidence or 0), 3),
        "tactic": finding.tactic,
        "technique_id": finding.technique_id,
        "worker": finding.worker,
        "origin": finding.origin,
        "verification": finding.verification or "",
        "recommendation": finding.recommendation,
        "citations": [asdict(c) for c in finding.citations],
    }


_ISO_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d{1,9})?)?(Z|[+-]\d{2}:?\d{2})?$")
# Event types the parsers assign themselves. Anything else came from the
# evidence (a JSON "event_type" key, a text field) and is not repeated.
_KNOWN_EVENT_TYPE = re.compile(
    r"^(windows_event_\d{1,5}|process_(start|creation|terminate)|network_connection|registry_(modification|set)|"
    r"file_(create|delete|stat)|scheduled_task_(create|created)|service_install|logon|logoff|windows_logon_failure|"
    r"binary_(analyzed|risk_assessed)|yara_match|parse_error|text_note|dns_query)$")


def _safe_time(value: Any) -> str | None:
    text = str(value or "")
    return text if _ISO_TIME.match(text) else None


def _safe_type(value: Any) -> str:
    text = str(value or "")
    return text if _KNOWN_EVENT_TYPE.match(text) else "event"


def _timeline_highlights(core_report: dict[str, Any] | None, limit: int = 15) -> list[dict[str, Any]]:
    """The riskiest timeline events, reduced to values the tool itself produced.

    Event descriptions, sources and free-text types come from evidence and
    are left out; a timestamp is kept only when it is a well-formed time.
    """
    if not core_report:
        return []
    events = [e for e in core_report.get("timeline", []) if isinstance(e, dict)]

    def risk(event: dict[str, Any]) -> float:
        try:
            return float(event.get("risk_score") or 0)
        except (TypeError, ValueError):
            return 0.0

    events.sort(key=lambda e: (-risk(e), str(_safe_time(e.get("timestamp")) or "")))
    picked = events[:limit]
    picked.sort(key=lambda e: str(_safe_time(e.get("timestamp")) or ""))
    return [
        {"timestamp": _safe_time(e.get("timestamp")), "event_type": _safe_type(e.get("event_type")),
         "risk_score": round(risk(e), 2)}
        for e in picked
    ]


def build_draft(
    *,
    case_id: str,
    findings: list[Finding],
    dropped: list[dict[str, str]],
    plan: list[dict[str, Any]],
    agent_results: list[dict[str, Any]],
    hostile_files: list[str],
    core_report: dict[str, Any] | None,
    custody_sha256: str,
    coverage_gaps: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    severity_counts: dict[str, int] = {}
    for finding in findings:
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
    tactics = sorted({f.tactic for f in findings if f.tactic})
    headline = (
        f"{len(findings)} cited finding(s) need review"
        + (f", {severity_counts.get('critical', 0)} critical" if severity_counts.get("critical") else "")
        + (f", {severity_counts.get('high', 0)} high" if severity_counts.get("high") else "")
        + "."
    )
    return {
        "status": DRAFT_STATUS,
        "case_id": case_id,
        "headline": headline,
        "severity_counts": severity_counts,
        "tactics": tactics,
        "attack_chain": attack_chain(findings),
        "findings": [_finding_entry(f, frozenset(hostile_files)) for f in findings],
        "dropped": dropped,
        "hostile_files": sorted(set(hostile_files)),
        "agents": agent_results,
        "plan": plan,
        "timeline_highlights": _timeline_highlights(core_report),
        "coverage_gaps": coverage_gaps or [],
        "custody_sha256": custody_sha256,
    }


_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+\-.!|<>~])")


def _cell(value: Any) -> str:
    """Text for a markdown table cell: one line, every markdown/HTML control character escaped."""
    text = "" if value is None else str(value)
    text = re.sub(r"[\x00-\x1f\x7f\u2028\u2029]", " ", text)
    return _MD_SPECIAL.sub(r"\\\1", text).replace("&", "&amp;")


def _code(value: Any) -> str:
    """An inline code span that no backtick run inside the value can close."""
    text = re.sub(r"[\x00-\x1f\x7f\u2028\u2029]", " ", "" if value is None else str(value))
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * (longest + 1)
    return f"{fence} {text} {fence}"


def render_markdown(draft: dict[str, Any], *, title: str = "Autopilot draft") -> str:
    lines = [f"# {title}: {_cell(draft['case_id'])}", "", f"**{_cell(draft['status'])}**", "", _cell(draft["headline"]), ""]
    if draft.get("hostile_files"):
        lines += [
            "## Warning: hostile evidence",
            "",
            "These files contain text aimed at an AI analyst. Read them only in a plain viewer.",
            "",
        ]
        lines += [f"- {_code(path)}" for path in draft["hostile_files"]] + [""]
    if draft.get("attack_chain"):
        lines += ["## Attack chain", "",
                  "Medium-or-higher findings by ATT&CK tactic, in kill-chain order. Each still needs a decision.",
                  "", "| Tactic | Findings | Highest | Techniques | What was seen |", "| --- | --- | --- | --- | --- |"]
        for step in draft["attack_chain"]:
            lines.append(f"| {_cell(step['tactic'])} | {step['findings']} | {_cell(step['top_severity'])} | "
                         f"{_cell(', '.join(step['techniques']))} | {_cell('; '.join(step['titles']))} |")
        lines.append("")
    lines += ["## Findings", "", "| ID | Severity | Title | Tactic | Agent | Cited at | Checked | Decision |",
              "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for finding in draft["findings"]:
        cites = "; ".join(
            f"{c['source_file']}" + (f" row {c['row']}" if c.get("row") else f" @{c.get('offset')}")
            for c in finding["citations"]
        )
        flag = " **[hostile source: verify by hand]**" if finding.get("warnings") else ""
        lines.append(
            f"| {_code(finding['finding_id'])} | {_cell(finding['severity'])} | {_cell(finding['title'])}{flag} | "
            f"{_cell(finding['tactic'])} | {_cell(finding['worker'])} | {_cell(cites)} | "
            f"{_cell(finding.get('verification') or '-')} | {_cell(finding.get('decision', 'pending'))} |"
        )
    if draft.get("timeline_highlights"):
        lines += ["", "## Timeline highlights", "", "| Time | Event | Risk |", "| --- | --- | --- |"]
        for event in draft["timeline_highlights"]:
            lines.append(f"| {_cell(event['timestamp'])} | {_cell(event['event_type'])} | {_cell(event['risk_score'])} |")
    lines += ["", "## Agents", "", "| Agent | Ran | Status | Findings | Why |", "| --- | --- | --- | --- | --- |"]
    results = {item["name"]: item for item in draft.get("agents", [])}
    for plan in draft.get("plan", []):
        result = results.get(plan["name"], {})
        lines.append(f"| {_cell(plan['name'])} | {'yes' if plan['run'] else 'no'} | "
                     f"{_cell(result.get('status', '-'))} | {_cell(result.get('finding_count', '-'))} | "
                     f"{_cell(result.get('detail') or plan['reason'])} |")
    if draft.get("coverage_gaps"):
        lines += ["", "## Coverage gaps", "", "Parts of the evidence this run did not fully analyse:", ""]
        lines += [f"- {_code(gap['what'])}: {_cell(gap['why'])}" for gap in draft["coverage_gaps"]]
    if draft.get("dropped"):
        lines += ["", f"{len(draft['dropped'])} draft finding(s) were dropped by the coordinator "
                      "(failed citation check or duplicate). See `autopilot_draft.json`."]
    lines += ["", f"Custody record SHA-256: {_code(draft['custody_sha256'])}", ""]
    return "\n".join(lines)
