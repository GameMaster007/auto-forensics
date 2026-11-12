"""The signed report as one self-contained HTML file.

``render_html`` turns the final report (the dict ``signoff.export`` writes as
``final_report.json``) into a page that prints cleanly and can be opened
anywhere: the styles are inline, there are no scripts, and nothing is loaded
from the network. The page carries its own Content-Security-Policy that
forbids everything except those inline styles.

Every value that comes from the case goes through ``_t``: control and
text-direction characters are replaced with a space, long values are cut,
and the result is escaped with ``html.escape``. No case value is ever put in
an attribute; the only attribute that varies is a severity class taken from
a fixed list.

Like ``final_report.md``, the page names who signed and when but does not
print the signature fingerprint; that stays in ``final_report.json``.
"""

from __future__ import annotations

import html
import re
from typing import Any

from .coordinator import KILL_CHAIN, SEVERITY_ORDER

CSP = "default-src 'none'; style-src 'unsafe-inline'"
SEVERITIES = ("critical", "high", "medium", "low", "info")
MAX_ROWS = 5000

# Control characters, invisible characters, text-direction overrides and lone surrogates.
_UNSAFE = re.compile(r"[\x00-\x1f\x7f-\x9f\u200b-\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069\ufeff\ud800-\udfff]")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

_STYLE = """
:root { --ink: #14213d; --rule: #f2c230; --muted: #56607a; --line: #d8dce6; --wash: #f5f6f9; --warn: #fdf5d7; }
* { box-sizing: border-box; }
html { background: #fff; }
body { margin: 0; background: #fff; color: var(--ink); line-height: 1.5; font-size: 15px;
  font-family: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  -webkit-print-color-adjust: exact; print-color-adjust: exact; }
.sheet { max-width: 1080px; margin: 0 auto; padding: 44px 32px 56px; }
.kicker { margin: 0 0 6px; font-size: 12px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--muted); }
h1 { margin: 0; padding-bottom: 14px; border-bottom: 2px solid var(--rule); font-size: 30px; line-height: 1.2;
  font-weight: 650; letter-spacing: -0.01em; overflow-wrap: anywhere; }
h2 { margin: 36px 0 10px; font-size: 13px; letter-spacing: 0.12em; text-transform: uppercase; font-weight: 700; }
p { margin: 0 0 10px; }
.status { margin: 14px 0 0; font-weight: 650; overflow-wrap: anywhere; }
.headline { margin: 6px 0 0; font-size: 18px; }
.muted { color: var(--muted); }
.mono { font-family: ui-monospace, "SF Mono", "Cascadia Mono", Consolas, "Liberation Mono", Menlo, monospace;
  font-size: 0.86em; overflow-wrap: anywhere; }
.hash { word-break: break-all; }
dl { display: grid; grid-template-columns: 190px 1fr; gap: 6px 20px; margin: 0; }
dt { color: var(--muted); }
dd { margin: 0; overflow-wrap: anywhere; }
.block { border: 1px solid var(--line); border-radius: 4px; padding: 16px 18px; break-inside: avoid;
  page-break-inside: avoid; }
.warning { background: var(--warn); border: 1px solid var(--rule); border-left: 5px solid var(--rule);
  border-radius: 4px; padding: 14px 18px; break-inside: avoid; page-break-inside: avoid; }
.warning strong { display: block; margin-bottom: 4px; }
ul { margin: 6px 0 0; padding-left: 20px; }
li { margin: 3px 0; overflow-wrap: anywhere; }
table { width: 100%; border-collapse: collapse; table-layout: fixed; font-size: 13.5px; }
thead { display: table-header-group; }
th { text-align: left; font-size: 11.5px; letter-spacing: 0.08em; text-transform: uppercase; color: var(--muted);
  font-weight: 700; padding: 8px 10px 8px 0; border-bottom: 1.5px solid var(--ink); vertical-align: bottom; }
td { padding: 10px 10px 10px 0; border-bottom: 1px solid var(--line); vertical-align: top; overflow-wrap: anywhere; }
tr { break-inside: avoid; page-break-inside: avoid; }
.title { font-weight: 650; }
.cite + .cite { margin-top: 6px; }
.sev { display: inline-block; padding: 1px 8px; border-radius: 3px; font-size: 11.5px; font-weight: 700;
  letter-spacing: 0.06em; text-transform: uppercase; border: 1.5px solid var(--ink); white-space: nowrap; }
.sev-critical { background: var(--ink); color: #fff; }
.sev-high { background: #fff; color: var(--ink); }
.sev-medium { background: var(--rule); border-color: var(--rule); color: var(--ink); }
.sev-low, .sev-info, .sev-other { background: var(--wash); border-color: var(--line); color: var(--muted); }
.flag { display: inline-block; margin-top: 4px; padding: 1px 6px; background: var(--warn);
  border: 1px solid var(--rule); border-radius: 3px; font-size: 12px; font-weight: 650; }
.none { color: var(--muted); font-style: italic; }
footer { margin-top: 44px; padding-top: 16px; border-top: 1px solid var(--line); font-size: 13px; }
footer dl { grid-template-columns: 210px 1fr; }
footer p { margin-top: 14px; color: var(--muted); }
.w-sev { width: 10%; } .w-find { width: 22%; } .w-tac { width: 13%; } .w-cite { width: 23%; }
.w-check { width: 11%; } .w-dec { width: 9%; } .w-note { width: 12%; }
.w-stage { width: 17%; } .w-count { width: 9%; } .w-top { width: 11%; } .w-tech { width: 22%; } .w-seen { width: 41%; }
@media screen and (max-width: 760px) {
  .sheet { padding: 24px 16px 40px; }
  dl, footer dl { grid-template-columns: 1fr; gap: 0; }
  dd { margin-bottom: 8px; }
  .scroll { overflow-x: auto; }
  .scroll table { min-width: 760px; }
}
@page { margin: 14mm 12mm; }
@media print {
  body { font-size: 10.5pt; }
  .sheet { max-width: none; padding: 0; }
  h1 { font-size: 20pt; }
  h2 { margin-top: 22pt; break-after: avoid; page-break-after: avoid; }
  table { font-size: 8.5pt; }
  th { font-size: 7pt; letter-spacing: 0.05em; }
  .sev { font-size: 6.5pt; padding: 1px 4px; letter-spacing: 0.03em; }
  .w-sev { width: 11%; } .w-find { width: 21%; }
  tr, .block, .warning, li { break-inside: avoid; page-break-inside: avoid; }
  footer { break-inside: avoid; page-break-inside: avoid; }
  .scroll { overflow: visible; }
}
"""


def _t(value: Any, limit: int = 2000) -> str:
    """Case text made safe for the page: one line, bounded, escaped."""
    text = "" if value is None else str(value)
    text = _UNSAFE.sub(" ", text)
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return html.escape(text, quote=True)


def _mono(value: Any, limit: int = 2000) -> str:
    return f'<span class="mono">{_t(value, limit)}</span>'


def _rows(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)][:MAX_ROWS] if isinstance(value, list) else []


def _severity(value: Any) -> str:
    name = str(value or "").lower()
    css = name if name in SEVERITIES else "other"
    return f'<span class="sev sev-{css}">{_t(value or "unknown", 20)}</span>'


def _where(finding: dict[str, Any]) -> str:
    parts = []
    for citation in _rows(finding.get("citations"))[:20]:
        row, offset = citation.get("row"), citation.get("offset")
        place = f"row {_t(row, 20)}" if row else f"byte {_t(0 if offset is None else offset, 20)}"
        digest = str(citation.get("sha256") or "").lower()
        proof = f'<div class="mono hash muted">SHA-256 {_t(digest, 80)}</div>' if _SHA256.match(digest) else ""
        parts.append(f'<div class="cite">{_mono(citation.get("source_file"), 400)}, {place}{proof}</div>')
    return "".join(parts) or '<span class="none">no citation</span>'


def _definition(pairs: list[tuple[str, str]]) -> str:
    return "<dl>" + "".join(f"<dt>{label}</dt><dd>{value}</dd>" for label, value in pairs) + "</dl>"


def _signature_block(final: dict[str, Any]) -> str:
    signature = final.get("signature")
    if not isinstance(signature, dict):
        return '<div class="block"><p class="none">This report has not been signed.</p></div>'
    statement = _t(signature.get("statement"), 2000) or '<span class="none">No statement was given.</span>'
    seal = ("Sealed with the signing key" if signature.get("seal")
            else "Not sealed (no signing key was set when it was signed)")
    pairs = [
        ("Signed by", _t(signature.get("actor"), 200)),
        ("Signed at", _mono(signature.get("signed_at"), 64)),
        ("Statement", statement),
        ("Decisions", f"{_t(signature.get('accepted'), 12)} accepted, {_t(signature.get('rejected'), 12)} rejected"),
        ("Seal", seal),
    ]
    gaps = signature.get("accepted_gaps")
    if isinstance(gaps, list) and gaps:
        pairs.append(("Gaps accepted", "The analyst signed knowing these checks did not finish cleanly: "
                      + ", ".join(_t(name, 80) for name in gaps[:50])))
    return f'<div class="block">{_definition(pairs)}</div>'


def _hostile(final: dict[str, Any]) -> str:
    files = final.get("hostile_files")
    if not isinstance(files, list) or not files:
        return ""
    items = "".join(f"<li>{_mono(path, 400)}</li>" for path in files[:MAX_ROWS])
    return ('<h2>Warning: hostile files</h2><div class="warning"><strong>These files contain text written to '
            "mislead an AI assistant.</strong>Open them only in a plain viewer, never through an AI tool."
            f"<ul>{items}</ul></div>")


def _gaps(final: dict[str, Any]) -> str:
    gaps = _rows(final.get("coverage_gaps"))
    if not gaps:
        return '<h2>Coverage gaps</h2><p class="none">None recorded. Every planned check ran on all of the evidence.</p>'
    items = "".join(f"<li>{_mono(gap.get('what'), 400)}: {_t(gap.get('why'), 400)}</li>" for gap in gaps)
    return f"<h2>Coverage gaps</h2><p>Parts of the evidence this run did not fully analyse:</p><ul>{items}</ul>"


def _chain(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Medium-or-higher findings by ATT&CK tactic in kill-chain order (as the coordinator groups a draft).

    Built from the findings in the report itself, so a signed report shows the
    path through the findings the analyst accepted, not through rejected ones.
    """
    groups: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        if SEVERITY_ORDER.get(str(finding.get("severity")), 9) > SEVERITY_ORDER["medium"]:
            continue
        groups.setdefault(str(finding.get("tactic") or "unknown").lower(), []).append(finding)
    order = {name: index for index, name in enumerate(KILL_CHAIN)}
    chain = []
    for tactic in sorted(groups, key=lambda name: (order.get(name, len(order)), name)):
        items = groups[tactic]
        chain.append({
            "tactic": tactic,
            "findings": len(items),
            "top_severity": min((str(f.get("severity")) for f in items), key=lambda sev: SEVERITY_ORDER.get(sev, 9)),
            "techniques": sorted({str(f["technique_id"]) for f in items if f.get("technique_id")}),
            "titles": sorted({str(f.get("title") or "") for f in items})[:6],
        })
    return chain


def _attack_path(final: dict[str, Any]) -> str:
    steps = _chain(_rows(final.get("findings")))
    if not steps:
        return ""
    body = ""
    for step in steps:
        body += (f"<tr><td>{_t(step['tactic'], 80)}</td><td>{_t(step['findings'], 12)}</td>"
                 f"<td>{_severity(step['top_severity'])}</td>"
                 f"<td>{_mono(', '.join(step['techniques'][:30]), 400)}</td>"
                 f"<td>{_t('; '.join(step['titles']), 900)}</td></tr>")
    return ("<h2>Attack path</h2><p class=\"muted\">The findings in this report of medium severity or higher, "
            "grouped by what the attacker was trying to do, in the order an attack usually unfolds.</p>"
            "<div class=\"scroll\"><table><thead><tr>"
            '<th class="w-stage">Stage</th><th class="w-count">Findings</th><th class="w-top">Highest</th>'
            '<th class="w-tech">Techniques</th><th class="w-seen">What was seen</th>'
            f"</tr></thead><tbody>{body}</tbody></table></div>")


def _findings(final: dict[str, Any]) -> str:
    findings = _rows(final.get("findings"))
    if not findings:
        return '<h2>Findings</h2><p class="none">No findings were accepted by the analyst.</p>'
    body = ""
    for finding in findings:
        flag = '<div class="flag">Hostile source: verify by hand</div>' if finding.get("warnings") else ""
        technique = (f'<div class="mono muted">{_t(finding.get("technique_id"), 40)}</div>'
                     if finding.get("technique_id") else "")
        decision = {"accept": "Accepted", "reject": "Rejected"}.get(str(finding.get("decision")), "Pending")
        analyst = f'<div class="muted">by {_t(finding.get("analyst"), 200)}</div>' if finding.get("analyst") else ""
        note = _t(finding.get("analyst_note"), 2000) or '<span class="none">none</span>'
        body += (f"<tr><td>{_severity(finding.get('severity'))}</td>"
                 f"<td><div class=\"title\">{_t(finding.get('title'), 400)}</div>"
                 f"<div class=\"mono muted\">{_t(finding.get('finding_id'), 200)}</div>{flag}</td>"
                 f"<td>{_t(finding.get('tactic') or 'unknown', 80)}{technique}</td>"
                 f"<td>{_where(finding)}</td><td>{_t(finding.get('verification') or '-', 200)}</td>"
                 f"<td>{decision}{analyst}</td><td>{note}</td></tr>")
    return ("<h2>Findings</h2><div class=\"scroll\"><table><thead><tr>"
            '<th class="w-sev">Severity</th><th class="w-find">Finding</th><th class="w-tac">Tactic / technique</th>'
            '<th class="w-cite">Where cited</th><th class="w-check">Checked</th><th class="w-dec">Decision</th>'
            f'<th class="w-note">Note</th></tr></thead><tbody>{body}</tbody></table></div>')


def _rejected(final: dict[str, Any]) -> str:
    rejected = _rows(final.get("rejected_findings"))
    if not rejected:
        return ""
    body = "".join(
        f"<tr><td><div class=\"title\">{_t(item.get('title'), 400)}</div>"
        f"<div class=\"mono muted\">{_t(item.get('finding_id'), 200)}</div></td>"
        f"<td>Rejected<div class=\"muted\">by {_t(item.get('analyst'), 200)}</div></td>"
        f"<td>{_t(item.get('analyst_note'), 2000)}</td></tr>"
        for item in rejected
    )
    return ("<h2>Rejected by the analyst</h2><p class=\"muted\">These were drafted by the tool and turned down. "
            "They are not part of the findings above.</p><div class=\"scroll\"><table><thead><tr><th>Finding</th>"
            f"<th>Decision</th><th>Reason</th></tr></thead><tbody>{body}</tbody></table></div>")


def _footer(final: dict[str, Any], manifest: dict[str, Any]) -> str:
    signature = final.get("signature") if isinstance(final.get("signature"), dict) else {}
    model = manifest.get("llm")
    if model == "ollama" and manifest.get("llama_model"):
        model = f"ollama ({manifest.get('llama_model')})"
    pairs = [
        ("Autopilot version", _mono(manifest.get("autopilot_version") or "not recorded", 40)),
        ("Core version", _mono(manifest.get("core_version") or "not recorded", 40)),
        ("Event log reader", _mono(manifest.get("evtx_reader") or "not recorded", 40)),
        ("Model", _mono(model or "not recorded", 80)),
        ("Run finished at", _mono(manifest.get("finished_at") or "not recorded", 64)),
        ("Custody record SHA-256", _mono(final.get("custody_sha256") or "not recorded", 80)),
        ("Draft SHA-256", _mono(signature.get("draft_sha256") or manifest.get("draft_sha256") or "not recorded", 80)),
        ("Decision log SHA-256", _mono(signature.get("signoff_log_sha256") or "not recorded", 80)),
    ]
    return (f"<footer>{_definition(pairs)}<p>The full signature record, including its fingerprint, is in "
            "final_report.json in the same folder. This page has no scripts and loads nothing from the "
            "internet.</p></footer>")


def render_html(final: dict[str, Any], manifest: dict[str, Any] | None = None, *, title: str = "Signed report") -> str:
    """One self-contained HTML document for a final (or draft) report dict."""
    manifest = manifest if isinstance(manifest, dict) else {}
    case = _t(final.get("case_id"), 80)
    return "".join([
        '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n',
        f'<meta http-equiv="Content-Security-Policy" content="{CSP}">\n',
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n',
        '<meta name="referrer" content="no-referrer">\n',
        f"<title>{_t(title, 80)}: {case}</title>\n<style>{_STYLE}</style>\n</head>\n<body>\n<div class=\"sheet\">\n",
        f'<header><p class="kicker">Auto Forensics &middot; {_t(title, 80)}</p><h1>Case {case}</h1>',
        f'<p class="status">{_t(final.get("status"), 600)}</p>',
        f'<p class="headline">{_t(final.get("headline"), 600)}</p></header>\n',
        "<h2>Analyst signature</h2>", _signature_block(final), "\n",
        _hostile(final), "\n", _gaps(final), "\n", _attack_path(final), "\n",
        _findings(final), "\n", _rejected(final), "\n", _footer(final, manifest),
        "\n</div>\n</body>\n</html>\n",
    ])
