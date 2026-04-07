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
from .security import SecurityPolicy, walk_case_directory
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


def _to_html(report: "CaseReport") -> str:
    import html as _html, json as _json
    # Escape </script> to prevent XSS via script tag breakout.
    payload = _json.dumps(report.to_dict()).replace("</script>", "<\\/script>")
    ec = _html.escape(report.case_id)
    ts = _html.escape(report.generated_at)
    tf = len(report.findings)
    tt = len(report.timeline)
    ti = len(report.iocs)
    ac = len({f.technique_id for f in report.findings if f.technique_id})
    sc: dict[str, int] = {}
    for f in report.findings:
        s = str(getattr(f, "severity", None) or "low").lower()
        sc[s] = sc.get(s, 0) + 1
    cc = sc.get("critical", 0)
    ch = sc.get("high", 0)
    CSS = (
        "*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}"
        ":root{--bg:#0d1117;--surface:#161b22;--surface2:#1c2333;--border:#30363d;--text:#e6edf3;--muted:#8b949e;--accent:#58a6ff;--accent2:#1f6feb;--crit:#f85149;--high:#fb8500;--med:#d29922;--low:#3fb950;--radius:12px}"
        "html{scroll-behavior:smooth}"
        "body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;font-size:14px;line-height:1.6}"
        ".shell{display:flex;min-height:100vh}"
        ".sidebar{width:220px;flex-shrink:0;background:var(--surface);border-right:1px solid var(--border);position:sticky;top:0;height:100vh;overflow-y:auto;display:flex;flex-direction:column;gap:4px;padding:1.4rem .8rem}"
        ".sidebar-logo{font-size:.78rem;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--accent);padding:0 .4rem 1rem;border-bottom:1px solid var(--border);margin-bottom:.6rem}"
        ".nav-item{display:flex;align-items:center;gap:.55rem;padding:.52rem .7rem;border-radius:8px;color:var(--muted);text-decoration:none;font-size:.85rem;font-weight:500;transition:background .15s,color .15s;cursor:pointer}"
        ".nav-item:hover,.nav-item.active{background:var(--surface2);color:var(--text)}"
        ".nav-icon{font-size:1rem;width:1.2rem;text-align:center}"
        ".nav-badge{margin-left:auto;background:var(--surface2);border:1px solid var(--border);border-radius:999px;padding:.05rem .5rem;font-size:.75rem;color:var(--muted)}"
        ".main{flex:1;overflow:hidden}"
        ".header{background:linear-gradient(135deg,#0d1117 0%,#1a2332 40%,#0f2240 100%);border-bottom:1px solid var(--border);padding:2.5rem 2.5rem 2rem;position:relative;overflow:hidden}"
        ".header::before{content:'';position:absolute;inset:0;background:radial-gradient(ellipse 800px 400px at 70% -20%,rgba(31,111,235,.18),transparent);pointer-events:none}"
        ".header-eyebrow{font-size:.72rem;font-weight:600;letter-spacing:.1em;text-transform:uppercase;color:var(--accent);margin-bottom:.4rem}"
        ".header-title{font-size:1.9rem;font-weight:700;letter-spacing:-.02em;color:var(--text);margin-bottom:.35rem}"
        ".header-meta{color:var(--muted);font-size:.82rem}"
        ".header-meta code{font-family:'JetBrains Mono',monospace;font-size:.8rem;background:rgba(88,166,255,.1);border:1px solid rgba(88,166,255,.25);border-radius:5px;padding:.1rem .45rem;color:var(--accent)}"
        ".stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:1rem;padding:1.8rem 2.5rem;border-bottom:1px solid var(--border);background:var(--surface)}"
        ".stat-card{background:var(--bg);border:1px solid var(--border);border-radius:var(--radius);padding:1.1rem 1.2rem;display:flex;flex-direction:column;gap:.3rem;transition:border-color .2s,transform .2s}"
        ".stat-card:hover{border-color:var(--accent2);transform:translateY(-2px)}"
        ".stat-label{font-size:.73rem;font-weight:600;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}"
        ".stat-value{font-size:2rem;font-weight:700;letter-spacing:-.03em;color:var(--text);line-height:1}"
        ".stat-value.crit{color:var(--crit)}.stat-value.high{color:var(--high)}.stat-value.accent{color:var(--accent)}"
        ".stat-sub{font-size:.78rem;color:var(--muted)}"
        ".sev-section{padding:1.8rem 2.5rem;border-bottom:1px solid var(--border)}"
        ".section-title{font-size:.73rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);margin-bottom:1.1rem}"
        ".sev-bars{display:flex;flex-direction:column;gap:.55rem;max-width:500px}"
        ".sev-row{display:flex;align-items:center;gap:.8rem}"
        ".sev-label{font-size:.8rem;font-weight:600;width:60px;text-transform:uppercase;letter-spacing:.05em}"
        ".sev-track{flex:1;height:8px;background:var(--surface2);border-radius:999px;overflow:hidden}"
        ".sev-fill{height:100%;border-radius:999px;transition:width .6s cubic-bezier(.4,0,.2,1)}"
        ".sev-fill.crit{background:linear-gradient(90deg,#f85149,#ff6b6b)}"
        ".sev-fill.high{background:linear-gradient(90deg,#fb8500,#ffa94d)}"
        ".sev-fill.med{background:linear-gradient(90deg,#d29922,#f0c040)}"
        ".sev-fill.low{background:linear-gradient(90deg,#3fb950,#69db7c)}"
        ".sev-count{font-size:.8rem;font-weight:600;color:var(--muted);width:28px;text-align:right}"
        ".content-section{padding:1.8rem 2.5rem;border-bottom:1px solid var(--border)}"
        ".toolbar{display:flex;flex-wrap:wrap;gap:.6rem;align-items:center;margin-bottom:1rem}"
        ".toolbar-label{font-size:.8rem;color:var(--muted);font-weight:500}"
        ".ctrl{background:var(--surface2);border:1px solid var(--border);color:var(--text);border-radius:8px;padding:.4rem .75rem;font-size:.82rem;font-family:inherit;outline:none;transition:border-color .15s}"
        ".ctrl:focus{border-color:var(--accent)}.ctrl-search{min-width:200px}"
        ".tbl-wrap{overflow-x:auto;border-radius:var(--radius);border:1px solid var(--border)}"
        "table{width:100%;border-collapse:collapse;font-size:.82rem}"
        "thead tr{background:var(--surface2)}"
        "th{padding:.65rem .85rem;text-align:left;white-space:nowrap;font-size:.72rem;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:var(--muted);border-bottom:1px solid var(--border)}"
        "td{padding:.6rem .85rem;border-bottom:1px solid var(--border);vertical-align:top;color:var(--text)}"
        "tbody tr{transition:background .12s}tbody tr:hover{background:var(--surface2)}tbody tr:last-child td{border-bottom:none}"
        ".chip{display:inline-flex;align-items:center;gap:4px;font-size:.72rem;font-weight:700;letter-spacing:.06em;text-transform:uppercase;border-radius:6px;padding:.2rem .55rem;border:1px solid transparent}"
        ".chip-critical{background:rgba(248,81,73,.15);color:#ff7b72;border-color:rgba(248,81,73,.3)}"
        ".chip-high{background:rgba(251,133,0,.15);color:#ffa657;border-color:rgba(251,133,0,.3)}"
        ".chip-medium{background:rgba(210,153,34,.15);color:#d29922;border-color:rgba(210,153,34,.3)}"
        ".chip-low{background:rgba(63,185,80,.15);color:#56d364;border-color:rgba(63,185,80,.3)}"
        ".type-badge{display:inline-block;font-family:'JetBrains Mono',monospace;font-size:.72rem;font-weight:500;border-radius:5px;padding:.15rem .45rem;background:rgba(88,166,255,.1);color:var(--accent);border:1px solid rgba(88,166,255,.2)}"
        ".risk-pill{display:inline-block;border-radius:999px;font-size:.78rem;font-weight:700;padding:.15rem .55rem}"
        ".risk-high{background:rgba(248,81,73,.18);color:var(--crit)}.risk-med{background:rgba(210,153,34,.18);color:var(--med)}.risk-low{background:rgba(63,185,80,.18);color:var(--low)}"
        ".mono{font-family:'JetBrains Mono',monospace;font-size:.8rem;word-break:break-all}"
        ".copy-btn{background:none;border:1px solid var(--border);border-radius:6px;color:var(--muted);font-size:.7rem;padding:.12rem .45rem;cursor:pointer;transition:all .15s;font-family:inherit}"
        ".copy-btn:hover{background:var(--surface2);color:var(--text);border-color:var(--accent)}"
        ".conf-bar{display:flex;align-items:center;gap:.5rem}"
        ".conf-track{flex:1;height:5px;background:var(--surface2);border-radius:999px;overflow:hidden}"
        ".conf-fill{height:100%;background:linear-gradient(90deg,var(--accent2),var(--accent));border-radius:999px}"
        ".conf-label{font-size:.78rem;color:var(--muted);width:34px;text-align:right}"
        ".empty{text-align:center;padding:2.5rem;color:var(--muted);font-size:.85rem}"
        ".empty-icon{font-size:2rem;margin-bottom:.4rem;display:block}"
        ".tactic{display:inline-block;font-size:.72rem;padding:.12rem .45rem;background:rgba(139,148,158,.1);border:1px solid var(--border);border-radius:5px;color:var(--muted)}"
        ".technique{font-family:'JetBrains Mono',monospace;font-size:.78rem;color:var(--muted)}"
        ".footer{padding:1.4rem 2.5rem;text-align:center;font-size:.78rem;color:var(--muted);border-top:1px solid var(--border)}"
        "::-webkit-scrollbar{width:6px;height:6px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:var(--border);border-radius:999px}"
        "@media print{.sidebar{display:none}.header{background:none;border:1px solid #ccc}body{background:#fff;color:#000}}"
    )
    JS = (
        f"const _DATA={payload};\n"
        "function e(v){return String(v==null?'':v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}\n"
        "function goTo(id){const el=document.getElementById(id);if(el)el.scrollIntoView({behavior:'smooth',block:'start'})}\n"
        "(function(){const order=['critical','high','medium','low'];const counts={};\n"
        "(_DATA.findings||[]).forEach(f=>{const s=(f.severity||'low').toLowerCase();counts[s]=(counts[s]||0)+1});\n"
        "const max=Math.max(...Object.values(counts),1);\n"
        "const color={critical:'crit',high:'high',medium:'med',low:'low'};\n"
        "const container=document.getElementById('sevBars');\n"
        "if(!Object.values(counts).some(Boolean)){container.innerHTML='<p style=\"color:var(--muted)\">No findings.</p>';return}\n"
        "order.forEach(s=>{const c=counts[s]||0;if(!c)return;const pct=Math.round(c/max*100);const cls=color[s]||'low';\n"
        "container.insertAdjacentHTML('beforeend',`<div class='sev-row'><span class='sev-label' style='color:var(--${cls})'>${s}</span><div class='sev-track'><div class='sev-fill ${cls}' style='width:${pct}%'></div></div><span class='sev-count'>${c}</span></div>`)})})();\n"
        "(function(){const tactics=[...new Set((_DATA.findings||[]).map(f=>f.tactic||'').filter(Boolean))].sort();\n"
        "const sel=document.getElementById('tacticFilter');\n"
        "tactics.forEach(t=>sel.insertAdjacentHTML('beforeend',`<option value='${e(t)}'>${e(t)}</option>`))})();\n"
        "function renderFindings(){\n"
        "  const sevF=document.getElementById('sevFilter').value.toLowerCase();\n"
        "  const tacF=document.getElementById('tacticFilter').value.toLowerCase();\n"
        "  const kw=document.getElementById('findingSearch').value.toLowerCase();\n"
        "  const rows=(_DATA.findings||[])\n"
        "    .filter(f=>!sevF||(f.severity||'').toLowerCase()===sevF)\n"
        "    .filter(f=>!tacF||(f.tactic||'').toLowerCase()===tacF)\n"
        "    .filter(f=>!kw||(f.title||'').toLowerCase().includes(kw)||(f.tactic||'').toLowerCase().includes(kw)||(f.technique_id||'').toLowerCase().includes(kw))\n"
        "    .map(f=>{const sev=(f.severity||'low').toLowerCase();\n"
        "      const conf=f.confidence!=null?Math.round(f.confidence*100):null;\n"
        "      const cb=conf!=null?`<div class='conf-bar'><div class='conf-track'><div class='conf-fill' style='width:${conf}%'></div></div><span class='conf-label'>${conf}%</span></div>`:'\\u2014';\n"
        "      return `<tr><td><span class='chip chip-${sev}'>${e(sev)}</span></td><td><strong>${e(f.title||f.rule_name||'')}</strong></td><td><span class='tactic'>${e(f.tactic||'\\u2014')}</span></td><td><span class='technique'>${e(f.technique_id||'\\u2014')}</span></td><td>${cb}</td><td style='font-size:.8rem;color:var(--muted);max-width:260px'>${e(f.recommendation||'\\u2014')}</td></tr>`})\n"
        "    .join('');\n"
        "  document.getElementById('findingsTbody').innerHTML=rows||`<tr><td colspan='6'><div class='empty'><span class='empty-icon'>&#128269;</span>No findings match the current filter.</div></td></tr>`}\n"
        "function riskPill(score){if(score==null)return '\\u2014';const cls=score>=70?'high':score>=40?'med':'low';return `<span class='risk-pill risk-${cls}'>${Math.round(score)}</span>`}\n"
        "function renderTimeline(){\n"
        "  const typeF=document.getElementById('typeFilter').value.toLowerCase();\n"
        "  const minR=parseFloat(document.getElementById('riskFilter').value)||0;\n"
        "  const kw=document.getElementById('tlSearch').value.toLowerCase();\n"
        "  const rows=(_DATA.timeline||[])\n"
        "    .filter(ev=>!typeF||(ev.event_type||'').toLowerCase().includes(typeF))\n"
        "    .filter(ev=>!minR||(ev.risk_score||0)>=minR)\n"
        "    .filter(ev=>!kw||(ev.description||'').toLowerCase().includes(kw)||(ev.source||'').toLowerCase().includes(kw))\n"
        "    .map(ev=>`<tr><td class='mono' style='white-space:nowrap;font-size:.75rem'>${e(ev.timestamp||'\\u2014')}</td><td><span class='type-badge'>${e(ev.event_type||'')}</span></td><td style='font-size:.78rem;color:var(--muted)'>${e(ev.source||'\\u2014')}</td><td style='max-width:360px'>${e(ev.description||'')}</td><td>${riskPill(ev.risk_score)}</td></tr>`)\n"
        "    .join('');\n"
        "  document.getElementById('timelineTbody').innerHTML=rows||`<tr><td colspan='5'><div class='empty'><span class='empty-icon'>&#128336;</span>No events match the current filter.</div></td></tr>`}\n"
        "function renderIocs(){\n"
        "  const typeF=document.getElementById('iocTypeFilter').value.toLowerCase();\n"
        "  const kw=document.getElementById('iocSearch').value.toLowerCase();\n"
        "  const rows=(_DATA.iocs||[])\n"
        "    .filter(i=>!typeF||(i.ioc_type||'').toLowerCase()===typeF)\n"
        "    .filter(i=>!kw||(i.value||'').toLowerCase().includes(kw)||((i.sources||[]).join(' ')).toLowerCase().includes(kw))\n"
        "    .map(i=>{const raw=String(i.value||'');return `<tr><td><span class='type-badge'>${e(i.ioc_type||'')}</span></td><td class='mono'>${e(raw)}</td><td style='font-size:.78rem;color:var(--muted)'>${e((i.sources||[]).join(', '))}</td><td><button class='copy-btn' onclick=\"navigator.clipboard.writeText(${JSON.stringify(raw)}).then(()=>{this.textContent='\\u2713';setTimeout(()=>this.textContent='copy',1200)})\">copy</button></td></tr>`})\n"
        "    .join('');\n"
        "  document.getElementById('iocsTbody').innerHTML=rows||`<tr><td colspan='4'><div class='empty'><span class='empty-icon'>&#128737;</span>No IOCs match the current filter.</div></td></tr>`}\n"
        "(function(){const rows=(_DATA.binary_features||[]).map(b=>{\n"
        "  const score=b.suspicious_score||0;\n"
        "  const sc2=score>=4?'var(--crit)':score>0?'var(--high)':'var(--low)';\n"
        "  const ent=b.entropy!=null?Number(b.entropy).toFixed(3):'\\u2014';\n"
        "  const sha=b.sha256?b.sha256.slice(0,16)+'\\u2026':'\\u2014';\n"
        "  const rat=(b.rationale||[]).slice(0,2).join('; ')||'\\u2014';\n"
        "  return `<tr><td class='mono' style='font-size:.76rem'>${e(b.path||'\\u2014')}</td><td class='mono' style='font-size:.75rem;color:var(--muted)'>${e(sha)}</td><td style='font-size:.82rem'>${ent}</td><td><strong style='color:${sc2}'>${score}</strong></td><td style='font-size:.78rem;color:var(--muted);max-width:260px'>${e(rat)}</td></tr>`})\n"
        "  .join('');\n"
        "  document.getElementById('binariesTbody').innerHTML=rows||`<tr><td colspan='5'><div class='empty'><span class='empty-icon'>&#128190;</span>No binaries analysed.</div></td></tr>`})();\n"
        "(function(){const en=_DATA.ioc_enrichments||[];if(!en.length)return;\n"
        "  document.getElementById('enrichments').style.display='';\n"
        "  const vc=v=>{if(!v)return '';const lv=v.toLowerCase();return lv.includes('malicious')?'chip chip-critical':lv.includes('suspicious')?'chip chip-high':'chip chip-low'};\n"
        "  const rows=en.map(r=>`<tr><td><span class='type-badge'>${e(r.ioc_type||'')}</span></td><td class='mono'>${e(r.value||'')}</td><td style='color:var(--muted)'>${e(r.provider||'')}</td><td><span class='${vc(r.verdict)}'>${e(r.verdict||'\\u2014')}</span></td><td>${r.confidence!=null?Math.round(r.confidence*100)+'%':'\\u2014'}</td></tr>`).join('');\n"
        "  document.getElementById('enrichTbody').innerHTML=rows})();\n"
        "document.getElementById('sevFilter').addEventListener('change',renderFindings);\n"
        "document.getElementById('tacticFilter').addEventListener('change',renderFindings);\n"
        "document.getElementById('findingSearch').addEventListener('input',renderFindings);\n"
        "document.getElementById('typeFilter').addEventListener('input',renderTimeline);\n"
        "document.getElementById('riskFilter').addEventListener('input',renderTimeline);\n"
        "document.getElementById('tlSearch').addEventListener('input',renderTimeline);\n"
        "document.getElementById('iocTypeFilter').addEventListener('change',renderIocs);\n"
        "document.getElementById('iocSearch').addEventListener('input',renderIocs);\n"
        "renderFindings();renderTimeline();renderIocs();\n"
        "const _secs=['overview','findings','timeline','iocs','binaries','enrichments'];\n"
        "const _navs=document.querySelectorAll('.nav-item');\n"
        "window.addEventListener('scroll',()=>{const y=window.scrollY+120;\n"
        "  _secs.forEach((id,i)=>{const el=document.getElementById(id);\n"
        "    if(el&&el.offsetTop<=y){_navs.forEach(n=>n.classList.remove('active'));_navs[i]&&_navs[i].classList.add('active')}})\n"
        "},{passive:true});\n"
    )
    return (
        "<!DOCTYPE html>\n"
        "<html lang='en'>\n<head>\n"
        "  <meta charset='utf-8' />\n"
        "  <meta name='viewport' content='width=device-width, initial-scale=1' />\n"
        f"  <title>Auto Forensics \u2014 {ec}</title>\n"
        "  <link rel='preconnect' href='https://fonts.googleapis.com' />\n"
        "  <link href='https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap' rel='stylesheet' />\n"
        f"  <style>\n{CSS}\n  </style>\n</head>\n<body>\n"
        "<div class='shell'>\n"
        "<nav class='sidebar'>\n"
        "  <div class='sidebar-logo'>&#9889; AutoForensics</div>\n"
        "  <a class='nav-item active' onclick=\"goTo('overview')\"><span class='nav-icon'>&#128203;</span> Overview</a>\n"
        f"  <a class='nav-item' onclick=\"goTo('findings')\"><span class='nav-icon'>&#128269;</span> Findings<span class='nav-badge'>{tf}</span></a>\n"
        f"  <a class='nav-item' onclick=\"goTo('timeline')\"><span class='nav-icon'>&#128336;</span> Timeline<span class='nav-badge'>{tt}</span></a>\n"
        f"  <a class='nav-item' onclick=\"goTo('iocs')\"><span class='nav-icon'>&#128737;</span> IOCs<span class='nav-badge'>{ti}</span></a>\n"
        "  <a class='nav-item' onclick=\"goTo('binaries')\"><span class='nav-icon'>&#128190;</span> Binaries</a>\n"
        "  <a class='nav-item' onclick='window.print()'><span class='nav-icon'>&#128424;</span> Print</a>\n"
        "</nav>\n"
        "<div class='main'>\n"
        f"<header class='header' id='overview'>\n"
        "  <div class='header-eyebrow'>Auto Forensics &#x2014; Incident Report</div>\n"
        f"  <h1 class='header-title'>{ec}</h1>\n"
        f"  <p class='header-meta'>Generated <code>{ts}</code>"
        f" &nbsp;&middot;&nbsp; <code>{tf}</code> findings"
        f" &nbsp;&middot;&nbsp; <code>{ti}</code> IOCs"
        f" &nbsp;&middot;&nbsp; <code>{tt}</code> events"
        f" &nbsp;&middot;&nbsp; <code>{ac}</code> MITRE techniques</p>\n"
        "</header>\n"
        "<div class='stat-grid'>\n"
        f"  <div class='stat-card'><span class='stat-label'>Total Findings</span><span class='stat-value accent'>{tf}</span><span class='stat-sub'>across all severities</span></div>\n"
        f"  <div class='stat-card'><span class='stat-label'>Critical</span><span class='stat-value crit'>{cc}</span><span class='stat-sub'>immediate action</span></div>\n"
        f"  <div class='stat-card'><span class='stat-label'>High</span><span class='stat-value high'>{ch}</span><span class='stat-sub'>urgent review</span></div>\n"
        f"  <div class='stat-card'><span class='stat-label'>IOCs</span><span class='stat-value accent'>{ti}</span><span class='stat-sub'>indicators extracted</span></div>\n"
        f"  <div class='stat-card'><span class='stat-label'>Timeline Events</span><span class='stat-value' style='font-size:1.5rem'>{tt}</span><span class='stat-sub'>chronological view</span></div>\n"
        f"  <div class='stat-card'><span class='stat-label'>ATT&amp;CK Coverage</span><span class='stat-value accent'>{ac}</span><span class='stat-sub'>unique techniques</span></div>\n"
        "</div>\n"
        "<div class='sev-section'><div class='section-title'>Severity Breakdown</div><div class='sev-bars' id='sevBars'></div></div>\n"
        "<section class='content-section' id='findings'>\n"
        "  <div class='section-title'>Findings</div>\n"
        "  <div class='toolbar'>\n"
        "    <label><span class='toolbar-label'>Severity</span>&nbsp;<select id='sevFilter' class='ctrl'><option value=''>All</option><option value='critical'>Critical</option><option value='high'>High</option><option value='medium'>Medium</option><option value='low'>Low</option></select></label>\n"
        "    <label><span class='toolbar-label'>Tactic</span>&nbsp;<select id='tacticFilter' class='ctrl'><option value=''>All</option></select></label>\n"
        "    <input id='findingSearch' class='ctrl ctrl-search' placeholder='Search title, tactic, technique\u2026' />\n"
        "  </div>\n"
        "  <div class='tbl-wrap'><table><thead><tr><th>Severity</th><th>Title</th><th>Tactic</th><th>Technique</th><th>Confidence</th><th>Recommendation</th></tr></thead><tbody id='findingsTbody'></tbody></table></div>\n"
        "</section>\n"
        "<section class='content-section' id='timeline'>\n"
        "  <div class='section-title'>Timeline</div>\n"
        "  <div class='toolbar'>\n"
        "    <input id='typeFilter' class='ctrl' placeholder='Filter event type\u2026' style='min-width:180px' />\n"
        "    <label><span class='toolbar-label'>Min Risk</span>&nbsp;<input id='riskFilter' type='number' class='ctrl' min='0' max='100' placeholder='0' style='width:75px' /></label>\n"
        "    <input id='tlSearch' class='ctrl ctrl-search' placeholder='Search description\u2026' />\n"
        "  </div>\n"
        "  <div class='tbl-wrap'><table><thead><tr><th>Timestamp</th><th>Event Type</th><th>Source</th><th>Description</th><th>Risk</th></tr></thead><tbody id='timelineTbody'></tbody></table></div>\n"
        "</section>\n"
        "<section class='content-section' id='iocs'>\n"
        "  <div class='section-title'>Indicators of Compromise</div>\n"
        "  <div class='toolbar'>\n"
        "    <select id='iocTypeFilter' class='ctrl'><option value=''>All Types</option><option value='ip'>IP Address</option><option value='domain'>Domain</option><option value='url'>URL</option><option value='sha256'>SHA-256</option><option value='md5'>MD5</option><option value='email'>Email</option><option value='path'>Path</option></select>\n"
        "    <input id='iocSearch' class='ctrl ctrl-search' placeholder='Search value or source\u2026' />\n"
        "  </div>\n"
        "  <div class='tbl-wrap'><table><thead><tr><th>Type</th><th>Value</th><th>Sources</th><th>Copy</th></tr></thead><tbody id='iocsTbody'></tbody></table></div>\n"
        "</section>\n"
        "<section class='content-section' id='binaries'>\n"
        "  <div class='section-title'>Binary Analysis</div>\n"
        "  <div class='tbl-wrap'><table><thead><tr><th>Path</th><th>SHA-256</th><th>Entropy</th><th>Score</th><th>Notes</th></tr></thead><tbody id='binariesTbody'></tbody></table></div>\n"
        "</section>\n"
        "<section class='content-section' id='enrichments' style='display:none'>\n"
        "  <div class='section-title'>IOC Enrichment</div>\n"
        "  <div class='tbl-wrap'><table><thead><tr><th>Type</th><th>Value</th><th>Provider</th><th>Verdict</th><th>Confidence</th></tr></thead><tbody id='enrichTbody'></tbody></table></div>\n"
        "</section>\n"
        f"<footer class='footer'>Auto Forensics &nbsp;&middot;&nbsp; Case <strong>{ec}</strong> &nbsp;&middot;&nbsp; Generated {ts}</footer>\n"
        "</div></div>\n"
        f"<script>\n{JS}</script>\n"
        "</body>\n</html>\n"
    )


def run_case(config: PipelineConfig) -> CaseReport:
    _external_registry = config.plugin_registry is not None
    registry = config.plugin_registry or PluginRegistry()
    if not _external_registry:
        registry.register_defaults()
    artifacts, binaries = discover_artifacts(
        config.input_dir,
        max_text_bytes=config.max_text_bytes,
        parser_registry=registry.artifact_parsers,
    )
    with ThreadPoolExecutor(max_workers=4, thread_name_prefix="af-binary") as pool:
        binary_features = list(pool.map(registry.analyze_binary, binaries))

    # Cap directory traversal depth at 20 to avoid runaway scans on deep trees.
    def yara_filter(p: Path) -> bool:
        return len(p.relative_to(config.input_dir).parts) <= 20

    scan_candidates = walk_case_directory(
        config.input_dir,
        SecurityPolicy(max_text_bytes=config.max_text_bytes),
        filter_func=yara_filter
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
