from __future__ import annotations

import logging
from pathlib import Path

from .models import CaseReport

logger = logging.getLogger(__name__)

# Characters per line before hard-wrapping in the PDF.
_LINE_WIDTH_CHARS = 110
# Bottom margin in points below which a new page is started.
_BOTTOM_MARGIN = 60
# Top margin offset from page height where new pages start.
_TOP_MARGIN_OFFSET = 40
# Line height in points.
_LINE_HEIGHT = 14


def write_pdf_report(report: CaseReport, output_path: Path) -> bool:
    try:
        from reportlab.lib.pagesizes import letter  # type: ignore
        from reportlab.pdfgen import canvas  # type: ignore
    except ImportError:
        logger.debug("reportlab not installed; PDF report generation skipped")
        return False

    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        pdf = canvas.Canvas(str(output_path), pagesize=letter)
    except OSError as exc:
        logger.warning("Cannot create PDF at %s: %s", output_path, exc)
        return False

    width, height = letter
    y = height - _TOP_MARGIN_OFFSET
    page_num = [1]

    def _draw_page_number() -> None:
        pdf.setFont("Helvetica", 8)
        pdf.drawRightString(width - 40, 30, f"Page {page_num[0]}")

    def new_page() -> None:
        _draw_page_number()
        pdf.showPage()
        page_num[0] += 1

    def line(text: str, bold: bool = False, font_size: int = 10) -> None:
        nonlocal y
        if y < _BOTTOM_MARGIN:
            new_page()
            y = height - _TOP_MARGIN_OFFSET
            pdf.setFont("Helvetica-Bold" if bold else "Helvetica", font_size)
        # Hard-wrap long text to avoid overflow off the right margin.
        display = text[:_LINE_WIDTH_CHARS]
        if len(text) > _LINE_WIDTH_CHARS:
            display += "…"
        try:
            pdf.drawString(40, y, display)
        except Exception as exc:
            logger.debug("PDF drawString error: %s", exc)
        y -= _LINE_HEIGHT

    pdf.setFont("Helvetica-Bold", 14)
    line(f"Auto Forensics Case Report: {report.case_id}", bold=True, font_size=14)
    pdf.setFont("Helvetica", 10)
    line(f"Generated: {report.generated_at}")

    total = report.summary.get("total_findings", len(report.findings))
    severity_breakdown = report.summary.get("severity_breakdown", {})
    breakdown_str = "  ".join(
        f"{k.upper()}: {v}" for k, v in sorted(severity_breakdown.items(), key=lambda kv: kv[0])
    )
    line(f"Findings: {total}   {breakdown_str}")
    line(f"Timeline events: {len(report.timeline)}")
    line(f"IOCs: {len(report.iocs)}")
    technique_count = report.summary.get("attack_technique_coverage", 0)
    if technique_count:
        line(f"ATT&CK techniques covered: {technique_count}")
    line("")

    # --- Findings section (all findings, not just top 25) ---
    pdf.setFont("Helvetica-Bold", 12)
    line("Findings", bold=True, font_size=12)
    pdf.setFont("Helvetica", 10)
    if not report.findings:
        line("  No findings produced.")
    for finding in report.findings:
        sev = finding.severity.upper()
        line(f"  [{sev}] {finding.title} (conf={finding.confidence:.2f})")
        if finding.tactic or finding.technique_id:
            line(f"    Tactic: {finding.tactic}  Technique: {finding.technique_id or 'N/A'}")
        if finding.recommendation:
            line(f"    Recommendation: {finding.recommendation}")

    line("")
    # --- IOC section ---
    pdf.setFont("Helvetica-Bold", 12)
    line("Indicators of Compromise", bold=True, font_size=12)
    pdf.setFont("Helvetica", 10)
    if not report.iocs:
        line("  No IOCs extracted.")
    for ioc in report.iocs:
        sources_str = ", ".join(ioc.sources[:3])
        line(f"  [{ioc.ioc_type}] {ioc.value}  (src: {sources_str})")

    line("")
    # --- Timeline section ---
    pdf.setFont("Helvetica-Bold", 12)
    line("Timeline", bold=True, font_size=12)
    pdf.setFont("Helvetica", 10)
    if not report.timeline:
        line("  No timeline events.")
    for event in report.timeline:
        ts = event.timestamp or "unknown-time"
        line(f"  {ts} | {event.event_type} | {event.description}")

    try:
        _draw_page_number()
        pdf.save()
    except Exception as exc:
        logger.warning("PDF save failed for %s: %s", output_path, exc)
        return False
    return True
