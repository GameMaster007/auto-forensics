"""Autonomous forensic agent — discovers a Case folder and solves it without user input."""
from __future__ import annotations

import os
import re
import sys
import time
from pathlib import Path
from typing import Any

from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.rule import Rule
from rich.text import Text
from rich.table import Table

from .config import AppConfig
from .service import AutoForensicsService

console = Console()
err_console = Console(stderr=True)

_SEV_COLOR: dict[str, str] = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "green",
}

_BANNER = r"""
  ___        __         ______
 / _ |__ __/ /____    / ____/__  ________ ___  ___ (_)______
/ __ / // / __/ _ \  / /_  / _ \/ __/ -_) _ \(_-</ / __(_-<
/_/ |_\_,_/\__/\___/ /_/   \___/_/  \__/_//_/___/_/\__/___/
"""

# ---------------------------------------------------------------------------
# Case discovery
# ---------------------------------------------------------------------------

def discover_case_dir(base_dir: Path) -> Path | None:
    """
    Look for the first directory inside *base_dir* whose name starts with
    'Case' (case-insensitive).  Returns None if nothing is found.
    """
    for child in sorted(base_dir.iterdir()):
        if child.is_dir() and child.name.lower().startswith("case"):
            return child
    return None


def derive_case_id(case_dir: Path) -> str:
    """
    Turn a folder name into a valid case slug.
    E.g.  'Case'          → 'case'
          'Case-M57 Jean' → 'case-m57-jean'
    """
    slug = case_dir.name.lower()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    slug = slug.strip("-")
    return slug or "auto-case"


def _find_evidence_dir(case_dir: Path) -> Path:
    """
    Return the evidence source directory.  Priority:
    1. <case_dir>/evidence/   if it exists and is non-empty
    2. <case_dir>/            (the case folder itself)
    """
    evidence = case_dir / "evidence"
    if evidence.is_dir() and any(evidence.iterdir()):
        return evidence
    return case_dir


def _is_interactive() -> bool:
    """Return True when stdout is a real terminal (not a pipe/redirect)."""
    return sys.stdout.isatty() or os.getenv("WT_SESSION") is not None  # Windows Terminal


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

class ForensicAgent:
    """
    Runs the full Auto Forensics pipeline autonomously:
      discover → init → ingest → analyze → conclusions → report

    No user interaction is required at any point.
    """

    def __init__(self, config: AppConfig, enable_llm: bool = True) -> None:
        self.config = config
        self.enable_llm = enable_llm
        self.svc = AutoForensicsService(config)

    # ------------------------------------------------------------------
    # Pipeline steps
    # ------------------------------------------------------------------

    def _step_init(self, case_id: str) -> dict[str, Any]:
        console.print(f"  [dim]>[/] Initialising case [bold cyan]{case_id}[/]…")
        return self.svc.create_case(case_id)

    def _step_ingest(self, case_id: str, evidence_dir: Path) -> dict[str, Any]:
        console.print(f"  [dim]>[/] Ingesting evidence from [dim]{evidence_dir}[/]…")
        result = self.svc.ingest_case(case_id, evidence_dir)
        files = result.get("ingested_files", 0)
        console.print(f"  [dim]>[/] [bold]{files}[/] file(s) ingested")
        return result

    def _step_analyze(self, case_id: str) -> dict[str, Any]:
        console.print("  [dim]>[/] Starting analysis engine…")
        resp = self.svc.analyze_case_async(case_id, enable_llama=self.enable_llm)
        if not resp.get("accepted"):
            console.print("  [dim]>[/] Analysis already running — waiting for completion…")

        state = ""
        status: dict[str, Any] = {}
        with Progress(
            SpinnerColumn(),
            TextColumn("     {task.description}"),
            BarColumn(bar_width=None),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        ) as prog:
            task = prog.add_task("[bold]Queued…[/]", total=100)
            while True:
                status = self.svc.get_case_status(case_id)
                state = str(status.get("state", ""))
                pct = int(status.get("progress", 0))
                msg = str(status.get("message") or state or "Analysing…")
                prog.update(task, completed=pct, description=f"[bold]{msg}[/]")
                if state in {"complete", "failed"}:
                    break
                time.sleep(0.5)

        if state == "failed":
            err = status.get("error") or "Analysis failed — check case for ingested evidence."
            console.print(Panel(
                f"[bold red]{err}[/]\n[dim]The agent will continue and generate whatever report it can.[/]",
                title="[yellow]⚠ Analysis Warning[/]",
                border_style="yellow",
                expand=False,
            ))
        return status

    def _step_wipe_recovery(
        self, case_id: str, case_dir: Path
    ) -> dict[str, Any]:
        """Byte-level wipe-recovery analysis for any disk images in the case."""
        console.print(
            "  [dim]>[/] Scanning for disk images to run wipe-recovery analysis…"
        )
        output_dir = case_dir / "recovery_reports"
        result = self.svc.analyse_disk_images_in_case(
            case_id, output_dir=output_dir, extra_search_dir=case_dir
        )
        found = result.get("images_found", 0)
        analysed = result.get("images_analysed", 0)
        new_f = result.get("new_findings", 0)
        new_e = result.get("new_events", 0)
        if found == 0:
            console.print("  [dim]>[/] No disk images found — skipping wipe recovery")
        else:
            console.print(
                f"  [dim]>[/] Wipe recovery: "
                f"[bold]{analysed}/{found}[/] image(s) analysed  "
                f"[bold cyan]{new_f}[/] finding(s)  "
                f"[bold cyan]{new_e}[/] timeline event(s) added"
            )
        return result

    def _step_conclusions(self, case_id: str) -> dict[str, Any]:
        console.print("  [dim]>[/] Generating forensic conclusions…")
        return self.svc.generate_conclusions(case_id)

    def _step_report(self, case_id: str, case_dir: Path) -> tuple[str, str]:
        """Write both markdown and HTML reports; return (md_path, html_path)."""
        console.print("  [dim]>[/] Rendering reports…")
        md = self.svc.get_report(case_id, fmt="md")
        html = self.svc.get_report(case_id, fmt="html")
        md_path = case_dir / "agent_report.md"
        html_path = case_dir / "agent_report.html"
        md_path.write_text(md, encoding="utf-8")
        html_path.write_text(html, encoding="utf-8")
        return str(md_path), str(html_path)

    # ------------------------------------------------------------------
    # Display helpers
    # ------------------------------------------------------------------

    def _print_findings_table(self, findings: list[dict]) -> None:
        if not findings:
            console.print("  [dim]No findings recorded.[/]")
            return
        t = Table(
            box=box.ROUNDED, header_style="bold cyan", border_style="dim",
            show_lines=False, caption=f"[dim]{len(findings)} finding(s)[/]",
        )
        t.add_column("Sev", no_wrap=True, width=8)
        t.add_column("Title")
        t.add_column("Tactic", style="dim")
        t.add_column("Technique", style="dim", width=14)
        for f in findings:
            sev = str(f.get("severity", ""))
            color = _SEV_COLOR.get(sev.lower(), "white")
            t.add_row(
                Text(sev.upper(), style=color),
                str(f.get("title") or f.get("rule_name") or ""),
                str(f.get("tactic") or "—"),
                str(f.get("technique") or "—"),
            )
        console.print(t)

    def _print_iocs_table(self, iocs: list[dict]) -> None:
        if not iocs:
            return
        t = Table(
            box=box.SIMPLE_HEAD, header_style="bold", border_style="dim",
            caption=f"[dim]{len(iocs)} IOC(s)[/]",
        )
        t.add_column("Type", width=12)
        t.add_column("Value")
        t.add_column("Source", style="dim", max_width=32)
        for ioc in iocs[:30]:
            t.add_row(
                str(ioc.get("ioc_type") or ioc.get("type") or ""),
                str(ioc.get("value") or ""),
                str(ioc.get("source_event") or "—"),
            )
        if len(iocs) > 30:
            t.add_row("…", f"[dim]({len(iocs) - 30} more — see agent_report.html)[/]", "")
        console.print(t)

    def _print_conclusions_panel(self, conclusions_data: dict) -> None:
        conclusions = conclusions_data.get("conclusions", [])
        if not conclusions:
            return
        console.print(Rule("[dim]Agent Conclusions[/]", style="dim"))
        for i, c in enumerate(conclusions, 1):
            console.print(f"  [bold]{i}.[/] {c}")

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def run(
        self,
        case_dir: Path | None = None,
        case_id: str | None = None,
        base_dir: Path | None = None,
    ) -> None:
        """
        Run the full autonomous agent pipeline.

        Parameters
        ----------
        case_dir:
            Explicit path to the case folder.  If *None*, the agent
            auto-discovers a ``Case`` folder inside *base_dir*.
        case_id:
            Explicit case ID slug.  If *None*, derived from *case_dir*.
        base_dir:
            Root directory to search for the ``Case`` folder.  Defaults
            to the tool's own root directory (3 levels up from this file).
        """
        # ── Discovery ────────────────────────────────────────────────────
        if base_dir is None:
            base_dir = Path(__file__).resolve().parent.parent.parent

        if case_dir is None:
            case_dir = discover_case_dir(base_dir)
            if case_dir is None:
                err_console.print(Panel(
                    "[bold red]No Case folder found.[/]\n\n"
                    f"Place a folder named [bold]Case[/] (or [bold]Case-<name>[/]) "
                    f"inside:\n  [dim]{base_dir}[/]\n\n"
                    "The folder should contain evidence files.  Then re-run.\n\n"
                    "Override:  [dim]auto-forensics solve --case-dir path/to/my/case[/]",
                    title="[bold red]Agent: No Case Detected[/]",
                    border_style="red",
                    expand=False,
                ))
                raise SystemExit(1)
        else:
            case_dir = Path(case_dir).expanduser().resolve()
            if not case_dir.is_dir():
                err_console.print(f"[bold red]Case directory not found:[/] {case_dir}")
                raise SystemExit(1)

        if case_id is None:
            case_id = derive_case_id(case_dir)

        evidence_dir = _find_evidence_dir(case_dir)

        # ── Startup banner ───────────────────────────────────────────────
        console.print(f"[bold cyan]{_BANNER}[/]")
        console.print(Panel(
            "\n".join([
                f"  Case folder  :  [bold]{case_dir}[/]",
                f"  Evidence dir :  [dim]{evidence_dir}[/]",
                f"  Case ID      :  [bold cyan]{case_id}[/]",
                f"  LLM enabled  :  {'[green]yes[/]' if self.enable_llm else '[dim]no (heuristics only)[/]'}",
                "",
                "[dim]Pipeline:  init > ingest > analyse > wipe-recovery > conclude > report[/]",
                "[dim]No user input required.[/]",
            ]),
            title="[bold]Autonomous Agent[/]",
            border_style="cyan",
            expand=False,
        ))

        t0 = time.monotonic()

        # ── Pipeline ─────────────────────────────────────────────────────
        console.print(Rule("[bold dim]Step 1 / 6  ·  Init[/]", style="bright_black"))
        self._step_init(case_id)

        console.print(Rule("[bold dim]Step 2 / 6  ·  Ingest[/]", style="bright_black"))
        ingest_result = self._step_ingest(case_id, evidence_dir)

        console.print(Rule("[bold dim]Step 3 / 6  ·  Analyse[/]", style="bright_black"))
        self._step_analyze(case_id)

        console.print(Rule("[bold dim]Step 4 / 6  ·  Wipe Recovery[/]", style="bright_black"))
        self._step_wipe_recovery(case_id, case_dir)

        console.print(Rule("[bold dim]Step 5 / 6  ·  Conclusions[/]", style="bright_black"))
        conclusions_data = self._step_conclusions(case_id)

        console.print(Rule("[bold dim]Step 6 / 6  ·  Report[/]", style="bright_black"))
        md_path, html_path = self._step_report(case_id, case_dir)

        elapsed = time.monotonic() - t0

        # ── Pull final data ───────────────────────────────────────────────
        overview = self.svc.case_overview(case_id)
        findings = overview.get("findings", [])
        timeline = overview.get("timeline", [])
        iocs = overview.get("iocs", [])
        verdict = conclusions_data.get("risk_verdict", "UNKNOWN")
        verdict_color = {"HIGH": "bold red", "MEDIUM": "yellow", "LOW": "green"}.get(verdict, "white")

        # ── Severity histogram ────────────────────────────────────────────
        sev_counts: dict[str, int] = {}
        for f in findings:
            sev = str(f.get("severity", "low")).lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        sev_bars = []
        _block = "█"
        for sev in ["critical", "high", "medium", "low"]:
            count = sev_counts.get(sev, 0)
            if count:
                bar = Text(f"{sev.upper():10s} {_block * min(count * 3, 30)} {count}", style=_SEV_COLOR.get(sev, "white"))
                sev_bars.append(bar)

        # ── Summary panel ─────────────────────────────────────────────────
        console.print()
        console.print(Rule("[bold green]Case Solved[/]", style="green"))
        console.print()
        console.print(Panel(
            "\n".join([
                f"[bold cyan]{case_id}[/]   Risk Verdict: [{verdict_color}]{verdict}[/{verdict_color}]",
                "",
                f"  Findings         :  [bold]{len(findings)}[/]",
                f"  IOCs             :  [bold]{len(iocs)}[/]",
                f"  Timeline events  :  [bold]{len(timeline)}[/]",
                f"  Ingested files   :  [bold]{ingest_result.get('ingested_files', '?')}[/]",
                f"  Elapsed          :  {elapsed:.1f}s",
                "",
                f"  [dim]Markdown report :[/]  [bold green]{md_path}[/]",
                f"  [dim]HTML report    :[/]  [bold green]{html_path}[/]",
            ]),
            title="[bold green]Agent Complete[/]",
            border_style="green",
            expand=False,
        ))

        # Severity bars
        if sev_bars:
            console.print()
            for bar in sev_bars:
                console.print(f"  {bar}")

        # Findings table
        if findings:
            console.print()
            console.print(Rule("[dim]Findings[/]", style="dim"))
            self._print_findings_table(findings)

        # IOC summary
        if iocs:
            console.print()
            console.print(Rule("[dim]Indicators of Compromise[/]", style="dim"))
            self._print_iocs_table(iocs)

        # Conclusions
        self._print_conclusions_panel(conclusions_data)

        console.print()
