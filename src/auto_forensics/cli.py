from __future__ import annotations

import argparse
import csv as csv_mod
import hashlib
import io
import json
import sys
import time
from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.prompt import Confirm
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from .api import main as api_main
from .config import AppConfig
from .pipeline import PipelineConfig, run_case
from .security import SecurityError, validate_case_id
from .service import AutoForensicsService

console = Console()
err_console = Console(stderr=True)

_SEV_COLOR: dict[str, str] = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "green",
}

_STATUS_BADGE: dict[str, str] = {
    "complete":  "[bold green]●[/] complete",
    "analyzing": "[yellow]◐[/] analyzing",
    "failed":    "[bold red]✗[/] failed",
    "ingesting": "[cyan]◌[/] ingesting",
    "pending":   "[dim]○[/] pending",
    "created":   "[dim]○[/] created",
    "ready":     "[bold cyan]◉[/] ready",
    "running":   "[yellow]◐[/] running",
    "queued":    "[dim]◌[/] queued",
    "not_found": "[dim]?[/] not found",
}

_BLOCK = "█"


def _badge(status: str) -> str:
    return _STATUS_BADGE.get(str(status).lower(), f"[dim]{status}[/]")


def _sev_text(severity: str) -> Text:
    color = _SEV_COLOR.get(str(severity).lower(), "white")
    return Text(str(severity).upper(), style=color)


def _fmt_ts(ts: str | None) -> str:
    if not ts:
        return "—"
    return str(ts).split(".")[0].replace("T", " ")


def _fmt_size(size_bytes: int | None) -> str:
    if not size_bytes:
        return "—"
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    if size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / 1024 / 1024:.1f} MB"
    return f"{size_bytes / 1024 / 1024 / 1024:.1f} GB"


def _severity_histogram(findings: list[dict]) -> Table | None:
    """Horizontal Unicode block bar chart of findings by severity."""
    order = ["critical", "high", "medium", "low"]
    counts: dict[str, int] = {s: 0 for s in order}
    for f in findings:
        sev = str(f.get("severity") or "low").lower()
        if sev in counts:
            counts[sev] += 1
    if not any(counts.values()):
        return None
    max_count = max(counts.values()) or 1
    bar_width = 24
    t = Table(box=None, show_header=False, padding=(0, 1), expand=False)
    t.add_column("Severity", style="dim", min_width=10)
    t.add_column("Bar")
    t.add_column("Count", justify="right", min_width=4)
    for sev in order:
        count = counts[sev]
        if count == 0:
            continue
        filled = max(1, int(bar_width * count / max_count))
        bar = Text(_BLOCK * filled, style=_SEV_COLOR.get(sev, "white"))
        t.add_row(sev.upper(), bar, str(count))
    return t


def _build_artifact_tree(artifacts: list[dict]) -> Tree:
    """Build a rich Tree from artifact rel_paths."""
    root = Tree("[bold dim]Evidence[/]")
    dirs: dict[str, Tree] = {"": root}
    for art in sorted(artifacts, key=lambda x: str(x.get("rel_path", ""))):
        path = str(art.get("rel_path", "")).replace("\\", "/")
        parts = [p for p in path.split("/") if p]
        if not parts:
            continue
        parent_key = ""
        for i, part in enumerate(parts[:-1]):
            key = "/".join(parts[: i + 1])
            if key not in dirs:
                dirs[key] = dirs[parent_key].add(f"[dim cyan]{part}/[/]")
            parent_key = key
        fname = parts[-1]
        atype = str(art.get("artifact_type") or "")
        size_str = _fmt_size(art.get("size_bytes"))
        label = f"[bold]{fname}[/]"
        meta_parts = [atype, size_str if size_str != "—" else ""]
        meta = "  ".join(p for p in meta_parts if p)
        if meta:
            label += f"  [dim]{meta}[/]"
        dirs[parent_key].add(label)
    return root


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

def _cmd_init(args: argparse.Namespace, svc: AutoForensicsService) -> None:
    result = svc.create_case(args.case_id)
    status = result.get("status", "created")
    lines = [
        f"[bold cyan]{result.get('case_id', args.case_id)}[/]",
        f"Status:    {_badge(status)}",
        f"Created:   {_fmt_ts(result.get('created_at'))}",
        f"Evidence:  {result.get('evidence_dir', '—')}",
        f"Output:    {result.get('output_dir', '—')}",
    ]
    console.print(Panel("\n".join(lines), title="[bold]Case Initialized[/]", border_style="cyan", expand=False))


def _cmd_list(args: argparse.Namespace, svc: AutoForensicsService) -> None:
    cases = svc.list_cases()
    if args.json:
        console.print_json(json.dumps(cases))
        return
    if not cases:
        console.print(
            "[dim]No cases found. Run [bold]auto-forensics init --case-id <id>[/] to create one.[/]"
        )
        return
    t = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
        caption=f"[dim]{len(cases)} case(s)[/]",
    )
    t.add_column("Case ID", style="bold")
    t.add_column("Status", no_wrap=True)
    t.add_column("Created", style="dim")
    t.add_column("Updated", style="dim")
    t.add_column("Last Error", style="dim red", max_width=40)
    for c in cases:
        err = str(c.get("last_error") or "")
        t.add_row(
            str(c.get("case_id", "")),
            _badge(c.get("status", "")),
            _fmt_ts(c.get("created_at")),
            _fmt_ts(c.get("updated_at")),
            (err[:38] + "…") if len(err) > 40 else err,
        )
    console.print(t)


def _cmd_stats(args: argparse.Namespace, svc: AutoForensicsService) -> None:
    data = svc.case_stats()
    total = data.get("total_cases", 0)
    by_status = data.get("by_status", {})
    active = data.get("active_cases", 0)
    failed = data.get("failed_cases", 0)

    summary = (
        f"[bold]{total}[/] total case(s)   "
        f"[bold cyan]{active}[/] active   "
        f"[bold red]{failed}[/] failed"
    )
    if data.get("newest_updated_at"):
        summary += f"\nLast activity:  [dim]{_fmt_ts(data['newest_updated_at'])}[/]"
    console.print(Panel(summary, title="[bold]Global Stats[/]", border_style="cyan", expand=False))

    if by_status:
        status_order = ["complete", "ready", "created", "ingesting", "analyzing", "failed"]
        status_colors = {
            "complete": "green", "ready": "cyan", "created": "dim",
            "ingesting": "cyan", "analyzing": "yellow", "failed": "red",
        }
        t = Table(box=None, show_header=False, padding=(0, 1), expand=False)
        t.add_column("Status", style="dim", min_width=12)
        t.add_column("Bar")
        t.add_column("Count", justify="right", min_width=4)
        max_count = max(by_status.values()) or 1
        seen = set()
        for st in status_order:
            count = by_status.get(st, 0)
            if count == 0:
                continue
            seen.add(st)
            filled = max(1, int(30 * count / max_count))
            t.add_row(st.upper(), Text(_BLOCK * filled, style=status_colors.get(st, "white")), str(count))
        for st, count in by_status.items():
            if st not in seen:
                filled = max(1, int(30 * count / max_count))
                t.add_row(st.upper(), Text(_BLOCK * filled, style="dim"), str(count))
        console.print(t)


def _cmd_ingest(args: argparse.Namespace, svc: AutoForensicsService) -> None:
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        transient=True,
        console=console,
    ) as prog:
        prog.add_task(f"Ingesting [cyan]{args.case_id}[/] from [dim]{args.source_dir}[/]…")
        result = svc.ingest_case(args.case_id, args.source_dir)

    ingested = result.get("ingested_files", 0)
    summary_lines = [
        f"Case:   [bold cyan]{result.get('case', args.case_id)}[/]",
        f"Files:  [bold]{ingested}[/] ingested",
        f"Dir:    [dim]{result.get('evidence_dir', '—')}[/]",
    ]
    console.print(Panel("\n".join(summary_lines), title="[bold green]Ingest Complete[/]", border_style="green", expand=False))

    # Artifact type breakdown from DB
    artifacts = svc.case_overview(args.case_id).get("artifacts", [])
    if artifacts:
        type_counts: dict[str, int] = {}
        for art in artifacts:
            atype = str(art.get("artifact_type") or "unknown")
            type_counts[atype] = type_counts.get(atype, 0) + 1
        bt = Table(
            box=box.SIMPLE_HEAD, header_style="bold dim", border_style="dim",
            expand=False, caption="[dim]by artifact type[/]",
        )
        bt.add_column("Type")
        bt.add_column("Files", justify="right", style="bold")
        for atype, count in sorted(type_counts.items(), key=lambda x: -x[1]):
            bt.add_row(atype, str(count))
        console.print(bt)


def _cmd_analyze(args: argparse.Namespace, svc: AutoForensicsService) -> None:
    # Launch async so we can stream live progress
    resp = svc.analyze_case_async(args.case_id, enable_llama=not args.disable_llama)
    if not resp.get("accepted"):
        console.print(Panel(
            f"[yellow]Analysis already running for this case.[/]\n{resp.get('detail', '')}",
            title="[yellow]Already Running[/]", border_style="yellow", expand=False,
        ))
        return

    state = ""
    status: dict[str, Any] = {}
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=None),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as prog:
        task = prog.add_task("[bold]Queued…[/]", total=100)
        while True:
            status = svc.get_case_status(args.case_id)
            state = str(status.get("state", ""))
            pct = int(status.get("progress", 0))
            msg = str(status.get("message") or state or "Analyzing…")
            prog.update(task, completed=pct, description=f"[bold]{msg}[/]")
            if state in {"complete", "failed"}:
                break
            time.sleep(0.5)

    if state == "failed":
        err_console.print(Panel(
            f"[bold red]{status.get('error') or 'Analysis failed.'}[/]",
            title="[bold red]Analysis Failed[/]", border_style="red", expand=False,
        ))
        raise SystemExit(1)

    # Pull fresh counts from DB
    overview = svc.case_overview(args.case_id)
    findings = overview.get("findings", [])
    timeline = overview.get("timeline", [])
    iocs = overview.get("iocs", [])

    t = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan", border_style="dim")
    t.add_column("Metric")
    t.add_column("Count", justify="right", style="bold")
    t.add_row("Findings", str(len(findings)))
    t.add_row("Timeline events", str(len(timeline)))
    t.add_row("IOCs", str(len(iocs)))
    console.print(Panel(t, title="[bold green]Analysis Complete[/]", border_style="green", expand=False))

    hist = _severity_histogram(findings)
    if hist:
        console.print(hist)


def _cmd_enrich(args: argparse.Namespace, svc: AutoForensicsService) -> None:
    if args.status:
        status = svc.get_case_enrichment_status(args.case_id)
        state = str(status.get("state", ""))
        lines = [
            f"State:    {_badge(state)}",
            f"Progress: {status.get('progress', 0)}%",
            f"Message:  {status.get('message', '—')}",
        ]
        console.print(Panel("\n".join(lines), title="[bold]Enrichment Status[/]", border_style="cyan", expand=False))
        return

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        transient=True,
        console=console,
    ) as prog:
        prog.add_task(f"Enriching IOCs for [cyan]{args.case_id}[/]…")
        result = svc.enrich_case_iocs_async(args.case_id)

    lines = [
        f"Accepted: {'[green]yes[/]' if result.get('accepted') else '[dim]no[/]'}",
        f"Job ID:   [dim]{result.get('job_id', '—')}[/]",
    ]
    if result.get("detail"):
        lines.append(f"Detail:   {result['detail']}")
    console.print(Panel("\n".join(lines), title="[bold]Enrichment Started[/]", border_style="cyan", expand=False))


def _cmd_overview(args: argparse.Namespace, svc: AutoForensicsService) -> None:
    data = svc.case_overview(args.case_id)
    if args.json:
        console.print_json(json.dumps(data))
        return

    case = data.get("case", {})
    findings = data.get("findings", [])
    iocs = data.get("iocs", [])
    timeline = data.get("timeline", [])
    artifacts = data.get("artifacts", [])
    summary = data.get("summary", {})

    # ── Summary card ──────────────────────────────────────────────────────────
    status = str(case.get("status", ""))
    risk = summary.get("risk_score") or summary.get("total_risk_score")
    risk_str = f"   Risk: [bold yellow]{risk}[/]" if risk is not None else ""
    summary_lines = [
        f"[bold cyan]{case.get('case_id', args.case_id)}[/]   {_badge(status)}{risk_str}",
        (
            f"[dim]Artifacts:[/] [bold]{len(artifacts)}[/]   "
            f"[dim]Findings:[/] [bold]{len(findings)}[/]   "
            f"[dim]IOCs:[/] [bold]{len(iocs)}[/]   "
            f"[dim]Timeline:[/] [bold]{len(timeline)}[/]"
        ),
        f"[dim]Created: [/]{_fmt_ts(case.get('created_at'))}",
        f"[dim]Updated: [/]{_fmt_ts(case.get('updated_at'))}",
    ]
    if case.get("last_error"):
        summary_lines.append(f"[dim]Error:   [/][red]{case['last_error']}[/]")
    console.print(Panel("\n".join(summary_lines), title="[bold]Case Overview[/]", border_style="cyan"))

    # ── Severity histogram ────────────────────────────────────────────────────
    hist = _severity_histogram(findings)
    if hist:
        console.print(Rule("[dim]Findings by Severity[/]", style="dim"))
        console.print(hist)

    # ── Findings table ────────────────────────────────────────────────────────
    if findings:
        console.print(Rule("[dim]Findings[/]", style="dim"))
        ft = Table(box=box.SIMPLE_HEAD, header_style="bold", border_style="dim", show_lines=False)
        ft.add_column("Sev", no_wrap=True, width=8)
        ft.add_column("Rule / Title")
        ft.add_column("Tactic", style="dim")
        ft.add_column("Technique", style="dim", width=14)
        ft.add_column("Source", style="dim", max_width=32)
        for f in findings:
            ft.add_row(
                _sev_text(str(f.get("severity", ""))),
                str(f.get("title") or f.get("rule_name") or ""),
                str(f.get("tactic") or "—"),
                str(f.get("technique") or "—"),
                str(f.get("source_file") or "—"),
            )
        console.print(ft)

    # ── IOCs table ────────────────────────────────────────────────────────────
    if iocs:
        console.print(Rule("[dim]IOCs[/]", style="dim"))
        it = Table(box=box.SIMPLE_HEAD, header_style="bold", border_style="dim")
        it.add_column("Type", width=10)
        it.add_column("Value")
        it.add_column("Source", style="dim", max_width=32)
        for ioc in iocs:
            it.add_row(
                str(ioc.get("ioc_type") or ioc.get("type") or ""),
                str(ioc.get("value") or ""),
                str(ioc.get("source_event") or "—"),
            )
        console.print(it)

    # ── Timeline (last 20) ────────────────────────────────────────────────────
    recent = timeline[-20:] if len(timeline) > 20 else timeline
    if recent:
        label = (
            f"Timeline — last {len(recent)} of {len(timeline)}"
            if len(timeline) > 20
            else "Timeline"
        )
        console.print(Rule(f"[dim]{label}[/]", style="dim"))
        tl = Table(box=box.SIMPLE_HEAD, header_style="bold", border_style="dim")
        tl.add_column("Timestamp", style="dim", no_wrap=True, width=20)
        tl.add_column("Event")
        tl.add_column("Risk", justify="right", width=6)
        tl.add_column("Source", style="dim", max_width=32)
        for ev in recent:
            risk_val = ev.get("risk_score")
            if risk_val is not None:
                risk_color = "red" if risk_val >= 70 else "yellow" if risk_val >= 40 else "green"
                risk_text = Text(str(risk_val), style=risk_color)
            else:
                risk_text = Text("—", style="dim")
            tl.add_row(
                _fmt_ts(ev.get("timestamp")),
                str(ev.get("description") or ev.get("event_type") or ""),
                risk_text,
                str(ev.get("source_file") or "—"),
            )
        console.print(tl)

    # ── Artifact tree ─────────────────────────────────────────────────────────
    if artifacts:
        console.print(Rule("[dim]Evidence Files[/]", style="dim"))
        console.print(_build_artifact_tree(artifacts))


def _cmd_report(args: argparse.Namespace, svc: AutoForensicsService) -> None:
    payload = svc.get_report(args.case_id, fmt=args.format)
    if args.format in {"json", "navigator", "stix"}:
        console.print(Syntax(payload, "json", theme="monokai", line_numbers=False, word_wrap=True))
    elif args.format == "md":
        console.print(Markdown(payload))
    else:
        console.print(payload)


def _cmd_jobs(args: argparse.Namespace, svc: AutoForensicsService) -> None:
    jobs = svc.case_job_history(args.case_id, job_type=args.type, limit=args.limit)
    if args.json:
        console.print_json(json.dumps(jobs))
        return
    if not jobs:
        console.print("[dim]No jobs found.[/]")
        return
    t = Table(
        box=box.ROUNDED, show_header=True, header_style="bold cyan",
        border_style="dim", caption=f"[dim]{len(jobs)} job(s)[/]",
    )
    t.add_column("Job ID", style="dim")
    t.add_column("Type")
    t.add_column("Status", no_wrap=True)
    t.add_column("Started", style="dim")
    t.add_column("Duration", justify="right")
    t.add_column("Message", style="dim", max_width=40)
    for j in jobs:
        started = _fmt_ts(j.get("started_at"))
        dur = j.get("duration_seconds")
        dur_str = f"{dur:.1f}s" if dur is not None else "—"
        t.add_row(
            str(j.get("job_id", "")),
            str(j.get("job_type") or j.get("type") or ""),
            _badge(j.get("status") or j.get("state") or ""),
            started,
            dur_str,
            str(j.get("message") or ""),
        )
    console.print(t)


def _cmd_serve(args: argparse.Namespace, config: AppConfig) -> None:
    if args.host:
        config.host = args.host
    if args.port:
        config.port = args.port
    host_display = config.host
    port_display = config.port
    browser_host = "127.0.0.1" if host_display in {"0.0.0.0", "::"} else host_display
    lines = [
        "[bold cyan]Auto Forensics API[/]  [dim]v1.0.0[/]",
        "",
        f"  Base URL :  [bold]http://{browser_host}:{port_display}[/]",
        f"  Docs     :  [dim]http://{browser_host}:{port_display}/docs[/]",
        f"  Health   :  [dim]http://{browser_host}:{port_display}/api/health[/]",
        "",
        f"  Bind     :  [dim]{host_display}:{port_display}[/]",
        "",
        "[dim]Set AUTO_FORENSICS_API_KEY to enable API key auth.[/]",
        "[dim]Press Ctrl+C to stop.[/]",
    ]
    console.print(Panel("\n".join(lines), title="[bold]API Server Starting[/]", border_style="cyan", expand=False))
    api_main(config)


def _cmd_run(args: argparse.Namespace, config: AppConfig) -> None:
    cfg = PipelineConfig(
        case_id=args.case_id,
        input_dir=args.input_dir,
        output_dir=args.output_dir,
        enable_llama=not args.disable_llama,
        llama_endpoint=args.llama_endpoint,
        llama_model=args.llama_model,
        rules_dir=config.rules_dir,
        sigma_rules_dir=config.sigma_rules_dir,
        attack_stix_path=config.attack_stix_path,
        openai_compatible_endpoint=config.openai_compatible_endpoint,
        openai_api_key=config.openai_api_key,
    )

    console.print(Rule(f"[bold]Pipeline — {args.case_id}[/]", style="cyan"))
    t0 = time.monotonic()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        transient=True,
        console=console,
    ) as prog:
        prog.add_task("[bold]Running full analysis pipeline…[/]")
        report_obj = run_case(cfg)

    elapsed = time.monotonic() - t0

    # Per-severity breakdown (findings may be Finding dataclass objects)
    findings_by_sev: dict[str, int] = {}
    for f in report_obj.findings:
        sev = str(getattr(f, "severity", None) or f.get("severity", "low") if isinstance(f, dict) else "low").lower()
        findings_by_sev[sev] = findings_by_sev.get(sev, 0) + 1

    t = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold", border_style="dim")
    t.add_column("Metric")
    t.add_column("Value", justify="right", style="bold")
    t.add_row("Findings", str(len(report_obj.findings)))
    for sev in ["critical", "high", "medium", "low"]:
        count = findings_by_sev.get(sev, 0)
        if count:
            t.add_row(f"  {sev}", Text(str(count), style=_SEV_COLOR.get(sev, "white")))
    t.add_row("Timeline events", str(len(report_obj.timeline)))
    t.add_row("IOCs", str(len(report_obj.iocs)))
    t.add_row("Elapsed", f"{elapsed:.1f}s")
    t.add_row("Output dir", str(cfg.output_dir))
    console.print(Panel(t, title="[bold green]Pipeline Complete[/]", border_style="green", expand=False))


def _cmd_export(args: argparse.Namespace, svc: AutoForensicsService) -> None:
    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(), transient=True, console=console,
    ) as prog:
        prog.add_task(f"Exporting [cyan]{args.case_id}[/]…")
        result = svc.export_case_archive(args.case_id, args.dest)
    archive_path = result.get("archive") or str(args.dest)
    lines = [
        f"Case:     [bold cyan]{args.case_id}[/]",
        f"Archive:  [bold]{archive_path}[/]",
        f"Files:    [bold]{result.get('files', '?')}[/]",
    ]
    console.print(Panel("\n".join(lines), title="[bold green]Export Complete[/]", border_style="green", expand=False))


def _cmd_import(args: argparse.Namespace, svc: AutoForensicsService) -> None:
    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(), transient=True, console=console,
    ) as prog:
        prog.add_task(f"Importing [dim]{args.archive}[/]…")
        result = svc.import_case_archive(args.archive, case_id_override=args.case_id)
    lines = [
        f"Case:         [bold cyan]{result.get('case_id', '—')}[/]",
        f"Evidence dir: [dim]{result.get('evidence_dir', '—')}[/]",
        f"Output dir:   [dim]{result.get('output_dir', '—')}[/]",
    ]
    console.print(Panel("\n".join(lines), title="[bold green]Import Complete[/]", border_style="green", expand=False))


def _cmd_delete(args: argparse.Namespace, svc: AutoForensicsService) -> None:
    if not getattr(args, "force", False):
        if not Confirm.ask(
            f"[bold red]Permanently delete case [cyan]{args.case_id}[/] and all its data?[/]",
            default=False,
            console=console,
        ):
            console.print("[dim]Cancelled.[/]")
            return
    result = svc.delete_case(args.case_id)
    lines = [
        f"Case:         [bold cyan]{result.get('case_id', args.case_id)}[/]",
        f"Deleted:      [bold green]yes[/]",
        f"Dirs removed: [bold]{result.get('dirs_removed', 0)}[/]",
    ]
    console.print(Panel("\n".join(lines), title="[bold red]Case Deleted[/]", border_style="red", expand=False))




def _cmd_migrate(args: argparse.Namespace, svc: AutoForensicsService) -> None:
    if args.status:
        data = svc.db_migration_status()
        t = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan", border_style="dim")
        t.add_column("Version", justify="right", width=8)
        t.add_column("Description")
        t.add_column("Applied At", style="dim")
        for step in data.get("history", []):
            t.add_row(
                str(step.get("version", "")),
                str(step.get("description", "")),
                _fmt_ts(step.get("applied_at")),
            )
        console.print(Panel(
            f"Schema version: [bold cyan]{data.get('current_version', '?')}[/]",
            title="[bold]Migration Status[/]", border_style="cyan", expand=False,
        ))
        if data.get("history"):
            console.print(t)
    else:
        result = svc.run_db_migrations()
        lines = [
            f"Applied:  [bold]{result.get('applied', 0)}[/] migration(s)",
            f"Version:  [bold cyan]{result.get('current_version', '?')}[/]",
        ]
        console.print(Panel("\n".join(lines), title="[bold green]Migrations Complete[/]", border_style="green", expand=False))


def _cmd_cleanup_jobs(args: argparse.Namespace, svc: AutoForensicsService) -> None:
    days = args.retention_days
    days_label = f"{days} day(s)" if days is not None else "the default retention window"
    if not getattr(args, "force", False):
        if not Confirm.ask(
            f"[yellow]Delete job records older than {days_label}?[/]",
            default=False,
            console=console,
        ):
            console.print("[dim]Cancelled.[/]")
            return
    result = svc.cleanup_job_history(retention_days=days)
    removed = result.get("removed_analysis_jobs", 0) + result.get("removed_enrichment_jobs", 0)
    console.print(
        f"[green]✓[/] Deleted [bold]{removed}[/] job record(s) older than {days_label}."
    )


def _cmd_search(args: argparse.Namespace, svc: AutoForensicsService) -> None:
    result = svc.search_case(args.case_id, args.query, limit=args.limit)
    if args.json:
        console.print_json(json.dumps(result))
        return

    counts = result.get("counts", {})
    console.print(Panel(
        f"Query [bold yellow]\"{result.get('query', args.query)}\"[/]"
        f" in [bold cyan]{args.case_id}[/]"
        f"   Findings: [bold]{counts.get('findings', 0)}[/]"
        f"   IOCs: [bold]{counts.get('iocs', 0)}[/]"
        f"   Timeline: [bold]{counts.get('timeline', 0)}[/]",
        title="[bold]Search Results[/]", border_style="cyan", expand=False,
    ))

    findings = result.get("findings", [])
    if findings:
        console.print(Rule("[dim]Findings[/]", style="dim"))
        ft = Table(box=box.SIMPLE_HEAD, header_style="bold", border_style="dim")
        ft.add_column("Sev", no_wrap=True, width=8)
        ft.add_column("Title")
        ft.add_column("Tactic", style="dim")
        for f in findings:
            ft.add_row(
                _sev_text(str(f.get("severity", ""))),
                str(f.get("title") or f.get("rule_name") or ""),
                str(f.get("tactic") or "—"),
            )
        console.print(ft)

    iocs = result.get("iocs", [])
    if iocs:
        console.print(Rule("[dim]IOCs[/]", style="dim"))
        it = Table(box=box.SIMPLE_HEAD, header_style="bold", border_style="dim")
        it.add_column("Type", width=10)
        it.add_column("Value")
        for ioc in iocs:
            it.add_row(
                str(ioc.get("ioc_type") or ioc.get("type") or ""),
                str(ioc.get("value") or ""),
            )
        console.print(it)

    timeline = result.get("timeline", [])
    if timeline:
        console.print(Rule("[dim]Timeline Events[/]", style="dim"))
        tl = Table(box=box.SIMPLE_HEAD, header_style="bold", border_style="dim")
        tl.add_column("Timestamp", style="dim", width=20)
        tl.add_column("Description")
        tl.add_column("Source", style="dim", max_width=32)
        for ev in timeline:
            tl.add_row(
                _fmt_ts(ev.get("timestamp")),
                str(ev.get("description") or ""),
                str(ev.get("source_file") or "—"),
            )
        console.print(tl)

    if not findings and not iocs and not timeline:
        console.print("[dim]No results found for that query.[/]")


def _cmd_notes(args: argparse.Namespace, svc: AutoForensicsService) -> None:
    notes = svc.list_case_notes(args.case_id)
    if args.json:
        console.print_json(json.dumps(notes))
        return
    if not notes:
        console.print(
            f"[dim]No notes for [bold]{args.case_id}[/]. "
            "Add one with [bold]add-note --case-id ... --text ...[/][/]"
        )
        return
    t = Table(
        box=box.ROUNDED, show_header=True, header_style="bold cyan",
        border_style="dim", caption=f"[dim]{len(notes)} note(s)[/]",
    )
    t.add_column("Author", style="bold", width=16)
    t.add_column("Timestamp", style="dim", width=20)
    t.add_column("Note")
    for n in notes:
        t.add_row(
            str(n.get("author") or "—"),
            _fmt_ts(n.get("created_at")),
            str(n.get("content") or ""),
        )
    console.print(t)


def _cmd_add_note(args: argparse.Namespace, svc: AutoForensicsService) -> None:
    result = svc.add_case_note(args.case_id, content=args.text, author=args.author)
    lines = [
        f"Case:   [bold cyan]{args.case_id}[/]",
        f"Author: [bold]{result.get('author', args.author)}[/]",
        f"Note:   {result.get('content', args.text)[:120]}",
        f"ID:     [dim]{result.get('note_id', '—')}[/]",
    ]
    console.print(Panel("\n".join(lines), title="[bold green]Note Added[/]", border_style="green", expand=False))


def _cmd_scan(args: argparse.Namespace, svc: AutoForensicsService) -> None:
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        transient=True,
        console=console,
    ) as prog:
        prog.add_task(f"Scanning [cyan]{args.path}[/]…")
        result = svc.scan_file(args.path)

    if args.json:
        console.print_json(json.dumps(result))
        return

    lines = [
        f"File:     [bold]{result.get('path', str(args.path))}[/]",
        f"Size:     [bold]{_fmt_size(result.get('size_bytes'))}[/]",
        f"SHA-256:  [dim]{result.get('sha256', '—')}[/]",
        f"MD5:      [dim]{result.get('md5', '—')}[/]",
        f"Entropy:  [bold yellow]{result.get('entropy', 0):.4f}[/]",
        f"Score:    [bold {'red' if result.get('suspicious_score', 0) >= 3 else 'yellow' if result.get('suspicious_score', 0) > 0 else 'green'}]{result.get('suspicious_score', 0)}[/]",
    ]
    console.print(Panel("\n".join(lines), title="[bold]File Scan[/]", border_style="cyan", expand=False))

    string_hits = result.get("string_hits", [])
    if string_hits:
        console.print(Rule("[dim]Suspicious Strings[/]", style="dim"))
        for s in string_hits:
            console.print(f"  [yellow]•[/] {s}")

    import_hints = result.get("import_hints", [])
    if import_hints:
        console.print(Rule("[dim]Risky PE Imports[/]", style="dim"))
        for h in import_hints:
            console.print(f"  [red]•[/] {h}")

    rationale = result.get("rationale", [])
    if rationale:
        console.print(Rule("[dim]Analysis Rationale[/]", style="dim"))
        for r in rationale:
            console.print(f"  [dim]→[/] {r}")

    yara_hits = result.get("yara_hits", [])
    if yara_hits:
        console.print(Rule("[dim]YARA Matches[/]", style="dim"))
        for yh in yara_hits:
            console.print(f"  [bold red]⚑[/] {yh.get('rule', '?')}  [dim]{yh.get('tags', [])}[/]")


def _cmd_scan_dir(args: argparse.Namespace, svc: AutoForensicsService) -> None:
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        transient=True,
        console=console,
    ) as prog:
        prog.add_task(f"Scanning directory [cyan]{args.path}[/]…")
        result = svc.scan_directory(args.path, recursive=not args.no_recursive)

    if args.json:
        console.print_json(json.dumps(result))
        return

    lines = [
        f"Directory:  [bold]{result.get('directory', str(args.path))}[/]",
        f"Recursive:  {'[green]yes[/]' if result.get('recursive') else '[dim]no[/]'}",
        f"Files:      [bold]{result.get('total_files', 0)}[/]",
        f"Total size: [bold]{_fmt_size(result.get('total_bytes'))}[/]",
        f"Suspicious: [bold {'red' if result.get('suspicious_files', 0) > 0 else 'green'}]{result.get('suspicious_files', 0)}[/]",
    ]
    console.print(Panel("\n".join(lines), title="[bold]Directory Scan[/]", border_style="cyan", expand=False))

    files = result.get("files", [])
    if files:
        t = Table(box=box.SIMPLE_HEAD, header_style="bold", border_style="dim")
        t.add_column("Score", justify="right", width=6)
        t.add_column("Entropy", justify="right", width=8)
        t.add_column("Size", justify="right", width=10)
        t.add_column("File")
        for f in files[:50]:  # cap display at 50
            score = f.get("suspicious_score", 0)
            score_color = "red" if score >= 3 else "yellow" if score > 0 else "dim"
            t.add_row(
                Text(f"{score:.1f}", style=score_color),
                f"{f.get('entropy', 0):.3f}",
                _fmt_size(f.get("size_bytes")),
                str(Path(f.get("path", "")).name),
            )
        if len(files) > 50:
            t.add_row("…", "…", "…", f"[dim]({len(files) - 50} more)[/]")
        console.print(t)


def _cmd_conclusions(args: argparse.Namespace, svc: AutoForensicsService) -> None:
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        transient=True,
        console=console,
    ) as prog:
        prog.add_task(f"Generating conclusions for [cyan]{args.case_id}[/]…")
        result = svc.generate_conclusions(args.case_id)

    if args.json:
        console.print_json(json.dumps(result))
        return

    verdict = result.get("risk_verdict", "LOW")
    verdict_color = {"HIGH": "bold red", "MEDIUM": "yellow", "LOW": "green"}.get(verdict, "white")
    header = (
        f"[bold cyan]{args.case_id}[/]   "
        f"Risk: [{verdict_color}]{verdict}[/{verdict_color}]   "
        f"Findings: [bold]{result.get('total_findings', 0)}[/]   "
        f"IOCs: [bold]{result.get('total_iocs', 0)}[/]   "
        f"Timeline: [bold]{result.get('total_timeline_events', 0)}[/]"
    )
    console.print(Panel(header, title="[bold]Case Conclusions[/]", border_style="cyan", expand=False))

    conclusions = result.get("conclusions", [])
    for i, c in enumerate(conclusions, 1):
        icon = "⚠" if "⚠" in c else "→"
        console.print(f"  [bold]{i}.[/] {c}")

    details = result.get("details", {})
    tactics = details.get("mitre_tactics", {})
    if tactics:
        console.print(Rule("[dim]MITRE ATT&CK Coverage[/]", style="dim"))
        tt = Table(box=box.SIMPLE_HEAD, header_style="bold", border_style="dim")
        tt.add_column("Tactic")
        tt.add_column("Findings", justify="right")
        for tactic, count in sorted(tactics.items(), key=lambda x: -x[1]):
            tt.add_row(tactic, str(count))
        console.print(tt)

    techniques = details.get("mitre_techniques", [])
    if techniques:
        console.print(f"  [dim]Techniques:[/] {', '.join(techniques)}")


def _cmd_timeline_filter(args: argparse.Namespace, svc: AutoForensicsService) -> None:
    result = svc.filter_timeline(
        args.case_id,
        after=args.after,
        before=args.before,
        min_risk=args.min_risk,
        event_type=args.event_type,
        keyword=args.keyword,
        limit=args.limit,
    )

    if args.json:
        console.print_json(json.dumps(result))
        return

    filters = result.get("filters", {})
    active_filters = [f"{k}={v}" for k, v in filters.items() if v is not None]
    filter_str = ", ".join(active_filters) if active_filters else "none"
    console.print(Panel(
        f"[bold cyan]{args.case_id}[/]   "
        f"Matched: [bold]{result.get('matched_events', 0)}[/] / {result.get('total_events', 0)}   "
        f"Filters: [dim]{filter_str}[/]",
        title="[bold]Timeline Filter[/]", border_style="cyan", expand=False,
    ))

    events = result.get("events", [])
    if events:
        tl = Table(box=box.SIMPLE_HEAD, header_style="bold", border_style="dim")
        tl.add_column("Timestamp", style="dim", no_wrap=True, width=20)
        tl.add_column("Event")
        tl.add_column("Risk", justify="right", width=6)
        tl.add_column("Source", style="dim", max_width=32)
        for ev in events:
            risk_val = ev.get("risk_score")
            if risk_val is not None:
                risk_color = "red" if risk_val >= 70 else "yellow" if risk_val >= 40 else "green"
                risk_text = Text(str(int(risk_val)), style=risk_color)
            else:
                risk_text = Text("—", style="dim")
            tl.add_row(
                _fmt_ts(ev.get("timestamp")),
                str(ev.get("description") or ev.get("event_type") or ""),
                risk_text,
                str(ev.get("source_file") or "—"),
            )
        console.print(tl)
    else:
        console.print("[dim]No events matched the specified filters.[/]")


def _cmd_iocs(args: argparse.Namespace, svc: AutoForensicsService) -> None:
    overview = svc.case_overview(args.case_id)
    iocs = overview.get("iocs", [])

    # Filter by type if specified
    if args.type:
        type_lower = args.type.strip().lower()
        iocs = [ioc for ioc in iocs if str(ioc.get("ioc_type") or ioc.get("type") or "").lower() == type_lower]

    # Export mode
    if args.export:
        if args.export == "json":
            output = json.dumps(iocs, indent=2)
        else:  # csv
            buf = io.StringIO()
            writer = csv_mod.writer(buf)
            writer.writerow(["ioc_type", "value", "first_seen", "last_seen", "source_event"])
            for ioc in iocs:
                writer.writerow([
                    ioc.get("ioc_type") or ioc.get("type") or "",
                    ioc.get("value") or "",
                    ioc.get("first_seen") or "",
                    ioc.get("last_seen") or "",
                    ioc.get("source_event") or "",
                ])
            output = buf.getvalue()
        sys.stdout.write(output)
        return

    if args.json:
        console.print_json(json.dumps(iocs))
        return

    # Type summary
    ioc_types: dict[str, int] = {}
    for ioc in iocs:
        it = str(ioc.get("ioc_type") or ioc.get("type") or "unknown")
        ioc_types[it] = ioc_types.get(it, 0) + 1
    type_parts = [f"{t}: [bold]{c}[/]" for t, c in sorted(ioc_types.items(), key=lambda x: -x[1])]
    console.print(Panel(
        f"[bold cyan]{args.case_id}[/]   Total IOCs: [bold]{len(iocs)}[/]   "
        + "   ".join(type_parts),
        title="[bold]Indicators of Compromise[/]", border_style="cyan", expand=False,
    ))

    if iocs:
        it = Table(box=box.SIMPLE_HEAD, header_style="bold", border_style="dim")
        it.add_column("Type", width=12)
        it.add_column("Value")
        it.add_column("First Seen", style="dim", width=20)
        it.add_column("Source", style="dim", max_width=32)
        for ioc in iocs:
            it.add_row(
                str(ioc.get("ioc_type") or ioc.get("type") or ""),
                str(ioc.get("value") or ""),
                _fmt_ts(ioc.get("first_seen")),
                str(ioc.get("source_event") or "—"),
            )
        console.print(it)
    else:
        console.print("[dim]No IOCs found matching the criteria.[/]")


def _cmd_audit(args: argparse.Namespace, svc: AutoForensicsService) -> None:
    if hasattr(args, "case_id") and args.case_id:
        validate_case_id(args.case_id)
        logs = svc.db.get_audit_log(case_id=args.case_id, limit=args.limit)
    else:
        logs = svc.db.get_audit_log(limit=args.limit)

    if args.json:
        console.print_json(json.dumps(logs))
        return

    if not logs:
        console.print("[dim]No audit log entries found.[/]")
        return

    t = Table(
        box=box.ROUNDED, show_header=True, header_style="bold cyan",
        border_style="dim", caption=f"[dim]{len(logs)} entry/entries[/]",
    )
    t.add_column("Timestamp", style="dim", width=20)
    t.add_column("Action", style="bold")
    t.add_column("Case", width=20)
    t.add_column("Actor", style="dim", width=12)
    t.add_column("Details", style="dim", max_width=50)
    for entry in logs:
        details_raw = entry.get("details_json") or entry.get("details") or ""
        if isinstance(details_raw, dict):
            details_str = json.dumps(details_raw)[:60]
        else:
            details_str = str(details_raw)[:60]
        t.add_row(
            _fmt_ts(entry.get("created_at")),
            str(entry.get("action") or ""),
            str(entry.get("case_id") or "—"),
            str(entry.get("actor") or "—"),
            details_str,
        )
    console.print(t)


def _cmd_hash(args: argparse.Namespace) -> None:
    path = args.path.expanduser().resolve()
    if not path.is_file():
        err_console.print(f"[bold red]Not a file:[/] {path}")
        raise SystemExit(1)

    algos = args.algo
    if algos == "all":
        algos_list = ["sha256", "md5", "sha1"]
    else:
        algos_list = [algos]

    hashers = {}
    for algo in algos_list:
        hashers[algo] = hashlib.new(algo)

    with path.open("rb") as f:
        while chunk := f.read(1024 * 1024):
            for h in hashers.values():
                h.update(chunk)

    if args.json:
        result = {algo: h.hexdigest() for algo, h in hashers.items()}
        result["file"] = str(path)
        result["size_bytes"] = path.stat().st_size
        console.print_json(json.dumps(result))
        return

    lines = [f"File: [bold]{path.name}[/]  [dim]({_fmt_size(path.stat().st_size)})[/]"]
    for algo, h in hashers.items():
        lines.append(f"{algo.upper()}: [dim]{h.hexdigest()}[/]")
    console.print(Panel("\n".join(lines), title="[bold]File Hash[/]", border_style="cyan", expand=False))


def _cmd_config(config: AppConfig) -> None:
    lines = [
        f"[bold cyan]Auto Forensics Configuration[/]",
        "",
        f"  Data dir         :  [bold]{config.data_dir}[/]",
        f"  Cases dir        :  [bold]{config.cases_dir}[/]",
        f"  Database path    :  [bold]{config.db_path}[/]",
        f"  Database URL     :  [dim]{config.database_url or '(SQLite default)'}[/]",
        f"  Rules dir        :  [dim]{config.rules_dir or '—'}[/]",
        f"  Sigma rules dir  :  [dim]{config.sigma_rules_dir or '—'}[/]",
        f"  Plugin dirs      :  [dim]{', '.join(str(p) for p in config.plugin_dirs) or '—'}[/]",
        "",
        f"  Server bind      :  [bold]{config.host}:{config.port}[/]",
        f"  Environment      :  [bold]{'production' if config.production else 'development'}[/]",
        f"  API key set      :  {'[green]yes[/]' if config.api_key_hash else '[dim]no[/]'}",
        f"  Rate limit       :  [bold]{config.rate_limit_per_minute}[/] req/min",
        "",
        f"  LLM endpoint     :  [dim]{config.llama_endpoint}[/]",
        f"  LLM model        :  [dim]{config.llama_model}[/]",
        f"  OpenAI endpoint  :  [dim]{config.openai_compatible_endpoint or '—'}[/]",
        "",
        f"  VirusTotal key   :  {'[green]set[/]' if config.virustotal_api_key else '[dim]no[/]'}",
        f"  MalwareBazaar    :  {'[green]set[/]' if config.malwarebazaar_api_key else '[dim]no[/]'}",
        f"  AbuseIPDB        :  {'[green]set[/]' if config.abuseipdb_api_key else '[dim]no[/]'}",
        f"  WHOIS lookups    :  {'[green]enabled[/]' if config.enable_whois_lookup else '[dim]disabled[/]'}",
        f"  Enrichment TTL   :  [dim]{config.enrichment_cache_ttl_minutes} min[/]",
        f"  Job retention    :  [dim]{config.job_retention_days} day(s)[/]",
    ]
    console.print(Panel("\n".join(lines), title="[bold]Configuration[/]", border_style="cyan", expand=False))


def _cmd_version() -> None:
    try:
        from importlib.metadata import version as pkg_version
        ver = pkg_version("auto-forensics-framework")
    except Exception:
        ver = "0.1.0-dev"
    lines = [
        f"[bold cyan]Auto Forensics Framework[/]  [dim]v{ver}[/]",
        f"  Python  :  [dim]{sys.version.split()[0]}[/]",
        f"  Platform:  [dim]{sys.platform}[/]",
    ]
    # Check optional dependencies
    optionals = {
        "pefile": "PE analysis",
        "yara": "YARA scanning",
        "pyyaml": "Sigma rules",
        "reportlab": "PDF reports",
        "fastapi": "API server",
        "sqlalchemy": "SQLAlchemy DB",
        "dpkt": "PCAP parsing",
    }
    available: list[str] = []
    missing: list[str] = []
    for mod, label in optionals.items():
        try:
            __import__(mod)
            available.append(label)
        except ImportError:
            missing.append(label)
    if available:
        lines.append(f"  Modules :  [green]{', '.join(available)}[/]")
    if missing:
        lines.append(f"  Missing :  [dim]{', '.join(missing)}[/]")
    console.print(Panel("\n".join(lines), title="[bold]Version[/]", border_style="cyan", expand=False))


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="auto-forensics",
        description="Automated malware-oriented binary analysis and incident timeline generation.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # init
    p = sub.add_parser("init", help="Create or return a case workspace.")
    p.add_argument("--case-id", required=True, help="Unique case identifier.")

    # list
    p = sub.add_parser("list", help="List known cases.")
    p.add_argument("--json", action="store_true", help="Emit JSON output.")

    # stats
    sub.add_parser("stats", help="Show global case statistics.")

    # ingest
    p = sub.add_parser("ingest", help="Ingest evidence directory into a case.")
    p.add_argument("--case-id", required=True, help="Case identifier.")
    p.add_argument("--source-dir", required=True, type=Path, help="Evidence source directory.")

    # analyze
    p = sub.add_parser("analyze", help="Run analysis for an initialized case.")
    p.add_argument("--case-id", required=True, help="Case identifier.")
    p.add_argument("--disable-llama", action="store_true", help="Disable LLM triage.")

    # enrich
    p = sub.add_parser("enrich", help="Run or inspect asynchronous IOC enrichment.")
    p.add_argument("--case-id", required=True, help="Case identifier.")
    p.add_argument("--status", action="store_true", help="Show enrichment job status only.")

    # overview
    p = sub.add_parser("overview", help="Show complete case overview from the database.")
    p.add_argument("--case-id", required=True, help="Case identifier.")
    p.add_argument("--json", action="store_true", help="Emit JSON output.")

    # report
    p = sub.add_parser("report", help="Print generated case report.")
    p.add_argument("--case-id", required=True, help="Case identifier.")
    p.add_argument("--format", choices=["json", "md", "html", "navigator", "stix"], default="json")

    # jobs
    p = sub.add_parser("jobs", help="List case analysis/enrichment jobs.")
    p.add_argument("--case-id", required=True, help="Case identifier.")
    p.add_argument("--type", choices=["analysis", "enrichment"], default=None)
    p.add_argument("--limit", type=int, default=100)
    p.add_argument("--json", action="store_true", help="Emit JSON output.")

    # search
    p = sub.add_parser("search", help="Search findings, IOCs, and timeline.")
    p.add_argument("--case-id", required=True, help="Case identifier.")
    p.add_argument("--query", "-q", required=True, help="Search query string.")
    p.add_argument("--limit", type=int, default=100)
    p.add_argument("--json", action="store_true", help="Emit JSON output.")

    # notes
    p = sub.add_parser("notes", help="List analyst notes for a case.")
    p.add_argument("--case-id", required=True, help="Case identifier.")
    p.add_argument("--json", action="store_true", help="Emit JSON output.")

    # add-note
    p = sub.add_parser("add-note", help="Add an analyst note to a case.")
    p.add_argument("--case-id", required=True, help="Case identifier.")
    p.add_argument("--text", required=True, help="Note text content.")
    p.add_argument("--author", default="analyst", help="Note author (default: analyst).")

    # serve
    p = sub.add_parser("serve", help="Start the API server.")
    p.add_argument("--host", default=None, help="Bind host.")
    p.add_argument("--port", default=None, type=int, help="Bind port.")

    # run
    p = sub.add_parser("run", help="Run a full forensic analysis pipeline.")
    p.add_argument("--case-id", required=True)
    p.add_argument("--input-dir", required=True, type=Path)
    p.add_argument("--output-dir", required=True, type=Path)
    p.add_argument("--llama-endpoint", default="http://localhost:11434")
    p.add_argument("--llama-model", default="llama3.1:8b")
    p.add_argument("--disable-llama", action="store_true")

    # export
    p = sub.add_parser("export", help="Export case as signed zip archive.")
    p.add_argument("--case-id", required=True)
    p.add_argument("--dest", required=True, type=Path)

    # import
    p = sub.add_parser("import", help="Import case from signed zip archive.")
    p.add_argument("--archive", required=True, type=Path)
    p.add_argument("--case-id", default=None, help="Optional case ID override.")

    # migrate
    p = sub.add_parser("migrate", help="Run or inspect database migrations.")
    p.add_argument("--status", action="store_true", help="Show status without applying.")

    # delete
    p = sub.add_parser("delete", help="Permanently delete a case and all its data.")
    p.add_argument("--case-id", required=True, help="Case identifier.")
    p.add_argument("--force", action="store_true", help="Skip confirmation prompt.")

    # cleanup-jobs
    p = sub.add_parser("cleanup-jobs", help="Delete job history older than retention days.")
    p.add_argument("--retention-days", type=int, default=None)
    p.add_argument("--force", action="store_true", help="Skip confirmation prompt.")

    # scan
    p = sub.add_parser("scan", help="Scan a single file for malicious indicators.")
    p.add_argument("--path", required=True, type=Path, help="File to scan.")
    p.add_argument("--json", action="store_true", help="Emit JSON output.")

    # scan-dir
    p = sub.add_parser("scan-dir", help="Scan all files in a directory.")
    p.add_argument("--path", required=True, type=Path, help="Directory to scan.")
    p.add_argument("--no-recursive", action="store_true", help="Disable recursive scan.")
    p.add_argument("--json", action="store_true", help="Emit JSON output.")

    # conclusions
    p = sub.add_parser("conclusions", help="Generate automated forensic conclusions for a case.")
    p.add_argument("--case-id", required=True, help="Case identifier.")
    p.add_argument("--json", action="store_true", help="Emit JSON output.")

    # timeline-filter
    p = sub.add_parser("timeline-filter", help="Filter timeline events by criteria.")
    p.add_argument("--case-id", required=True, help="Case identifier.")
    p.add_argument("--after", default=None, help="Show events after this ISO timestamp.")
    p.add_argument("--before", default=None, help="Show events before this ISO timestamp.")
    p.add_argument("--min-risk", type=float, default=None, help="Minimum risk score.")
    p.add_argument("--event-type", default=None, help="Filter by event type (substring match).")
    p.add_argument("--keyword", default=None, help="Filter by keyword in description/source.")
    p.add_argument("--limit", type=int, default=500, help="Max events to return.")
    p.add_argument("--json", action="store_true", help="Emit JSON output.")

    # iocs
    p = sub.add_parser("iocs", help="List and export IOCs for a case.")
    p.add_argument("--case-id", required=True, help="Case identifier.")
    p.add_argument("--type", default=None, help="Filter by IOC type.")
    p.add_argument("--export", choices=["csv", "json"], default=None, help="Export IOCs to stdout.")
    p.add_argument("--json", action="store_true", help="Emit JSON output.")

    # audit
    p = sub.add_parser("audit", help="View the audit trail.")
    p.add_argument("--case-id", default=None, help="Filter by case identifier.")
    p.add_argument("--limit", type=int, default=100, help="Max entries to show.")
    p.add_argument("--json", action="store_true", help="Emit JSON output.")

    # hash
    p = sub.add_parser("hash", help="Compute file hashes.")
    p.add_argument("--path", required=True, type=Path, help="File to hash.")
    p.add_argument("--algo", choices=["sha256", "md5", "sha1", "all"], default="sha256", help="Hash algorithm.")
    p.add_argument("--json", action="store_true", help="Emit JSON output.")

    # config
    sub.add_parser("config", help="Show current configuration and data paths.")

    # version
    sub.add_parser("version", help="Display version information.")

    # start (alias for serve)
    p = sub.add_parser("start", help="Start the API server (alias for serve).")
    p.add_argument("--host", default=None, help="Bind host.")
    p.add_argument("--port", default=None, type=int, help="Bind port.")

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    config = AppConfig.from_env()
    service: AutoForensicsService | None = None

    def ensure_service() -> AutoForensicsService:
        nonlocal service
        if service is None:
            service = AutoForensicsService(config)
        return service

    try:
        if args.command == "init":
            validate_case_id(args.case_id)
            _cmd_init(args, ensure_service())
            return

        if args.command == "list":
            _cmd_list(args, ensure_service())
            return

        if args.command == "stats":
            _cmd_stats(args, ensure_service())
            return

        if args.command == "ingest":
            validate_case_id(args.case_id)
            _cmd_ingest(args, ensure_service())
            return

        if args.command == "analyze":
            validate_case_id(args.case_id)
            _cmd_analyze(args, ensure_service())
            return

        if args.command == "enrich":
            validate_case_id(args.case_id)
            _cmd_enrich(args, ensure_service())
            return

        if args.command == "overview":
            validate_case_id(args.case_id)
            _cmd_overview(args, ensure_service())
            return

        if args.command == "report":
            validate_case_id(args.case_id)
            _cmd_report(args, ensure_service())
            return

        if args.command == "jobs":
            validate_case_id(args.case_id)
            _cmd_jobs(args, ensure_service())
            return

        if args.command == "search":
            validate_case_id(args.case_id)
            _cmd_search(args, ensure_service())
            return

        if args.command == "notes":
            validate_case_id(args.case_id)
            _cmd_notes(args, ensure_service())
            return

        if args.command == "add-note":
            validate_case_id(args.case_id)
            _cmd_add_note(args, ensure_service())
            return

        if args.command == "serve":
            _cmd_serve(args, config)
            return

        if args.command == "run":
            _cmd_run(args, config)
            return

        if args.command == "export":
            validate_case_id(args.case_id)
            _cmd_export(args, ensure_service())
            return

        if args.command == "delete":
            validate_case_id(args.case_id)
            _cmd_delete(args, ensure_service())
            return

        if args.command == "import":
            _cmd_import(args, ensure_service())
            return

        if args.command == "migrate":
            _cmd_migrate(args, ensure_service())
            return

        if args.command == "cleanup-jobs":
            _cmd_cleanup_jobs(args, ensure_service())
            return

        if args.command == "scan":
            _cmd_scan(args, ensure_service())
            return

        if args.command == "scan-dir":
            _cmd_scan_dir(args, ensure_service())
            return

        if args.command == "conclusions":
            validate_case_id(args.case_id)
            _cmd_conclusions(args, ensure_service())
            return

        if args.command == "timeline-filter":
            validate_case_id(args.case_id)
            _cmd_timeline_filter(args, ensure_service())
            return

        if args.command == "iocs":
            validate_case_id(args.case_id)
            _cmd_iocs(args, ensure_service())
            return

        if args.command == "audit":
            _cmd_audit(args, ensure_service())
            return

        if args.command == "hash":
            _cmd_hash(args)
            return

        if args.command == "config":
            _cmd_config(config)
            return

        if args.command == "version":
            _cmd_version()
            return

        if args.command == "start":
            _cmd_serve(args, config)
            return

    except SecurityError as exc:
        err_console.print(f"[bold red]Security error:[/] {exc}")
        raise SystemExit(1) from exc
    except Exception as exc:
        err_console.print(f"[bold red]Error:[/] {exc}")
        raise SystemExit(1) from exc

    raise SystemExit(f"Unknown command: {args.command}")


if __name__ == "__main__":
    main()
