"""Case detail screen with evidence tree, findings, timeline, and IOCs."""

from __future__ import annotations

from textual.app import ComposeResult
from textual import widgets
from textual.screen import Screen, ModalScreen
from textual.widgets import (
    DataTable,
    Tree,
    Static,
    TabbedContent,
    TabPane,
    Button,
    TextArea,
)
from textual.containers import Vertical, Horizontal, Grid
from textual.reactive import reactive
from textual.message import Message


class ReportModal(ModalScreen[str]):
    """A modal dialog for displaying a report."""

    DEFAULT_CSS = """
    ReportModal {
        align: center middle;
    }
    ReportModal > Grid {
        grid-size: 1;
        grid-gutter: 1;
        padding: 1;
        width: 90;
        height: 80;
        background: #313244;
        border: solid #45475a;
    }
    ReportModal > Grid > Static {
        content-align: center middle;
        text-style: bold;
        color: #cba6f7;
        height: 1;
    }
    ReportModal TextArea {
        height: 1fr;
        border: solid #45475a;
    }
    """

    def __init__(self, title: str, content: str, **kwargs) -> None:
        super().__init__(**kwargs)
        self.title_text = title
        self.content = content

    def compose(self):
        with Grid():
            yield Static(self.title_text)
            yield TextArea(self.content, id="report-content", read_only=True)
            yield Button("Close", variant="primary", id="close")


from ..widgets.file_browser import FileBrowserDialog


class CaseDetailScreen(Screen):
    """Screen showing detailed case information."""

    DEFAULT_CSS = """
    CaseDetailScreen {
        layout: vertical;
        padding: 1;
    }
    CaseDetailScreen .screen-title {
        text-align: center;
        text-style: bold;
        color: #cba6f7;
        height: 3;
    }
    CaseDetailScreen #case-header {
        height: auto;
        background: #181825;
        border-bottom: solid #313244;
        padding: 1;
    }
    CaseDetailScreen #case-id-display {
        text-style: bold;
        color: #89b4fa;
    }
    CaseDetailScreen #status-display {
        color: #94e2d5;
    }
    CaseDetailScreen #risk-display {
        color: #fab387;
    }
    CaseDetailScreen TabbedContent {
        height: 1fr;
    }
    CaseDetailScreen DataTable {
        height: 1fr;
        border: solid #45475a;
    }
    """

    BINDINGS = [
        ("i", "ingest", "Ingest Evidence"),
        ("a", "analyze", "Analyze"),
        ("e", "enrich", "Enrich IOCs"),
        ("r", "report", "Report"),
        ("escape", "back", "Back"),
    ]

    case_id: reactive[str | None] = reactive(None)
    case_data: reactive[dict] = reactive({})

    def __init__(self, case_id: str | None = None, service=None, **kwargs) -> None:
        super().__init__(**kwargs)
        self.case_id = case_id
        self.service = service

    def compose(self):
        yield Static("Case Detail", classes="screen-title")
        
        with Vertical():
            with Horizontal(id="case-header"):
                yield Static(f"Case: {self.case_id or '—'}", id="case-id-display")
                yield Static("Status: —", id="status-display")
                yield Static("Risk: —", id="risk-display")
            
            with Horizontal(id="actions"):
                yield Button("Ingest [i]", id="ingest", variant="primary")
                yield Button("Analyze [a]", id="analyze", variant="success")
                yield Button("Enrich [e]", id="enrich", variant="default")
                yield Button("Report [r]", id="report", variant="default")
                yield Button("Back [esc]", id="back", variant="default")

            with TabbedContent():
                with TabPane("Evidence", id="tab-evidence"):
                    yield Tree("Evidence", id="evidence-tree")
                with TabPane("Findings", id="tab-findings"):
                    yield DataTable(id="findings-table")
                with TabPane("Timeline", id="tab-timeline"):
                    yield DataTable(id="timeline-table")
                with TabPane("IOCs", id="tab-iocs"):
                    yield DataTable(id="iocs-table")
                with TabPane("Notes", id="tab-notes"):
                    yield DataTable(id="notes-table")

    def on_mount(self) -> None:
        """Initialize tables."""
        findings = self.query_one("#findings-table", DataTable)
        findings.add_column("Severity", width=10)
        findings.add_column("Title", width=40)
        findings.add_column("Tactic", width=20)
        findings.add_column("Technique", width=15)

        timeline = self.query_one("#timeline-table", DataTable)
        timeline.add_column("Timestamp", width=20)
        timeline.add_column("Event", width=50)
        timeline.add_column("Risk", width=8)

        iocs = self.query_one("#iocs-table", DataTable)
        iocs.add_column("Type", width=12)
        iocs.add_column("Value", width=40)
        iocs.add_column("First Seen", width=20)

        notes = self.query_one("#notes-table", DataTable)
        notes.add_column("Author", width=15)
        notes.add_column("Timestamp", width=20)
        notes.add_column("Content")

        if self.case_id:
            self.refresh_data()

    def refresh_data(self) -> None:
        """Load case data."""
        if self.service and self.case_id:
            self.run_worker(self._load_case_data(), exclusive=True)

    async def _load_case_data(self) -> None:
        """Async worker to load case overview."""
        if self.service and self.case_id:
            try:
                self.case_data = self.service.case_overview(self.case_id)
                self._update_display()
            except Exception as e:
                self.notify(f"Failed to load case: {e}", severity="error")

    def _update_display(self) -> None:
        """Update all UI elements with case data."""
        case = self.case_data.get("case", {})
        summary = self.case_data.get("summary", {})

        # Update header
        self.query_one("#case-id-display", Static).update(f"Case: {case.get('case_id', self.case_id)}")
        self.query_one("#status-display", Static).update(f"Status: {case.get('status', '—')}")
        risk = summary.get("risk_score") or summary.get("total_risk_score")
        self.query_one("#risk-display", Static).update(f"Risk: {risk if risk is not None else '—'}")

        # Update evidence tree
        tree = self.query_one("#evidence-tree", Tree)
        tree.clear()
        tree.root.expand()
        artifacts = self.case_data.get("artifacts", [])
        for art in artifacts[:50]:  # Limit for performance
            tree.root.add_leaf(art.get("rel_path", "unknown"))

        # Update findings table
        findings_table = self.query_one("#findings-table", DataTable)
        findings_table.clear()
        for f in self.case_data.get("findings", [])[:100]:
            severity = f.get("severity", "").lower()
            severity_style = {
                "critical": "bold #f38ba8",
                "high": "bold #fab387",
                "medium": "#f9e2af",
                "low": "#a6e3a1",
            }.get(severity, "#cdd6f4")
            
            findings_table.add_row(
                f.get("severity", "").upper(),
                f.get("title", f.get("rule_name", "")),
                f.get("tactic", "—"),
                f.get("technique", "—"),
            )

        # Update timeline table
        timeline_table = self.query_one("#timeline-table", DataTable)
        timeline_table.clear()
        for ev in self.case_data.get("timeline", [])[:100]:
            timeline_table.add_row(
                str(ev.get("timestamp", "")).split(".")[0],
                ev.get("description", ev.get("event_type", "")),
                str(ev.get("risk_score", "—")),
            )

        # Update IOCs table
        iocs_table = self.query_one("#iocs-table", DataTable)
        iocs_table.clear()
        for ioc in self.case_data.get("iocs", [])[:100]:
            iocs_table.add_row(
                ioc.get("ioc_type", ioc.get("type", "")),
                ioc.get("value", ""),
                str(ioc.get("first_seen", "—")),
            )

        # Update notes table
        notes_table = self.query_one("#notes-table", DataTable)
        notes_table.clear()
        for note in self.case_data.get("notes", [])[:50]:
            notes_table.add_row(
                note.get("author", "—"),
                str(note.get("created_at", "—")).split(".")[0],
                note.get("content", "")[:80],
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "back":
            self.action_back()
        elif event.button.id == "ingest":
            self.action_ingest()
        elif event.button.id == "analyze":
            self.action_analyze()
        elif event.button.id == "enrich":
            self.action_enrich()
        elif event.button.id == "report":
            self.action_report()

    def action_back(self) -> None:
        """Go back to cases list."""
        self.app.switch_screen("cases")

    def action_ingest(self) -> None:
        """Open file browser to select evidence directory for ingest."""
        def on_result(path) -> None:
            if path:
                self.run_worker(self._ingest_path(path), exclusive=True)

        self.app.push_screen(
            FileBrowserDialog(title="Select Evidence Directory"),
            on_result,
        )

    async def _ingest_path(self, path) -> None:
        """Async worker to ingest evidence."""
        if self.service and self.case_id:
            try:
                self.notify(f"Ingesting from {path}...", severity="information")
                self.service.ingest_case(self.case_id, path)
                self.notify(f"Evidence ingested from {path}", severity="information")
                self.refresh_data()
            except Exception as e:
                self.notify(f"Failed to ingest: {e}", severity="error")

    def action_analyze(self) -> None:
        """Start analysis and go to progress screen."""
        if self.service and self.case_id:
            try:
                self.service.analyze_case_async(self.case_id)
                self.notify(f"Analysis started for {self.case_id}", severity="information")
                self.app.switch_screen("analysis")
            except Exception as e:
                self.notify(f"Failed to start analysis: {e}", severity="error")

    def action_enrich(self) -> None:
        """Start IOC enrichment."""
        if self.service and self.case_id:
            try:
                self.service.enrich_case_iocs_async(self.case_id)
                self.notify(f"IOC enrichment started for {self.case_id}", severity="information")
            except Exception as e:
                self.notify(f"Failed to start enrichment: {e}", severity="error")

    def action_report(self) -> None:
        """Generate and display a report."""
        if self.service and self.case_id:
            try:
                report_content = self.service.get_report(self.case_id, fmt="md")
                self.app.push_screen(ReportModal(f"Report: {self.case_id}", report_content))
            except Exception as e:
                self.notify(f"Failed to generate report: {e}", severity="error")
