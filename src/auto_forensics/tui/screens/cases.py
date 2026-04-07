"""Cases list screen with filters and status badges."""

from __future__ import annotations

from textual.screen import Screen
from textual.widgets import DataTable, Static, Button
from textual.containers import Vertical, Horizontal
from textual.reactive import reactive

from ..widgets import FilterBar, ConfirmationModal, CaseCreatorDialog
from ..widgets.file_browser import FileBrowserDialog


class CasesScreen(Screen):
    """Screen for listing and filtering cases."""

    DEFAULT_CSS = """
    CasesScreen {
        layout: vertical;
        padding: 1;
    }
    CasesScreen .screen-title {
        text-align: center;
        text-style: bold;
        color: #cba6f7;
        height: 3;
    }
    CasesScreen DataTable {
        height: 1fr;
        border: solid #45475a;
    }
    CasesScreen DataTable:focus {
        border: solid #cba6f7;
    }
    CasesScreen #actions {
        height: auto;
        margin-top: 1;
    }
    """

    BINDINGS = [
        ("n", "new_case", "New Case"),
        ("e", "export_case", "Export Case"),
        ("d", "delete_case", "Delete Case"),
        ("enter", "open_case", "Open Case"),
        ("r", "refresh", "Refresh"),
    ]

    cases: reactive[list] = reactive([])
    selected_case_id: reactive[str | None] = reactive(None)

    def __init__(self, service=None, **kwargs) -> None:
        super().__init__(**kwargs)
        self.service = service

    def compose(self):
        yield Static("Cases", classes="screen-title")
        
        with Vertical():
            yield FilterBar(
                placeholder="Search cases...",
                status_options=[
                    ("All", ""),
                    ("Created", "created"),
                    ("Ready", "ready"),
                    ("Ingesting", "ingesting"),
                    ("Analyzing", "analyzing"),
                    ("Complete", "complete"),
                    ("Failed", "failed"),
                ],
            )
            yield DataTable(id="cases-table", cursor_type="row")
            
            with Horizontal(id="actions"):
                yield Button("New Case [n]", id="new-case", variant="primary")
                yield Button("Open [enter]", id="open-case", variant="default")
                yield Button("Export [e]", id="export-case", variant="default")
                yield Button("Delete [d]", id="delete-case", variant="error")
                yield Button("Refresh [r]", id="refresh", variant="default")

    def on_mount(self) -> None:
        """Configure table columns."""
        table = self.query_one("#cases-table", DataTable)
        table.add_column("Case ID", width=30)
        table.add_column("Status", width=15)
        table.add_column("Created", width=20)
        table.add_column("Updated", width=20)
        table.add_column("Artifacts", width=10)
        table.add_column("Findings", width=10)
        self.refresh_data()

    def refresh_data(self) -> None:
        """Load cases from service."""
        if self.service:
            self.run_worker(self._load_cases(), exclusive=True)

    async def _load_cases(self) -> None:
        """Async worker to load cases."""
        if self.service:
            try:
                self.cases = self.service.list_cases(limit=100)
                self._update_table()
            except Exception as e:
                self.notify(f"Failed to load cases: {e}", severity="error")

    def _update_table(self) -> None:
        """Update the data table."""
        table = self.query_one("#cases-table", DataTable)
        table.clear()
        
        # Get filter values
        filter_bar = self.query_one(FilterBar)
        search, status_filter = filter_bar.get_filter_values()
        search = search.lower()
        
        for case in self.cases:
            case_id = case.get("case_id", "")
            status = case.get("status", "")
            
            # Apply filters
            if search and search not in case_id.lower():
                continue
            if status_filter and status != status_filter:
                continue
            
            table.add_row(
                case_id,
                status,
                self._fmt_ts(case.get("created_at")),
                self._fmt_ts(case.get("updated_at")),
                str(case.get("artifact_count", "—")),
                str(case.get("finding_count", "—")),
                key=case_id,
            )

    def _fmt_ts(self, ts: str | None) -> str:
        """Format timestamp."""
        if not ts:
            return "—"
        return str(ts).split("T")[0]

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle row selection."""
        self.selected_case_id = str(event.row_key) if event.row_key else None

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "new-case":
            self.action_new_case()
        elif event.button.id == "open-case":
            self.action_open_case()
        elif event.button.id == "export-case":
            self.action_export_case()
        elif event.button.id == "delete-case":
            self.action_delete_case()
        elif event.button.id == "refresh":
            self.action_refresh()

    def action_new_case(self) -> None:
        """Open dialog to create new case."""
        def on_result(case_id: str | None) -> None:
            if case_id and self.service:
                try:
                    self.service.create_case(case_id)
                    self.notify(f"Case {case_id} created", severity="success")
                    self.refresh_data()
                except Exception as e:
                    self.notify(f"Failed to create case: {e}", severity="error")

        self.app.push_screen(CaseCreatorDialog(), on_result)

    def action_delete_case(self) -> None:
        """Delete selected case with confirmation."""
        if not self.selected_case_id:
            self.notify("No case selected", severity="warning")
            return

        def confirm_delete(confirmed: bool) -> None:
            if confirmed and self.service:
                try:
                    self.service.delete_case(self.selected_case_id)
                    self.notify(f"Case {self.selected_case_id} deleted", severity="success")
                    self.selected_case_id = None
                    self.refresh_data()
                except Exception as e:
                    self.notify(f"Failed to delete case: {e}", severity="error")

        self.app.push_screen(
            ConfirmationModal(
                "Delete Case",
                f"Permanently delete case '{self.selected_case_id}'?\n\nThis cannot be undone.",
            ),
            confirm_delete,
        )

    def action_export_case(self) -> None:
        """Export selected case to archive."""
        if not self.selected_case_id:
            self.notify("No case selected", severity="warning")
            return

        def on_dest_selected(dest_path: str | None) -> None:
            if dest_path and self.service:
                try:
                    self.service.export_case(self.selected_case_id, dest_path)
                    self.notify(f"Case exported to {dest_path}", severity="success")
                except Exception as e:
                    self.notify(f"Failed to export case: {e}", severity="error")

        self.app.push_screen(FileBrowserDialog(title="Export Case To"), on_dest_selected)

    def action_open_case(self) -> None:
        """Open selected case detail."""
        if not self.selected_case_id:
            self.notify("No case selected", severity="warning")
            return
        self.app.push_screen("case_detail", self.selected_case_id)

    def action_refresh(self) -> None:
        """Refresh case list."""
        self.refresh_data()
