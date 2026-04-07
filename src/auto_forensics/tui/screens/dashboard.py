"""Dashboard screen with overview cards and animated stats."""

from __future__ import annotations

from textual.screen import Screen
from textual.widgets import Static, Button
from textual.containers import Grid, Vertical, Horizontal
from textual.reactive import reactive

from ..widgets import CaseCard, ProgressCard, StatsPanel


class DashboardScreen(Screen):
    """Main dashboard with global stats and recent activity."""

    DEFAULT_CSS = """
    DashboardScreen {
        layout: vertical;
        padding: 1;
    }
    DashboardScreen .screen-title {
        text-align: center;
        text-style: bold;
        color: #cba6f7;
        height: 3;
    }
    DashboardScreen .section-title {
        text-style: bold;
        color: #f5c2e7;
        margin-top: 1;
        margin-bottom: 1;
    }
    #actions-grid {
        grid-size: 4;
        grid-gutter: 1;
        margin-top: 2;
        height: auto;
    }
    #recent-cases-container {
        height: auto;
        max-height: 20;
    }
    """

    BINDINGS = [
        ("a", "analyze", "New Analysis"),
        ("s", "settings", "Settings"),
        ("r", "refresh", "Refresh"),
    ]

    stats: reactive[dict] = reactive({})
    recent_cases: reactive[list] = reactive([])
    active_jobs: reactive[list] = reactive([])

    def __init__(self, service=None, **kwargs) -> None:
        super().__init__(**kwargs)
        self.service = service
        self.auto_refresh_interval = 5.0

    def compose(self):
        yield Static("Dashboard", classes="screen-title")
        
        with Vertical():
            yield Static("Global Statistics", classes="section-title")
            yield StatsPanel(id="stats-panel")

            yield Static("Recent Cases", classes="section-title")
            with Vertical(id="recent-cases-container"):
                pass  # Populated dynamically

            yield Static("Active Jobs", classes="section-title")
            with Vertical(id="active-jobs-container"):
                pass  # Populated dynamically

            with Grid(id="actions-grid"):
                yield Button("List Cases [c]", id="btn-cases", variant="primary")
                yield Button("New Analysis [a]", id="btn-analyze", variant="success")
                yield Button("Refresh [r]", id="btn-refresh", variant="default")
                yield Button("Settings [s]", id="btn-settings", variant="default")

    def on_mount(self) -> None:
        """Start auto-refresh on mount."""
        self.set_interval(self.auto_refresh_interval, self.refresh_data)
        self.refresh_data()

    def refresh_data(self) -> None:
        """Refresh dashboard data from service."""
        if self.service:
            self.run_worker(self._fetch_stats(), exclusive=True)
            self.run_worker(self._fetch_cases(), exclusive=True)
            self.run_worker(self._fetch_jobs(), exclusive=True)

    async def _fetch_stats(self) -> None:
        """Fetch global statistics."""
        if self.service:
            try:
                self.stats = self.service.case_stats()
                stats_panel = self.query_one("#stats-panel", StatsPanel)
                stats_panel.update_stats(self.stats)
            except Exception as e:
                self.notify(f"Failed to fetch stats: {e}", severity="error")

    async def _fetch_cases(self) -> None:
        """Fetch recent cases."""
        if self.service:
            try:
                cases = self.service.list_cases(limit=6)
                self.recent_cases = cases
                self._update_cases_display()
            except Exception as e:
                self.notify(f"Failed to fetch cases: {e}", severity="error")

    async def _fetch_jobs(self) -> None:
        """Fetch active jobs."""
        if not self.service:
            return

        new_jobs: list[dict] = []
        try:
            cases = self.service.list_cases(limit=20)
            for case in cases:
                case_id = case.get("case_id")
                if not case_id:
                    continue
                status = self.service.get_case_status(case_id)
                if status.get("state") in {"analyzing", "queued"}:
                    new_jobs.append({
                        "case_id": case_id,
                        "job_id": status.get("job_id"),
                        "state": status.get("state"),
                        "progress": status.get("progress", 0),
                        "message": status.get("message", ""),
                        "type": "analysis",
                    })
                enrich = self.service.get_case_enrichment_status(case_id)
                if enrich.get("state") in {"running", "queued"}:
                    new_jobs.append({
                        "case_id": case_id,
                        "job_id": enrich.get("job_id"),
                        "state": enrich.get("state"),
                        "progress": enrich.get("progress", 0),
                        "message": enrich.get("message", ""),
                        "type": "enrichment",
                    })

            self.active_jobs = new_jobs
            self._update_jobs_display()
        except Exception as e:
            self.notify(f"Failed to fetch jobs: {e}", severity="error")

    def _update_cases_display(self) -> None:
        """Update the recent cases display."""
        container = self.query_one("#recent-cases-container", Vertical)
        container.remove_children()
        
        if not self.recent_cases:
            container.mount(Static("[dim]No cases yet. Create a case to get started.[/]"))
            return

        for case in self.recent_cases:
            card = CaseCard(
                case_id=case.get("case_id", ""),
                status=case.get("status", ""),
                artifact_count=case.get("artifact_count", 0),
                finding_count=case.get("finding_count", 0),
                ioc_count=case.get("ioc_count", 0),
            )
            container.mount(card)

    def _update_jobs_display(self) -> None:
        """Update the jobs container with ProgressCards."""
        container = self.query_one("#active-jobs-container", Vertical)
        container.remove_children()
        
        if not self.active_jobs:
            container.mount(Static("[dim]No active jobs. Start an analysis from a case.[/]"))
            return

        for job in self.active_jobs:
            card = ProgressCard(
                job_id=job.get("job_id", ""),
                case_id=job.get("case_id", ""),
                job_type=job.get("type", ""),
            )
            card.progress = job.get("progress", 0)
            card.state = job.get("state", "")
            card.message = job.get("message", "")
            container.mount(card)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "btn-cases":
            self.action_cases()
        elif event.button.id == "btn-analyze":
            self.action_analyze()
        elif event.button.id == "btn-refresh":
            self.action_refresh()
        elif event.button.id == "btn-settings":
            self.action_settings()

    def action_cases(self) -> None:
        """Navigate to cases screen."""
        self.app.switch_screen("cases")

    def action_analyze(self) -> None:
        """Open analysis screen."""
        self.app.switch_screen("analysis")

    def action_settings(self) -> None:
        """Open settings screen."""
        self.app.push_screen("settings")

    def action_refresh(self) -> None:
        """Refresh data."""
        self.refresh_data()
        self.notify("Dashboard refreshed", severity="information")
