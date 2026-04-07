"""Analysis progress screen with real-time updates."""

from __future__ import annotations

from textual.screen import Screen
from textual.widgets import Static, ProgressBar, Button, Log
from textual.containers import Vertical, Horizontal
from textual.reactive import reactive

from ..widgets import ProgressCard


class AnalysisScreen(Screen):
    """Screen showing real-time analysis and enrichment progress."""

    DEFAULT_CSS = """
    AnalysisScreen {
        layout: vertical;
        padding: 1;
    }
    AnalysisScreen .screen-title {
        text-align: center;
        text-style: bold;
        color: #cba6f7;
        height: 3;
    }
    AnalysisScreen .section-title {
        text-style: bold;
        color: #f5c2e7;
        margin-top: 1;
        margin-bottom: 1;
    }
    AnalysisScreen #jobs-container {
        height: auto;
        max-height: 25;
        overflow-y: auto;
        border: solid #313244;
        padding: 1;
    }
    AnalysisScreen Log {
        height: 10;
        border: solid #45475a;
    }
    """

    BINDINGS = [
        ("c", "cancel", "Cancel Job"),
        ("r", "refresh", "Refresh"),
        ("escape", "back", "Back"),
    ]

    jobs: reactive[list[dict]] = reactive([])
    selected_job_id: reactive[str | None] = reactive(None)
    auto_refresh: reactive[bool] = reactive(True)

    def __init__(self, service=None, **kwargs) -> None:
        super().__init__(**kwargs)
        self.service = service

    def compose(self):
        yield Static("Analysis Progress", classes="screen-title")
        
        with Vertical():
            yield Static("Active Jobs", classes="section-title")
            with Vertical(id="jobs-container"):
                pass  # Populated with ProgressCards

            yield Static("Log", classes="section-title")
            yield Log(id="job-log", highlight=True)

            with Horizontal(id="actions"):
                yield Button("Cancel [c]", id="cancel", variant="error")
                yield Button("Refresh [r]", id="refresh", variant="default")
                yield Button("Back [esc]", id="back", variant="primary")

    def on_mount(self) -> None:
        """Start refresh loop."""
        self.set_interval(1.0, self.refresh_data)
        self.refresh_data()

    def refresh_data(self) -> None:
        """Poll for job status updates."""
        if self.service and self.auto_refresh:
            self.run_worker(self._fetch_jobs(), exclusive=True)

    async def _fetch_jobs(self) -> None:
        """Fetch job statuses."""
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
                if status.get("state") in {"analyzing", "queued", "running"}:
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

            self.jobs = new_jobs
            self._update_jobs_display()
            
            # Log updates
            log = self.query_one("#job-log", Log)
            for job in new_jobs:
                if job.get("message"):
                    log.write_line(f"[{job['case_id']}] {job['message']}")
                    
        except Exception as e:
            self.notify(f"Failed to fetch jobs: {e}", severity="error")

    def _update_jobs_display(self) -> None:
        """Update the jobs container with ProgressCards."""
        container = self.query_one("#jobs-container", Vertical)
        container.remove_children()
        
        if not self.jobs:
            container.mount(Static("[dim]No active jobs. Start an analysis from a case detail screen.[/]"))
            return

        for job in self.jobs:
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
        if event.button.id == "back":
            self.action_back()
        elif event.button.id == "cancel":
            self.action_cancel()
        elif event.button.id == "refresh":
            self.action_refresh()

    def action_back(self) -> None:
        """Go back to dashboard."""
        self.app.switch_screen("dashboard")

    def action_cancel(self) -> None:
        """Cancel a running job - shows info about stopping analysis."""
        if not self.jobs:
            self.notify("No active jobs to cancel", severity="warning")
            return
        
        # Get running jobs
        running_jobs = [j for j in self.jobs if j.get("state") in {"analyzing", "running"}]
        if not running_jobs:
            self.notify("No running jobs to cancel", severity="warning")
            return
        
        job = running_jobs[0]
        case_id = job.get("case_id")
        job_type = job.get("type")
        
        self.notify(
            f"To stop {job_type} for {case_id}, use CLI:\n"
            f"auto-forensics jobs --case-id {case_id} --type {job_type}\n"
            f"Then cancel from there.",
            title="Cancel Job",
            severity="information",
            timeout=10,
        )

    def action_refresh(self) -> None:
        """Refresh job status."""
        self.refresh_data()
