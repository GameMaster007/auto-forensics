"""Progress card widget for displaying job progress with smooth animations."""

from __future__ import annotations

from textual.widgets import ProgressBar, Static
from textual.reactive import reactive
from textual.containers import Vertical


class ProgressCard(Vertical):
    """A card showing job progress with animated bar and status."""

    DEFAULT_CSS = """
    ProgressCard {
        height: auto;
        background: #313244;
        border: solid #45475a;
        padding: 1;
        margin: 1;
    }
    ProgressCard .job-title {
        text-style: bold;
        color: #cba6f7;
    }
    ProgressCard .job-message {
        color: #a6adc8;
    }
    ProgressCard .case-id {
        color: #89b4fa;
        text-style: bold;
    }
    ProgressCard ProgressBar {
        margin-top: 1;
    }
    """

    job_id: reactive[str] = reactive("")
    case_id: reactive[str] = reactive("")
    job_type: reactive[str] = reactive("")  # "analysis" or "enrichment"
    progress: reactive[int] = reactive(0)
    state: reactive[str] = reactive("")
    message: reactive[str] = reactive("")

    def __init__(
        self,
        job_id: str,
        case_id: str,
        job_type: str,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.job_id = job_id
        self.case_id = case_id
        self.job_type = job_type
        self.progress = 0
        self.state = "queued"
        self.message = "Queued..."

    def compose(self):
        yield Static(f"{self.job_type.upper()}: {self.case_id}", classes="job-title")
        yield Static(self.message, classes="job-message")
        yield ProgressBar(total=100, show_eta=False)

    def on_mount(self) -> None:
        self.update_progress()

    def update_progress(self) -> None:
        """Update the progress bar."""
        try:
            progress_bar = self.query_one(ProgressBar)
            progress_bar.update(progress=self.progress)
        except Exception:
            pass

    def update_message(self) -> None:
        """Update the message display."""
        try:
            message_label = self.query_one(".job-message", Static)
            if message_label:
                message_label.update(self.message)
        except Exception:
            pass

    def watch_progress(self, progress: int) -> None:
        """React to progress changes."""
        self.update_progress()

    def watch_message(self, message: str) -> None:
        """React to message changes."""
        self.update_message()

    def watch_state(self, state: str) -> None:
        """React to state changes - update border color."""
        state_colors = {
            "queued": "#6c7086",
            "running": "#89dceb",
            "complete": "#a6e3a1",
            "failed": "#f38ba8",
        }
        border_color = state_colors.get(state, "#45475a")
        self.styles.border = ("solid", border_color)

    def is_active(self) -> bool:
        """Check if job is still active."""
        return self.state in {"queued", "running"}
