"""Case card widget for displaying case summaries with animations."""

from __future__ import annotations

from textual.message import Message
from textual.widgets import Static
from textual.reactive import reactive
from textual.containers import Vertical


class CaseCard(Vertical, can_focus=True):
    """A clickable card displaying case information with beautiful animations."""

    DEFAULT_CSS = """
    CaseCard {
        width: auto;
        height: auto;
        background: #313244;
        border: solid #45475a;
        padding: 1;
        margin: 1;
    }
    CaseCard:focus {
        border: solid #f5c2e7;
        background: #45475a;
    }
    CaseCard:hover {
        background: #45475a;
        border: solid #cba6f7;
    }
    CaseCard .case-id {
        text-style: bold;
        color: #89b4fa;
    }
    CaseCard .status {
        color: #a6adc8;
    }
    CaseCard .stats {
        color: #cdd6f4;
    }
    """

    case_id: reactive[str] = reactive("")
    status: reactive[str] = reactive("")
    artifact_count: reactive[int] = reactive(0)
    finding_count: reactive[int] = reactive(0)
    ioc_count: reactive[int] = reactive(0)
    risk_score: reactive[int | None] = reactive(None)

    def __init__(
        self,
        case_id: str,
        status: str = "",
        artifact_count: int = 0,
        finding_count: int = 0,
        ioc_count: int = 0,
        risk_score: int | None = None,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.case_id = case_id
        self.status = status
        self.artifact_count = artifact_count
        self.finding_count = finding_count
        self.ioc_count = ioc_count
        self.risk_score = risk_score

    def compose(self):
        from textual.widgets import Static
        yield Static(f"Case: {self.case_id}", classes="case-id")
        yield Static(f"Status: {self.status}", classes="status")
        
        stats_text = f"Artifacts: {self.artifact_count} | Findings: {self.finding_count} | IOCs: {self.ioc_count}"
        if self.risk_score is not None:
            stats_text += f" | Risk: {self.risk_score}"
        yield Static(stats_text, classes="stats")

    def on_mount(self) -> None:
        self.update_content()

    def update_content(self) -> None:
        """Refresh the card content."""
        # Remove all children and re-compose
        for child in list(self.children):
            child.remove()
        self.compose()

    def watch_case_id(self, case_id: str) -> None:
        self.update_content()

    def watch_status(self, status: str) -> None:
        self.update_content()

    def watch_artifact_count(self, count: int) -> None:
        self.update_content()

    def watch_finding_count(self, count: int) -> None:
        self.update_content()

    def watch_ioc_count(self, count: int) -> None:
        self.update_content()

    def watch_risk_score(self, score: int | None) -> None:
        self.update_content()

    def on_click(self) -> None:
        """Handle click - post message for parent."""
        self.post_message(self.CaseSelected(self.case_id))

    class CaseSelected(Message):
        """Message sent when case card is selected."""

        def __init__(self, case_id: str) -> None:
            super().__init__()
            self.case_id = case_id
