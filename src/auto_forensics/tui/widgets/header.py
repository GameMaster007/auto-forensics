"""Custom header widget for the TUI dashboard."""

from __future__ import annotations

from textual.widgets import Static
from textual.reactive import reactive


class CustomHeader(Static):
    """Custom header with navigation breadcrumbs and title."""

    DEFAULT_CSS = """
    CustomHeader {
        height: 3;
        background: #181825;
        color: #cba6f7;
        content-align: center middle;
        text-style: bold;
        border-bottom: solid #313244;
    }
    """

    title: reactive[str] = reactive("Auto Forensics TUI")
    subtitle: reactive[str] = reactive("")

    def __init__(self, title: str = "Auto Forensics TUI") -> None:
        super().__init__()
        self.title = title

    def render(self) -> str:
        if self.subtitle:
            return f"{self.title} | {self.subtitle}"
        return self.title

    def watch_title(self, title: str) -> None:
        """Update display when title changes."""
        self.update(self.render())

    def watch_subtitle(self, subtitle: str) -> None:
        """Update display when subtitle changes."""
        self.update(self.render())

    def set_subtitle(self, subtitle: str) -> None:
        """Set the subtitle."""
        self.subtitle = subtitle
