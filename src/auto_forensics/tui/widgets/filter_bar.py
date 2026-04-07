"""Filter bar widget for search and filtering."""

from __future__ import annotations

from textual.message import Message
from textual.widgets import Input, Select, Button
from textual.containers import Horizontal


class FilterBar(Horizontal):
    """A horizontal bar with filter inputs."""

    DEFAULT_CSS = """
    FilterBar {
        height: auto;
        background: #181825;
        border-bottom: solid #313244;
        padding: 1;
    }
    FilterBar Input {
        width: 40;
        height: 5;
        padding: 0 1;
    }
    FilterBar Select {
        width: 20;
    }
    """

    def __init__(
        self,
        placeholder: str = "Search...",
        status_options: list[tuple[str, str]] | None = None,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.placeholder = placeholder
        self.status_options = status_options or [
            ("All", ""),
            ("Created", "created"),
            ("Ready", "ready"),
            ("Ingesting", "ingesting"),
            ("Analyzing", "analyzing"),
            ("Complete", "complete"),
            ("Failed", "failed"),
        ]

    def compose(self):
        yield Input(placeholder=self.placeholder, id="search-input")
        yield Select(
            self.status_options,
            prompt="Status",
            id="status-select",
        )
        yield Button("Clear", id="clear-button", variant="default")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "clear-button":
            self.query_one("#search-input", Input).value = ""
            select = self.query_one("#status-select", Select)
            select.clear()
            self.post_message(self.FilterCleared())

    def get_filter_values(self) -> tuple[str, str]:
        """Get current filter values."""
        search = self.query_one("#search-input", Input).value
        status_select = self.query_one("#status-select", Select)
        status = status_select.value if status_select.value != Select.BLANK else ""
        return search, str(status) if status else ""

    class FilterCleared(Message):
        """Message sent when filters are cleared."""
        pass

    class FilterChanged(Message):
        """Message sent when filter values change."""

        def __init__(self, search: str, status: str) -> None:
            super().__init__()
            self.search = search
            self.status = status
