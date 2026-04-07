"""Stats panel widget with animated counters."""

from __future__ import annotations

from textual.widgets import Static
from textual.reactive import reactive
from textual.containers import Grid


class StatsPanel(Grid):
    """A panel displaying global statistics with animated updates."""

    DEFAULT_CSS = """
    StatsPanel {
        height: auto;
        background: #313244;
        border: solid #45475a;
        padding: 1;
        layout: grid;
        grid-size: 4;
        grid-gutter: 1;
    }
    """

    total_cases: reactive[int] = reactive(0)
    active_cases: reactive[int] = reactive(0)
    failed_cases: reactive[int] = reactive(0)
    complete_cases: reactive[int] = reactive(0)

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._stat_widgets: dict[str, Static] = {}

    def compose(self):
        """Create stat cards."""
        # Total cases
        yield Static("Total Cases", classes="stat-label")
        yield Static("0", classes="stat-value", id="total-cases")
        
        # Active cases
        yield Static("Active", classes="stat-label")
        yield Static("0", classes="stat-value stat-active", id="active-cases")
        
        # Failed cases
        yield Static("Failed", classes="stat-label")
        yield Static("0", classes="stat-value stat-failed", id="failed-cases")
        
        # Complete cases
        yield Static("Complete", classes="stat-label")
        yield Static("0", classes="stat-value stat-complete", id="complete-cases")

    def on_mount(self) -> None:
        """Cache widget references."""
        self._stat_widgets["total"] = self.query_one("#total-cases", Static)
        self._stat_widgets["active"] = self.query_one("#active-cases", Static)
        self._stat_widgets["failed"] = self.query_one("#failed-cases", Static)
        self._stat_widgets["complete"] = self.query_one("#complete-cases", Static)

    def update_stats(self, stats: dict) -> None:
        """Update statistics from service."""
        self.total_cases = stats.get("total_cases", 0)
        self.active_cases = stats.get("active_cases", 0)
        self.failed_cases = stats.get("failed_cases", 0)
        
        by_status = stats.get("by_status", {})
        self.complete_cases = by_status.get("complete", 0)

    def watch_total_cases(self, value: int) -> None:
        if "total" in self._stat_widgets:
            self._stat_widgets["total"].update(str(value))

    def watch_active_cases(self, value: int) -> None:
        if "active" in self._stat_widgets:
            self._stat_widgets["active"].update(str(value))

    def watch_failed_cases(self, value: int) -> None:
        if "failed" in self._stat_widgets:
            self._stat_widgets["failed"].update(str(value))

    def watch_complete_cases(self, value: int) -> None:
        if "complete" in self._stat_widgets:
            self._stat_widgets["complete"].update(str(value))
