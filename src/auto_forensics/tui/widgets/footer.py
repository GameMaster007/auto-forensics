"""Custom footer widget with key bindings display."""

from __future__ import annotations

from textual.widgets import Footer


class CustomFooter(Footer):
    """Extended footer with status information."""

    DEFAULT_CSS = """
    CustomFooter {
        background: #181825;
        border-top: solid #313244;
    }
    """
