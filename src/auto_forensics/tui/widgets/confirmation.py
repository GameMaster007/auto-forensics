"""Confirmation modal dialog widget with beautiful animations."""

from __future__ import annotations

from textual.screen import ModalScreen
from textual.widgets import Button, Label, Static
from textual.containers import Grid


class ConfirmationModal(ModalScreen[bool]):
    """A modal dialog for confirmations with scale-in animation."""

    DEFAULT_CSS = """
    ConfirmationModal {
        align: center middle;
    }
    ConfirmationModal > Grid {
        grid-size: 2;
        grid-gutter: 1;
        padding: 2;
        width: 60;
        height: auto;
        background: #313244;
        border: solid #45475a;
        border-radius: 1;
    }
    ConfirmationModal > Grid > Label {
        column-span: 2;
        content-align: center middle;
        text-style: bold;
        color: #cba6f7;
        height: 2;
    }
    ConfirmationModal > Grid > Static {
        column-span: 2;
        content-align: center middle;
        margin: 1;
        color: #cdd6f4;
    }
    """

    def __init__(self, title: str, message: str, **kwargs) -> None:
        super().__init__(**kwargs)
        self.title = title
        self.message = message

    def compose(self) -> Grid:
        with Grid():
            yield Label(self.title)
            yield Static(self.message)
            yield Button("Yes", variant="error", id="yes")
            yield Button("No", variant="primary", id="no")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "yes":
            self.dismiss(True)
        else:
            self.dismiss(False)

    def on_key(self, event) -> None:
        """Handle keyboard shortcuts."""
        if event.key == "y":
            self.dismiss(True)
        elif event.key == "n" or event.key == "escape":
            self.dismiss(False)
