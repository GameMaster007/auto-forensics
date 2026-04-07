"""Case creation dialog widget."""

from __future__ import annotations

from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Static
from textual.containers import Grid, Vertical


class CaseCreatorDialog(ModalScreen[str | None]):
    """A modal dialog for creating a new case."""

    DEFAULT_CSS = """
    CaseCreatorDialog {
        align: center middle;
    }
    CaseCreatorDialog > Grid {
        grid-size: 1;
        grid-gutter: 1;
        padding: 2;
        width: 60;
        height: auto;
        background: #313244;
        border: solid #45475a;
    }
    CaseCreatorDialog > Grid > Label {
        content-align: center middle;
        text-style: bold;
        color: #cba6f7;
        height: 2;
    }
    CaseCreatorDialog > Grid > Static {
        color: #a6adc8;
        height: auto;
    }
    CaseCreatorDialog Input {
        margin: 1 0;
        padding: 0 1;
        height: 5;
        border: solid #45475a;
        background: #313244;
        color: #cdd6f4;
    }
    CaseCreatorDialog .error {
        color: #f38ba8;
        text-style: bold;
    }
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.case_id = ""

    def compose(self) -> Grid:
        with Grid():
            yield Label("Create New Case")
            yield Static("Enter a unique case identifier:")
            yield Input(
                placeholder="e.g., case-001, incident-2024-001",
                id="case-id-input",
            )
            yield Static(
                "Valid: letters, numbers, dots, hyphens, underscores\n"
                "Length: 2-64 characters",
                id="hint",
            )
            yield Static("", id="error-msg", classes="error")
            with Vertical():
                yield Button("Create", variant="success", id="create")
                yield Button("Cancel", variant="default", id="cancel")

    def on_mount(self) -> None:
        """Focus the input on mount."""
        self.query_one("#case-id-input", Input).focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        """Validate input as user types."""
        case_id = event.value.strip()
        error_msg = self.query_one("#error-msg", Static)
        
        if not case_id:
            error_msg.update("")
            return
        
        # Validate case ID format
        import re
        if not re.match(r'^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$', case_id):
            error_msg.update("Invalid case ID format")
        else:
            error_msg.update("")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "cancel":
            self.dismiss(None)
        elif event.button.id == "create":
            self._create_case()

    def _create_case(self) -> None:
        """Validate and create case."""
        input_widget = self.query_one("#case-id-input", Input)
        case_id = input_widget.value.strip()
        error_msg = self.query_one("#error-msg", Static)
        
        if not case_id:
            error_msg.update("Case ID is required")
            return
        
        # Validate format
        import re
        if not re.match(r'^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$', case_id):
            error_msg.update("Invalid case ID format")
            return
        
        self.dismiss(case_id)

    def on_key(self, event) -> None:
        """Handle keyboard shortcuts."""
        if event.key == "escape":
            self.dismiss(None)
        elif event.key == "enter":
            self._create_case()
