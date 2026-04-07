"""File browser dialog for selecting evidence directories."""

from __future__ import annotations

from pathlib import Path
from textual.screen import ModalScreen
from textual.widgets import Button, DirectoryTree, Input, Label, Static
from textual.containers import Grid, Horizontal, Vertical


class FileBrowserDialog(ModalScreen[Path | None]):
    """A modal dialog for browsing and selecting directories or files."""

    DEFAULT_CSS = """
    FileBrowserDialog {
        align: center middle;
    }
    FileBrowserDialog > Grid {
        grid-size: 1;
        grid-gutter: 1;
        padding: 1;
        width: 80;
        height: 30;
        background: #313244;
        border: solid #45475a;
    }
    FileBrowserDialog > Grid > Label {
        content-align: center middle;
        text-style: bold;
        color: #cba6f7;
        height: 1;
    }
    FileBrowserDialog .path-display {
        background: #181825;
        color: #cdd6f4;
        padding: 1;
        height: auto;
    }
    FileBrowserDialog DirectoryTree {
        height: 1fr;
        border: solid #45475a;
    }
    FileBrowserDialog > Grid > Horizontal {
        height: auto;
    }
    """

    def __init__(
        self,
        title: str = "Select Directory",
        start_path: Path | None = None,
        select_files: bool = False,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.title_text = title
        self.start_path = start_path or Path.home()
        self.select_files = select_files
        self.selected_path: Path | None = None

    def compose(self) -> Grid:
        with Grid():
            yield Label(self.title_text)
            yield Static(str(self.start_path), id="current-path", classes="path-display")
            yield DirectoryTree(self.start_path, id="file-tree")
            with Horizontal():
                yield Button("Select", variant="success", id="select")
                yield Button("Cancel", variant="default", id="cancel")

    def on_directory_tree_directory_selected(
        self, event: DirectoryTree.DirectorySelected
    ) -> None:
        """Handle directory selection."""
        self.selected_path = event.path
        self.query_one("#current-path", Static).update(str(event.path))

    def on_directory_tree_file_selected(self, event: DirectoryTree.FileSelected) -> None:
        """Handle file selection."""
        if self.select_files:
            self.selected_path = event.path
            self.query_one("#current-path", Static).update(str(event.path))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "cancel":
            self.dismiss(None)
        elif event.button.id == "select":
            self._confirm_selection()

    def _confirm_selection(self) -> None:
        """Confirm the selection and dismiss."""
        # Get current selection or use the displayed path
        if self.selected_path:
            self.dismiss(self.selected_path)
        else:
            # Use the path shown in the display
            path_text = self.query_one("#current-path", Static).renderable
            self.dismiss(Path(str(path_text)))

    def on_key(self, event) -> None:
        """Handle keyboard shortcuts."""
        if event.key == "escape":
            self.dismiss(None)
        elif event.key == "enter":
            self._confirm_selection()
