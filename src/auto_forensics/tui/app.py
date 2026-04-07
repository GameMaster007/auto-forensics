"""Main TUI application for Auto Forensics with beautiful Catppuccin theme."""

from __future__ import annotations

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import Footer

from auto_forensics.config import AppConfig

from .widgets import CustomHeader
from .screens import (
    DashboardScreen,
    CasesScreen,
    CaseDetailScreen,
    AnalysisScreen,
    SettingsScreen,
)


class ForensicsTUIApp(App):
    """Interactive Terminal UI for Auto Forensics Framework.
    
    Features:
    - Catppuccin Mocha color scheme
    - Smooth animations and transitions
    - Real-time job progress monitoring
    - Keyboard navigation (vim-style)
    - Auto-refreshing dashboard
    """

    CSS_PATH = "styles.css"

    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
        Binding("h", "home", "Dashboard", show=True),
        Binding("c", "cases", "Cases", show=True),
        Binding("a", "analysis", "Analysis", show=True),
        Binding("s", "settings", "Settings", show=True),
        Binding("?", "help", "Help", show=False),
    ]

    def __init__(
        self,
        config: AppConfig | None = None,
        service=None,
        **kwargs,
    ) -> None:
        """Initialize the TUI app.
        
        Args:
            config: AppConfig instance (or None to load from env)
            service: AutoForensicsService instance (or None to create new)
            **kwargs: Additional arguments for App
        """
        super().__init__(**kwargs)
        self.config = config or AppConfig.from_env()
        self.service = service
        self._service_owned = service is None
        self._screens_installed = False

    def compose(self) -> ComposeResult:
        """Compose the app layout."""
        yield CustomHeader("Auto Forensics TUI")
        yield Footer()

    def _install_screens(self) -> None:
        """Install all screens with service reference."""
        if self._screens_installed:
            return

        try:
            self.install_screen(DashboardScreen(service=self.service), name="dashboard")
            self.install_screen(CasesScreen(service=self.service), name="cases")
            self.install_screen(CaseDetailScreen(service=self.service), name="case_detail")
            self.install_screen(AnalysisScreen(service=self.service), name="analysis")
            self.install_screen(SettingsScreen(service=self.service), name="settings")
            self._screens_installed = True
        except Exception as e:
            self.notify(
                f"Failed to install screens: {e}",
                title="Error",
                severity="error",
                timeout=10,
            )
            raise

    def on_mount(self) -> None:
        """Initialize service and push initial screen."""
        try:
            if self.service is None:
                from auto_forensics.service import AutoForensicsService
                self.service = AutoForensicsService(self.config)
                self.service.startup()

            self._install_screens()
            self.push_screen("dashboard")
            self.notify(
                "Welcome to Auto Forensics TUI! Press '?' for help.",
                title="Welcome",
                severity="information",
                timeout=5,
            )
        except Exception as e:
            self.notify(
                f"Failed to initialize: {e}",
                title="Startup Error",
                severity="error",
                timeout=10,
            )

    def action_home(self) -> None:
        """Navigate to dashboard."""
        try:
            self.switch_screen("dashboard")
        except Exception as e:
            self.notify(
                f"Failed to navigate: {e}",
                title="Navigation Error",
                severity="error",
                timeout=5,
            )

    def action_cases(self) -> None:
        """Navigate to cases list."""
        try:
            self.switch_screen("cases")
        except Exception as e:
            self.notify(
                f"Failed to navigate: {e}",
                title="Navigation Error",
                severity="error",
                timeout=5,
            )

    def action_analysis(self) -> None:
        """Navigate to analysis screen."""
        try:
            self.switch_screen("analysis")
        except Exception as e:
            self.notify(
                f"Failed to navigate: {e}",
                title="Navigation Error",
                severity="error",
                timeout=5,
            )

    def action_settings(self) -> None:
        """Navigate to settings screen."""
        try:
            self.switch_screen("settings")
        except Exception as e:
            self.notify(
                f"Failed to navigate: {e}",
                title="Navigation Error",
                severity="error",
                timeout=5,
            )

    def action_help(self) -> None:
        """Show help screen."""
        help_text = """Keyboard Shortcuts:

Navigation:
  h - Dashboard  c - Cases
  a - Analysis   s - Settings

Actions:
  q - Quit       r - Refresh
  esc - Back     ? - Help

Lists: up/down or j/k, Enter to select
"""
        self.notify(help_text, title="Help", severity="information", timeout=10)

    def action_quit(self) -> None:
        """Quit the application with cleanup."""
        try:
            if self._service_owned and self.service:
                self.service.shutdown()
        except Exception:
            pass  # Best effort cleanup
        self.exit()

    def on_shutdown(self) -> None:
        """Clean up service on shutdown."""
        if self._service_owned and self.service:
            try:
                self.service.shutdown()
            except Exception:
                pass  # Best effort cleanup


def main() -> None:
    """Entry point for TUI application."""
    config = AppConfig.from_env()
    app = ForensicsTUIApp(config=config)
    app.run()


if __name__ == "__main__":
    main()
