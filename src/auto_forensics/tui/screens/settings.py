"""Settings screen for configuration viewing and editing."""

from __future__ import annotations

import os
from pathlib import Path

from textual import work
from textual.screen import Screen
from textual.widgets import (
    Static,
    Button,
    Input,
    Switch,
)
from textual.containers import Vertical, Horizontal, Grid
from textual.binding import Binding

from auto_forensics.llama_workflow import LlamaWorkflow


class SettingsScreen(Screen):
    """Screen for viewing and editing application settings."""

    DEFAULT_CSS = """
    SettingsScreen {
        layout: vertical;
        padding: 1;
    }
    SettingsScreen .screen-title {
        text-align: center;
        text-style: bold;
        color: #cba6f7;
        height: 3;
    }
    SettingsScreen .section-title {
        text-style: bold;
        color: #f5c2e7;
        margin-top: 1;
        margin-bottom: 1;
    }
    SettingsScreen .config-path {
        color: #a6adc8;
        margin-bottom: 1;
    }
    SettingsScreen .field-label {
        width: 24;
        color: #cdd6f4;
        content-align: center middle;
    }
    SettingsScreen Input {
        margin: 0 0 1 0;
        background: #313244;
        color: #cdd6f4;
        border: solid #45475a;
        min-width: 30;
    }
    SettingsScreen Input:focus {
        border: solid #cba6f7;
    }
    SettingsScreen .test-btn {
        max-width: 16;
    }
    SettingsScreen #save-status {
        color: #a6e3a1;
        text-style: bold;
        margin: 1 0;
    }
    SettingsScreen #save-status.error {
        color: #f38ba8;
    }
    SettingsScreen #test-result {
        color: #89b4fa;
        margin: 1 0;
    }
    SettingsScreen #test-result.success {
        color: #a6e3a1;
    }
    SettingsScreen #test-result.error {
        color: #f38ba8;
    }
    """

    BINDINGS = [
        ("escape", "back", "Back"),
        ("ctrl+s", "save", "Save Settings"),
    ]

    def __init__(self, service=None, **kwargs) -> None:
        super().__init__(**kwargs)
        self.service = service

    def _get_str_value(self, name: str, default: str = "") -> str:
        """Safely get string config attribute."""
        if self.service and hasattr(self.service, "config"):
            value = getattr(self.service.config, name, default)
            return str(value) if value is not None else default
        return default

    def _get_bool_value(self, name: str, default: bool = False) -> bool:
        """Safely get boolean config attribute."""
        if self.service and hasattr(self.service, "config"):
            value = getattr(self.service.config, name, default)
            return bool(value)
        return default

    def _get_int_value(self, name: str, default: int = 0) -> int:
        """Safely get integer config attribute."""
        if self.service and hasattr(self.service, "config"):
            value = getattr(self.service.config, name, default)
            try:
                return int(value)
            except (TypeError, ValueError):
                return default
        return default

    def compose(self):
        yield Static("Settings", classes="screen-title")

        # Config file path display
        config_path = self._get_config_file_path()
        yield Static(f"Configuration file: {config_path}", classes="config-path")

        # LLM Settings Section
        yield Static("LLM / AI Settings", classes="section-title")
        with Vertical(id="llm-settings"):
            with Horizontal():
                yield Static("Ollama Endpoint:", classes="field-label")
                yield Input(
                    value=self._get_str_value("llama_endpoint", "http://localhost:11434"),
                    id="llama-endpoint",
                    placeholder="http://localhost:11434",
                )
                yield Button("Test", id="test-ollama", classes="test-btn", variant="default")
            with Horizontal():
                yield Static("Ollama Model:", classes="field-label")
                yield Input(
                    value=self._get_str_value("llama_model", "llama3.1:8b"),
                    id="llama-model",
                    placeholder="llama3.1:8b",
                )
            with Horizontal():
                yield Static("OpenAI Endpoint:", classes="field-label")
                yield Input(
                    value=self._get_str_value("openai_compatible_endpoint", ""),
                    id="openai-endpoint",
                    placeholder="https://api.openai.com/v1",
                )
                yield Button("Test", id="test-openai", classes="test-btn", variant="default")
            with Horizontal():
                yield Static("OpenAI API Key:", classes="field-label")
                yield Input(
                    value=self._get_str_value("openai_api_key", ""),
                    id="openai-api-key",
                    placeholder="sk-...",
                    password=True,
                )
            with Horizontal():
                yield Static("OpenAI Model:", classes="field-label")
                yield Input(
                    value=self._get_str_value("llama_model", "gpt-4"),
                    id="openai-model",
                    placeholder="gpt-4",
                )

        # API Keys Section
        yield Static("Threat Intelligence API Keys", classes="section-title")
        with Vertical(id="api-keys"):
            with Horizontal():
                yield Static("VirusTotal Key:", classes="field-label")
                yield Input(
                    value=self._get_str_value("virustotal_api_key", ""),
                    id="virustotal-key",
                    placeholder="API key",
                    password=True,
                )
            with Horizontal():
                yield Static("MalwareBazaar Key:", classes="field-label")
                yield Input(
                    value=self._get_str_value("malwarebazaar_api_key", ""),
                    id="malwarebazaar-key",
                    placeholder="API key",
                    password=True,
                )
            with Horizontal():
                yield Static("AbuseIPDB Key:", classes="field-label")
                yield Input(
                    value=self._get_str_value("abuseipdb_api_key", ""),
                    id="abuseipdb-key",
                    placeholder="API key",
                    password=True,
                )

        # Feature Toggles Section
        yield Static("Feature Toggles", classes="section-title")
        with Grid(id="feature-toggles"):
            yield Static("Enable WHOIS Lookup:", classes="field-label")
            yield Switch(
                self._get_bool_value("enable_whois_lookup", False),
                id="enable-whois",
            )
            yield Static("Auto-Extract Archives:", classes="field-label")
            yield Switch(
                self._get_bool_value("auto_extract", True),
                id="auto-extract",
            )

        # Server Settings Section
        yield Static("Server Settings", classes="section-title")
        with Vertical(id="server-settings"):
            with Horizontal():
                yield Static("Server Host:", classes="field-label")
                yield Input(
                    value=self._get_str_value("host", "127.0.0.1"),
                    id="server-host",
                    placeholder="127.0.0.1",
                )
            with Horizontal():
                yield Static("Server Port:", classes="field-label")
                yield Input(
                    value=str(self._get_int_value("port", 8765)),
                    id="server-port",
                    placeholder="8765",
                )

        # Status and Actions
        yield Static("", id="test-result")
        yield Static("", id="save-status")

        with Horizontal(id="actions"):
            yield Button("Save Settings", id="save", variant="success")
            yield Button("Back [esc]", id="back", variant="primary")
            yield Button("Refresh", id="refresh", variant="default")

    def _get_config_file_path(self) -> str:
        """Get the path to the .env configuration file."""
        data_dir = self._get_data_dir()
        env_path = data_dir / ".env"
        if env_path.exists():
            return str(env_path)
        # Check for env file in current directory or home
        fallback = Path(".env")
        if fallback.exists():
            return str(fallback.resolve())
        return str(env_path) + " (will be created)"

    def _get_data_dir(self) -> Path:
        """Get the data directory."""
        if self.service and hasattr(self.service, "config"):
            return getattr(self.service.config, "data_dir", Path.home() / ".auto_forensics")
        base = os.getenv("AUTO_FORENSICS_HOME")
        if base:
            return Path(base).expanduser().resolve()
        return (Path.home() / ".auto_forensics").resolve()

    def _collect_settings(self) -> dict[str, str]:
        """Collect all settings from input widgets."""
        settings = {}

        # LLM Settings
        llama_endpoint = self.query_one("#llama-endpoint", Input).value.strip()
        if llama_endpoint:
            settings["AUTO_FORENSICS_LLAMA_ENDPOINT"] = llama_endpoint

        llama_model = self.query_one("#llama-model", Input).value.strip()
        if llama_model:
            settings["AUTO_FORENSICS_LLAMA_MODEL"] = llama_model

        openai_endpoint = self.query_one("#openai-endpoint", Input).value.strip()
        if openai_endpoint:
            settings["AUTO_FORENSICS_OPENAI_ENDPOINT"] = openai_endpoint

        openai_key = self.query_one("#openai-api-key", Input).value
        if openai_key:
            settings["AUTO_FORENSICS_OPENAI_API_KEY"] = openai_key

        openai_model = self.query_one("#openai-model", Input).value.strip()
        if openai_model:
            settings["AUTO_FORENSICS_OPENAI_MODEL"] = openai_model

        # API Keys
        vt_key = self.query_one("#virustotal-key", Input).value
        if vt_key:
            settings["AUTO_FORENSICS_VIRUSTOTAL_API_KEY"] = vt_key

        mb_key = self.query_one("#malwarebazaar-key", Input).value
        if mb_key:
            settings["AUTO_FORENSICS_MALWAREBAZAAR_API_KEY"] = mb_key

        abuse_key = self.query_one("#abuseipdb-key", Input).value
        if abuse_key:
            settings["AUTO_FORENSICS_ABUSEIPDB_API_KEY"] = abuse_key

        # Feature Toggles
        whois_switch = self.query_one("#enable-whois", Switch)
        settings["AUTO_FORENSICS_ENABLE_WHOIS"] = "true" if whois_switch.value else "false"

        auto_extract_switch = self.query_one("#auto-extract", Switch)
        settings["AUTO_FORENSICS_AUTO_EXTRACT"] = "true" if auto_extract_switch.value else "false"

        # Server Settings
        server_host = self.query_one("#server-host", Input).value.strip()
        if server_host:
            settings["AUTO_FORENSICS_HOST"] = server_host

        server_port = self.query_one("#server-port", Input).value.strip()
        if server_port:
            settings["AUTO_FORENSICS_PORT"] = server_port

        return settings

    def _write_env_file(self, settings: dict[str, str]) -> tuple[bool, str]:
        """Write settings to .env file."""
        data_dir = self._get_data_dir()
        env_path = data_dir / ".env"

        try:
            # Read existing settings
            existing = {}
            if env_path.exists():
                with open(env_path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if "=" in line and not line.startswith("#"):
                            key, _, value = line.partition("=")
                            existing[key.strip()] = value.strip()

            # Merge with new settings
            existing.update(settings)

            # Write back
            env_path.parent.mkdir(parents=True, exist_ok=True)
            with open(env_path, "w") as f:
                f.write("# Auto Forensics Configuration\n")
                f.write("# Generated by Settings Screen\n\n")
                for key in sorted(existing.keys()):
                    value = existing[key]
                    f.write(f"{key}={value}\n")

            return True, str(env_path)
        except Exception as e:
            return False, str(e)

    def _set_test_result(self, message: str, is_error: bool = False) -> None:
        """Set the test result message."""
        result = self.query_one("#test-result", Static)
        result.update(message)
        result.remove_class("success")
        result.remove_class("error")
        if is_error:
            result.add_class("error")
        else:
            result.add_class("success")

    @work(exclusive=True)
    async def _test_ollama_connection(self) -> None:
        """Test connection to Ollama endpoint."""
        endpoint = self.query_one("#llama-endpoint", Input).value.strip()
        model = self.query_one("#llama-model", Input).value.strip()

        self._set_test_result("Testing Ollama connection...", False)

        try:
            workflow = LlamaWorkflow(
                endpoint=endpoint or "http://localhost:11434",
                model=model or "llama3.1:8b",
                timeout_seconds=10,
                provider="ollama",
            )
            # Simple connectivity test - just try to call
            test_result = workflow._call_ollama("Respond with just the word: OK")
            if test_result is not None:
                self._set_test_result("✓ Ollama connection successful!", False)
            else:
                self._set_test_result("✗ Ollama connection failed - no response", True)
        except Exception as e:
            self._set_test_result(f"✗ Ollama connection failed: {e}", True)

    @work(exclusive=True)
    async def _test_openai_connection(self) -> None:
        """Test connection to OpenAI-compatible endpoint."""
        endpoint = self.query_one("#openai-endpoint", Input).value.strip()
        api_key = self.query_one("#openai-api-key", Input).value
        model = self.query_one("#openai-model", Input).value.strip()

        if not endpoint:
            self._set_test_result("✗ OpenAI endpoint is required", True)
            return

        self._set_test_result("Testing OpenAI-compatible connection...", False)

        try:
            workflow = LlamaWorkflow(
                endpoint=endpoint,
                model=model or "gpt-4",
                timeout_seconds=10,
                provider="openai_compatible",
                api_key=api_key or None,
            )
            test_result = workflow._call_openai_compatible("Respond with just the word: OK")
            if test_result is not None:
                self._set_test_result("✓ OpenAI-compatible connection successful!", False)
            else:
                self._set_test_result("✗ OpenAI connection failed - no response", True)
        except Exception as e:
            self._set_test_result(f"✗ OpenAI connection failed: {e}", True)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "back":
            self.action_back()
        elif event.button.id == "refresh":
            self.refresh()
        elif event.button.id == "save":
            self.action_save()
        elif event.button.id == "test-ollama":
            self._test_ollama_connection()
        elif event.button.id == "test-openai":
            self._test_openai_connection()

    def action_save(self) -> None:
        """Save settings to .env file."""
        status = self.query_one("#save-status", Static)
        settings = self._collect_settings()

        if not settings:
            status.update("No changes to save")
            status.add_class("error")
            return

        success, path_or_error = self._write_env_file(settings)

        if success:
            status.update(f"✓ Settings saved to {path_or_error}")
            status.remove_class("error")
            self.notify(
                "Settings saved! Some changes may require restart to take effect.",
                title="Settings Saved",
                severity="information",
            )
        else:
            status.update(f"✗ Failed to save: {path_or_error}")
            status.add_class("error")

    def action_back(self) -> None:
        """Go back to dashboard."""
        self.app.switch_screen("dashboard")
