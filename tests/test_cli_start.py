from __future__ import annotations

import sys
from pathlib import Path

from auto_forensics import cli
from auto_forensics.config import AppConfig
from auto_forensics.security import SecurityPolicy


def _config(tmp_path: Path) -> AppConfig:
    data_dir = tmp_path / "data"
    return AppConfig(
        data_dir=data_dir,
        cases_dir=data_dir / "cases",
        db_path=data_dir / "app.db",
        host="127.0.0.1",
        port=8765,
        production=False,
        api_key_hash=None,
        allowed_origins=[],
        trusted_hosts=["127.0.0.1", "localhost"],
        allowed_ingest_roots=[tmp_path.resolve()],
        rate_limit_per_minute=240,
        llama_endpoint="http://localhost:11434",
        llama_model="llama3.1:8b",
        security_policy=SecurityPolicy(max_file_size_bytes=5_000_000, max_total_files=1000, max_text_bytes=1_000_000),
        job_retention_days=30,
    )


def test_cli_serve_calls_api_main(monkeypatch, tmp_path: Path):
    """serve command should call api_main with the configured host/port."""
    cfg = _config(tmp_path)
    seen: dict[str, object] = {}

    monkeypatch.setattr(cli.AppConfig, "from_env", classmethod(lambda cls: cfg))
    monkeypatch.setattr(sys, "argv", ["auto-forensics", "serve", "--host", "0.0.0.0", "--port", "9876"])
    monkeypatch.setattr(cli, "api_main", lambda runtime_cfg: seen.update({"host": runtime_cfg.host, "port": runtime_cfg.port}))

    cli.main()

    assert seen["host"] == "0.0.0.0"
    assert seen["port"] == 9876


def test_cli_serve_default_host_port(monkeypatch, tmp_path: Path):
    """serve command with no flags uses config defaults."""
    cfg = _config(tmp_path)
    seen: dict[str, object] = {}

    monkeypatch.setattr(cli.AppConfig, "from_env", classmethod(lambda cls: cfg))
    monkeypatch.setattr(sys, "argv", ["auto-forensics", "serve"])
    monkeypatch.setattr(cli, "api_main", lambda runtime_cfg: seen.update({"host": runtime_cfg.host, "port": runtime_cfg.port}))

    cli.main()

    assert seen["host"] == "127.0.0.1"
    assert seen["port"] == 8765
