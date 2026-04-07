from __future__ import annotations

import json
import sys
from pathlib import Path

from auto_forensics import cli
from auto_forensics.config import AppConfig
from auto_forensics.security import SecurityPolicy
from auto_forensics.service import AutoForensicsService


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


def _run_cli(monkeypatch, capsys, cfg: AppConfig, args: list[str]) -> str:
    monkeypatch.setattr(cli.AppConfig, "from_env", classmethod(lambda cls: cfg))
    monkeypatch.setattr(sys, "argv", ["auto-forensics", *args])
    cli.main()
    return capsys.readouterr().out.strip()


def test_cli_jobs_list_and_filter(monkeypatch, capsys, tmp_path: Path):
    cfg = _config(tmp_path)
    service = AutoForensicsService(cfg)
    service.create_case("case-cli-jobs-001")
    service.db.upsert_analysis_job(
        job_id="job-cli-analysis",
        case_id="case-cli-jobs-001",
        job_type="analysis",
        state="complete",
        progress=100,
        message="analysis complete",
    )
    service.db.upsert_analysis_job(
        job_id="job-cli-enrich",
        case_id="case-cli-jobs-001",
        job_type="enrichment",
        state="complete",
        progress=100,
        message="enrichment complete",
    )

    payload = json.loads(
        _run_cli(monkeypatch, capsys, cfg, ["jobs", "--case-id", "case-cli-jobs-001", "--json"])
    )
    assert len(payload) == 2
    assert {item["job_type"] for item in payload} == {"analysis", "enrichment"}

    filtered = json.loads(
        _run_cli(
            monkeypatch,
            capsys,
            cfg,
            ["jobs", "--case-id", "case-cli-jobs-001", "--type", "analysis", "--limit", "10", "--json"],
        )
    )
    assert len(filtered) == 1
    assert filtered[0]["job_type"] == "analysis"


def test_cli_cleanup_jobs(monkeypatch, capsys, tmp_path: Path):
    cfg = _config(tmp_path)
    service = AutoForensicsService(cfg)
    service.create_case("case-cli-cleanup-001")
    service.db.upsert_analysis_job(
        job_id="job-cli-analysis-cleanup",
        case_id="case-cli-cleanup-001",
        job_type="analysis",
        state="complete",
        progress=100,
        message="analysis complete",
    )
    service.db.upsert_analysis_job(
        job_id="job-cli-enrich-cleanup",
        case_id="case-cli-cleanup-001",
        job_type="enrichment",
        state="complete",
        progress=100,
        message="enrichment complete",
    )

    # --force skips the interactive confirmation prompt.
    _run_cli(
        monkeypatch,
        capsys,
        cfg,
        ["cleanup-jobs", "--retention-days", "0", "--force"],
    )

    jobs_after = json.loads(
        _run_cli(monkeypatch, capsys, cfg, ["jobs", "--case-id", "case-cli-cleanup-001", "--json"])
    )
    assert jobs_after == []
