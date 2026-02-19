from __future__ import annotations

import json
from pathlib import Path

import pytest

from auto_forensics.config import AppConfig
from auto_forensics.migrations import LATEST_SCHEMA_VERSION
from auto_forensics.security import SecurityPolicy
from auto_forensics.service import AutoForensicsService


def test_sqlalchemy_backend_with_sqlite_url(tmp_path: Path):
    pytest.importorskip("sqlalchemy")

    data_dir = tmp_path / "data"
    db_url = f"sqlite:///{(tmp_path / 'sa_app.db').resolve()}"
    cfg = AppConfig(
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
        database_url=db_url,
    )
    service = AutoForensicsService(cfg)
    service.create_case("case-sa-001")

    source = tmp_path / "source"
    source.mkdir()
    (source / "events.json").write_text(
        json.dumps(
            [
                {
                    "timestamp": "2026-02-17T13:12:00Z",
                    "event_type": "process_start",
                    "description": "sample process",
                    "source": "unit-test",
                }
            ]
        ),
        encoding="utf-8",
    )
    (source / "sample.bin").write_text("MZ fake binary powershell", encoding="utf-8")
    service.ingest_case("case-sa-001", source)
    result = service.analyze_case("case-sa-001", enable_llama=False)
    assert result["findings"] >= 1

    migration_status = service.db_migration_status()
    assert migration_status["current_version"] == LATEST_SCHEMA_VERSION

    service.db.upsert_analysis_job(
        job_id="job-sa-1",
        case_id="case-sa-001",
        job_type="analysis",
        state="running",
        progress=33,
        message="sa job",
    )
    latest = service.db.get_case_latest_job("case-sa-001")
    assert latest is not None
    assert latest["job_id"] == "job-sa-1"


def test_sqlalchemy_job_history_and_cleanup(tmp_path: Path):
    pytest.importorskip("sqlalchemy")

    data_dir = tmp_path / "data"
    db_url = f"sqlite:///{(tmp_path / 'sa_jobs.db').resolve()}"
    cfg = AppConfig(
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
        database_url=db_url,
        job_retention_days=30,
    )
    service = AutoForensicsService(cfg)
    service.create_case("case-sa-jobs-001")

    service.db.upsert_analysis_job(
        job_id="job-sa-analysis",
        case_id="case-sa-jobs-001",
        job_type="analysis",
        state="complete",
        progress=100,
        message="analysis complete",
    )
    service.db.upsert_analysis_job(
        job_id="job-sa-enrichment",
        case_id="case-sa-jobs-001",
        job_type="enrichment",
        state="complete",
        progress=100,
        message="enrichment complete",
    )

    all_jobs = service.db.list_case_jobs("case-sa-jobs-001")
    analysis_only = service.db.list_case_jobs("case-sa-jobs-001", job_type="analysis")
    enrichment_only = service.db.list_case_jobs("case-sa-jobs-001", job_type="enrichment")

    assert len(all_jobs) == 2
    assert len(analysis_only) == 1
    assert analysis_only[0]["job_type"] == "analysis"
    assert len(enrichment_only) == 1
    assert enrichment_only[0]["job_type"] == "enrichment"

    removed_analysis = service.db.cleanup_analysis_jobs(0, job_type="analysis")
    removed_enrichment = service.db.cleanup_analysis_jobs(0, job_type="enrichment")
    assert removed_analysis >= 1
    assert removed_enrichment >= 1
    assert service.db.list_case_jobs("case-sa-jobs-001") == []
