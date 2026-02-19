from __future__ import annotations

from pathlib import Path

from auto_forensics.db import Database
from auto_forensics.migrations import LATEST_SCHEMA_VERSION


def test_sqlite_database_runs_migrations_and_tracks_version(tmp_path: Path):
    db = Database(tmp_path / "app.db")
    status = db.run_migrations()
    version = db.get_schema_version()
    history = db.list_schema_migrations()

    assert status["latest_version"] == LATEST_SCHEMA_VERSION
    assert version == LATEST_SCHEMA_VERSION
    assert len(history) >= LATEST_SCHEMA_VERSION


def test_analysis_job_roundtrip(tmp_path: Path):
    db = Database(tmp_path / "app.db")
    db.create_case("case-job", tmp_path / "evidence", tmp_path / "output")
    db.upsert_analysis_job(
        job_id="job-1",
        case_id="case-job",
        job_type="analysis",
        state="running",
        progress=42,
        message="Working",
    )
    db.upsert_analysis_job(
        job_id="job-1",
        case_id="case-job",
        job_type="analysis",
        state="complete",
        progress=100,
        message="Done",
        result={"ok": True},
    )

    latest = db.get_case_latest_job("case-job")
    db.upsert_analysis_job(
        job_id="enrich-1",
        case_id="case-job",
        job_type="enrichment",
        state="complete",
        progress=100,
        message="done",
        result={"ioc_enrichment_count": 0},
    )
    latest_enrich = db.get_case_latest_job("case-job", job_type="enrichment")

    assert latest is not None
    assert latest["job_id"] == "job-1"
    assert latest["state"] == "complete"
    assert latest["progress"] == 100
    assert latest["result"]["ok"] is True
    assert latest_enrich is not None
    assert latest_enrich["job_id"] == "enrich-1"
