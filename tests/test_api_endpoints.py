from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from auto_forensics.api import create_app
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


def _create_case_with_artifacts(client, tmp_path: Path, case_id: str) -> None:
    created = client.post("/api/cases", json={"case_id": case_id})
    assert created.status_code == 200

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
    (source / "sample.bin").write_text("MZ fake binary powershell https://c2.example", encoding="utf-8")

    ingested = client.post(f"/api/cases/{case_id}/ingest", json={"source_dir": str(source)})
    assert ingested.status_code == 200


def test_api_case_jobs_and_cleanup_endpoints(tmp_path: Path):
    pytest.importorskip("fastapi")
    testclient_module = pytest.importorskip("fastapi.testclient")
    TestClient = testclient_module.TestClient

    cfg = _config(tmp_path)
    app = create_app(cfg)
    client = TestClient(app)

    case_id = "case-api-jobs-001"
    _create_case_with_artifacts(client, tmp_path, case_id)

    started = client.post(f"/api/cases/{case_id}/analyze/async", json={"enable_llama": False})
    assert started.status_code == 200
    assert started.json()["accepted"] is True

    deadline = time.time() + 15
    state = "queued"
    while time.time() < deadline:
        status = client.get(f"/api/cases/{case_id}/status")
        assert status.status_code == 200
        state = status.json()["state"]
        if state in {"complete", "failed"}:
            break
        time.sleep(0.1)
    assert state == "complete"

    enrich_started = client.post(f"/api/cases/{case_id}/enrich/async")
    assert enrich_started.status_code == 200
    assert enrich_started.json()["accepted"] is True

    deadline = time.time() + 15
    enrich_state = "queued"
    while time.time() < deadline:
        status = client.get(f"/api/cases/{case_id}/enrich/status")
        assert status.status_code == 200
        enrich_state = status.json()["state"]
        if enrich_state in {"complete", "failed"}:
            break
        time.sleep(0.1)
    assert enrich_state == "complete"

    jobs = client.get(f"/api/cases/{case_id}/jobs")
    assert jobs.status_code == 200
    payload = jobs.json()
    assert any(item.get("job_type") == "analysis" for item in payload)
    assert any(item.get("job_type") == "enrichment" for item in payload)

    analysis_jobs = client.get(
        f"/api/cases/{case_id}/jobs",
        params={"job_type": "analysis", "limit": 10},
    )
    assert analysis_jobs.status_code == 200
    filtered = analysis_jobs.json()
    assert filtered
    assert all(item.get("job_type") == "analysis" for item in filtered)

    invalid_type = client.get(f"/api/cases/{case_id}/jobs", params={"job_type": "invalid"})
    assert invalid_type.status_code == 422

    cleanup = client.post("/api/admin/jobs/cleanup", json={"retention_days": 3650})
    assert cleanup.status_code == 200
    cleanup_payload = cleanup.json()
    assert cleanup_payload["retention_days"] == 3650
    assert "removed_analysis_jobs" in cleanup_payload
    assert "removed_enrichment_jobs" in cleanup_payload

    cleanup_default = client.post("/api/admin/jobs/cleanup", json={})
    assert cleanup_default.status_code == 200
    assert cleanup_default.json()["retention_days"] == cfg.job_retention_days
