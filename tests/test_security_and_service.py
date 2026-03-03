from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor as _TestPool
from pathlib import Path

from auto_forensics.config import AppConfig
from auto_forensics.security import SecurityError, SecurityPolicy, confine_path, validate_case_id
from auto_forensics.service import AutoForensicsService


def _make_cfg(tmp_path: Path) -> AppConfig:
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
    )


def _write_minimal_source(source: Path) -> None:
    source.mkdir(exist_ok=True)
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


def test_validate_case_id_rejects_invalid_chars():
    try:
        validate_case_id("../etc/passwd")
        assert False, "Expected SecurityError"
    except SecurityError:
        pass


def test_confine_path_rejects_escape(tmp_path: Path):
    root = tmp_path / "root"
    root.mkdir()
    escaped = tmp_path / "outside" / "x.txt"
    escaped.parent.mkdir()
    escaped.write_text("x", encoding="utf-8")
    try:
        confine_path(root, escaped)
        assert False, "Expected SecurityError"
    except SecurityError:
        pass


def test_case_lifecycle_end_to_end(tmp_path: Path):
    data_dir = tmp_path / "data"
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
    )
    service = AutoForensicsService(cfg)
    assert service.db_migration_status()["current_version"] >= 1
    service.create_case("case-001")

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
    (source / "sample.bin").write_text(
        "MZ fake binary powershell VirtualAlloc https://c2.example",
        encoding="utf-8",
    )

    ingest_result = service.ingest_case("case-001", source)
    assert ingest_result["ingested_files"] == 2

    analyze_result = service.analyze_case("case-001", enable_llama=False)
    assert analyze_result["findings"] >= 1
    assert analyze_result["iocs"] >= 1

    overview = service.case_overview("case-001")
    assert overview["case"]["status"] == "complete"
    assert len(overview["timeline"]) >= 1
    assert len(overview["iocs"]) >= 1
    assert len(overview["evidence_hash_log"]) >= 2
    assert len(overview["audit_log"]) >= 3

    note = service.add_case_note("case-001", "Investigate suspicious process", author="unit")
    assert note["author"] == "unit"
    notes = service.list_case_notes("case-001")
    assert len(notes) == 1

    html_report = service.get_report("case-001", fmt="html")
    nav_report = service.get_report("case-001", fmt="navigator")
    stix_report = service.get_report("case-001", fmt="stix")
    assert "<html" in html_report.lower()
    assert "techniques" in nav_report
    assert "bundle" in stix_report

    search = service.search_case("case-001", "process")
    assert search["counts"]["timeline"] >= 1


def test_async_analysis_status_transitions(tmp_path: Path):
    data_dir = tmp_path / "data"
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
    )
    service = AutoForensicsService(cfg)
    service.create_case("case-async-001")

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
    service.ingest_case("case-async-001", source)

    kickoff = service.analyze_case_async("case-async-001", enable_llama=False)
    assert kickoff["accepted"] is True
    assert kickoff["job_id"].startswith("job-")

    deadline = time.time() + 15
    state = "queued"
    while time.time() < deadline:
        status = service.get_case_status("case-async-001")
        state = status["state"]
        if state in {"complete", "failed"}:
            break
        time.sleep(0.1)

    assert state == "complete"
    overview = service.case_overview("case-async-001")
    assert overview["latest_job"] is not None
    assert overview["latest_job"]["state"] == "complete"

    enrich_kickoff = service.enrich_case_iocs_async("case-async-001")
    assert enrich_kickoff["accepted"] is True
    assert enrich_kickoff["job_id"].startswith("enrich-")

    deadline = time.time() + 15
    enrich_state = "queued"
    while time.time() < deadline:
        status = service.get_case_enrichment_status("case-async-001")
        enrich_state = status["state"]
        if enrich_state in {"complete", "failed"}:
            break
        time.sleep(0.1)

    assert enrich_state == "complete"
    overview = service.case_overview("case-async-001")
    assert overview["latest_enrichment_job"] is not None
    assert overview["latest_enrichment_job"]["state"] == "complete"


def test_case_export_and_import_archive(tmp_path: Path):
    data_dir = tmp_path / "data"
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
    )
    service = AutoForensicsService(cfg)
    service.create_case("case-export-001")

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
    service.ingest_case("case-export-001", source)

    archive = tmp_path / "case-export.zip"
    exported = service.export_case_archive("case-export-001", archive)
    assert exported["files"] >= 1

    imported = service.import_case_archive(archive, case_id_override="case-import-001")
    assert imported["case_id"] == "case-import-001"


def test_job_history_filter_and_cleanup(tmp_path: Path):
    data_dir = tmp_path / "data"
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
        job_retention_days=30,
    )
    service = AutoForensicsService(cfg)
    service.create_case("case-jobs-001")

    service.db.upsert_analysis_job(
        job_id="job-analysis-1",
        case_id="case-jobs-001",
        job_type="analysis",
        state="complete",
        progress=100,
        message="analysis complete",
    )
    service.db.upsert_analysis_job(
        job_id="job-enrich-1",
        case_id="case-jobs-001",
        job_type="enrichment",
        state="complete",
        progress=100,
        message="enrichment complete",
    )

    all_jobs = service.case_job_history("case-jobs-001")
    analysis_jobs = service.case_job_history("case-jobs-001", job_type="analysis")
    enrichment_jobs = service.case_job_history("case-jobs-001", job_type="enrichment")

    assert len(all_jobs) == 2
    assert len(analysis_jobs) == 1
    assert analysis_jobs[0]["job_type"] == "analysis"
    assert len(enrichment_jobs) == 1
    assert enrichment_jobs[0]["job_type"] == "enrichment"

    try:
        service.case_job_history("case-jobs-001", job_type="invalid")
        assert False, "Expected SecurityError"
    except SecurityError:
        pass

    cleanup = service.cleanup_job_history(retention_days=0)
    assert cleanup["retention_days"] == 0
    assert cleanup["removed_analysis_jobs"] >= 1
    assert cleanup["removed_enrichment_jobs"] >= 1
    assert service.case_job_history("case-jobs-001") == []


def test_case_listing_filters_and_stats_service(tmp_path: Path):
    data_dir = tmp_path / "data"
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
        job_retention_days=30,
    )
    service = AutoForensicsService(cfg)
    service.create_case("case-list-alpha")
    service.create_case("case-list-beta")
    service.create_case("case-list-gamma")
    service.db.set_case_status("case-list-beta", "failed", "sample error")
    service.db.set_case_status("case-list-gamma", "analyzing")

    limited = service.list_cases(limit=2)
    assert len(limited) == 2

    failed_only = service.list_cases(status="failed")
    assert len(failed_only) == 1
    assert failed_only[0]["case_id"] == "case-list-beta"

    search = service.list_cases(query="sample error")
    assert len(search) == 1
    assert search[0]["case_id"] == "case-list-beta"

    try:
        service.list_cases(status="invalid")
        assert False, "Expected SecurityError"
    except SecurityError:
        pass

    stats = service.case_stats()
    assert stats["total_cases"] == 3
    assert stats["by_status"]["failed"] == 1
    assert stats["by_status"]["analyzing"] == 1
    assert stats["active_cases"] == 1
    assert stats["failed_cases"] == 1
    assert isinstance(stats["newest_updated_at"], str)


def test_async_job_immediate_status_is_queued(tmp_path: Path):
    service = AutoForensicsService(_make_cfg(tmp_path))
    service.create_case("case-imm-001")
    _write_minimal_source(tmp_path / "source-imm")
    service.ingest_case("case-imm-001", tmp_path / "source-imm")

    kickoff = service.analyze_case_async("case-imm-001", enable_llama=False)
    assert kickoff["accepted"] is True

    # Check status immediately — before the job can possibly complete.
    status = service.get_case_status("case-imm-001")
    assert status["state"] in {"queued", "running"}, (
        f"Expected 'queued' or 'running' immediately after submission, got {status['state']!r}"
    )

    # Wait for job to finish so the executor is clean before teardown.
    deadline = time.time() + 30
    while time.time() < deadline:
        if service.get_case_status("case-imm-001")["state"] in {"complete", "failed"}:
            break
        time.sleep(0.1)


def test_async_duplicate_job_rejected(tmp_path: Path):
    service = AutoForensicsService(_make_cfg(tmp_path))
    service.create_case("case-dup-001")
    _write_minimal_source(tmp_path / "source-dup")
    service.ingest_case("case-dup-001", tmp_path / "source-dup")

    results: list[dict] = []
    with _TestPool(max_workers=2) as pool:
        f1 = pool.submit(service.analyze_case_async, "case-dup-001", False)
        f2 = pool.submit(service.analyze_case_async, "case-dup-001", False)
        results = [f1.result(), f2.result()]

    accepted = [r for r in results if r["accepted"] is True]
    rejected = [r for r in results if r["accepted"] is False]
    assert len(accepted) == 1, f"Expected exactly 1 accepted, got {len(accepted)}"
    assert len(rejected) == 1, f"Expected exactly 1 rejected, got {len(rejected)}"

    # Wait for the accepted job to finish before teardown.
    deadline = time.time() + 30
    while time.time() < deadline:
        if service.get_case_status("case-dup-001")["state"] in {"complete", "failed"}:
            break
        time.sleep(0.1)
