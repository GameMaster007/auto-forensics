from __future__ import annotations

import json
from pathlib import Path
import pytest
from auto_forensics.config import AppConfig
from auto_forensics.security import SecurityPolicy, SecurityError
from auto_forensics.service import AutoForensicsService

@pytest.fixture
def service(tmp_path):
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
        security_policy=SecurityPolicy(
            max_file_size_bytes=5_000_000,
            max_total_files=1000,
            max_text_bytes=1_000_000,
        ),
    )
    return AutoForensicsService(cfg)

def test_full_case_ingestion_cycle(service, tmp_path):
    case_id = "test-integration-case"
    service.create_case(case_id)
    
    # Prepare source directory
    source_dir = tmp_path / "evidence_source"
    source_dir.mkdir()
    
    # 1. JSON artifact
    (source_dir / "events.json").write_text(json.dumps([
        {"timestamp": "2026-02-24T10:00:00Z", "event_type": "test_evt", "description": "desc 1"},
        {"timestamp": "2026-02-24T10:01:00Z", "event_type": "test_evt", "description": "desc 2"}
    ]), encoding="utf-8")
    
    # 2. CSV artifact
    (source_dir / "data.csv").write_text("timestamp,event_type,description\n2026-02-24T10:02:00Z,csv_evt,csv desc\n", encoding="utf-8")
    
    # 3. Text artifact
    (source_dir / "notes.txt").write_text("2026-02-24T10:03:00Z | text_evt | text desc\nplain note\n", encoding="utf-8")
    
    # 4. Binary artifact
    (source_dir / "malicious.exe").write_bytes(b"MZ" + b"\x00" * 100 + b"powershell")
    
    # 5. Unsupported file (should be ignored by default ingestion)
    (source_dir / "ignore.me").write_text("should not be ingested", encoding="utf-8")
    
    # Perform ingestion
    result = service.ingest_case(case_id, source_dir)
    assert result["ingested_files"] == 4
    
    # Verify database state
    overview = service.case_overview(case_id)
    artifacts = overview["artifacts"]
    assert len(artifacts) == 4
    
    # Verify filenames
    names = {a["rel_path"] for a in artifacts}
    assert "events.json" in names
    assert "data.csv" in names
    assert "notes.txt" in names
    assert "malicious.exe" in names
    assert "ignore.me" not in names
    
    # Verify evidence files exist in case directory
    case_evidence_dir = Path(service.require_case(case_id)["evidence_dir"])
    assert (case_evidence_dir / "events.json").exists()
    assert (case_evidence_dir / "malicious.exe").exists()
    
    # Verify hashes were recorded
    hash_log = overview["evidence_hash_log"]
    assert len(hash_log) == 4
    for entry in hash_log:
        assert entry["sha256"] is not None
        assert entry["size_bytes"] > 0

def test_ingestion_respects_limits(service, tmp_path):
    case_id = "limit-test-case"
    service.create_case(case_id)
    
    source_dir = tmp_path / "too_many_files"
    source_dir.mkdir()
    
    # Create 10 files
    for i in range(10):
        (source_dir / f"file_{i}.json").write_text("[]", encoding="utf-8")
        
    # Temporarily lower limit
    service.case_manager.policy.max_total_files = 5
    
    with pytest.raises(SecurityError, match="Maximum file count exceeded"):
        service.ingest_case(case_id, source_dir)
