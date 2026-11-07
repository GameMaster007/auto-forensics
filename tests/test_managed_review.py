"""Managed analyst decisions stay visible and repairable without rerunning analysis."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

from auto_forensics.cli import main
from auto_forensics.config import AppConfig
from auto_forensics.replay import replay_manifest
from auto_forensics.reviews import ReviewError, record_review
from auto_forensics.security import SecurityError, SecurityPolicy
from auto_forensics.service import AutoForensicsService


def _config(root: Path, backend: str = "sqlite") -> AppConfig:
    data = root / "data"
    return AppConfig(
        data_dir=data, cases_dir=data / "cases", db_path=data / "app.db",
        host="127.0.0.1", port=8765, production=False, api_key_hash=None,
        allowed_origins=[], trusted_hosts=["127.0.0.1"], allowed_ingest_roots=[root],
        rate_limit_per_minute=240, llama_endpoint="http://localhost:11434", llama_model="test",
        security_policy=SecurityPolicy(),
        database_url=f"sqlite:///{data / 'sa.db'}" if backend == "sqlalchemy" else None,
    )


@pytest.fixture(params=["sqlite", "sqlalchemy"])
def managed_service(tmp_path: Path, request, offline_enrichment: None):
    service = AutoForensicsService(_config(tmp_path, request.param))
    service.create_case("managed-case")
    assert service.check_case_integrity("managed-case")["match"] is True
    source = tmp_path / "source"
    source.mkdir()
    (source / "payload.bin").write_bytes(b"MZ powershell VirtualAlloc synthetic evidence")
    (source / "events.json").write_text(json.dumps([{
        "timestamp": "2026-11-07T00:00:00Z", "event_type": "process_start",
        "description": "Synthetic process", "source": "sysmon",
    }]))
    service.ingest_case("managed-case", source)
    service.analyze_case("managed-case", enable_llama=False)
    try:
        yield service
    finally:
        service._analysis_executor.shutdown(wait=True)
        service._enrichment_executor.shutdown(wait=True)
        if hasattr(service.db, "engine"):
            service.db.engine.dispose()


def _finding(service: AutoForensicsService) -> dict:
    return service.db.get_findings("managed-case")[0]


def test_managed_reviews_update_all_views_and_replay(managed_service):
    service = managed_service
    assert service.check_case_integrity("managed-case")["match"] is True
    finding = _finding(service)
    entry = service.review_finding("managed-case", finding_id=finding["finding_id"], decision="accept", actor="Ada")
    saved = _finding(service)
    assert saved["review_status"] == "accepted" and saved["analyst_verified"] is True
    assert saved["review_at"] == entry["at"] and saved["created_at"] == finding["created_at"]
    service.review_finding("managed-case", finding_id=finding["finding_id"], decision="annotate", actor="Bea", note="Checked row")
    assert _finding(service)["review_note"] == "Checked row"
    with pytest.raises(ReviewError, match="already set"):
        service.review_finding("managed-case", finding_id=finding["finding_id"], decision="reject", actor="Bea")
    service.review_finding("managed-case", finding_id=finding["finding_id"], decision="reject", actor="Bea", override=True)
    assert _finding(service)["verification"] == "not verified"
    assert service.check_case_integrity("managed-case")["match"] is True
    manifest = Path(service.require_case("managed-case")["output_dir"]) / "run_manifest.json"
    assert replay_manifest(manifest)["match"] is True


def test_standalone_reviews_are_detected_and_sync_does_not_rerun_or_change_report(managed_service, monkeypatch):
    service = managed_service
    finding = _finding(service)
    output = Path(service.require_case("managed-case")["output_dir"])
    record_review(output, finding_id=finding["finding_id"], decision="accept", actor="Ada")
    integrity = service.check_case_integrity("managed-case")
    assert integrity["run"]["match"] is True and integrity["projection_match"] is False
    assert integrity["finding_changes"]["modified"] == [finding["finding_id"]]
    with pytest.raises(ReviewError, match="sync-report"):
        service.review_finding("managed-case", finding_id=finding["finding_id"], decision="annotate", actor="Bea", note="Wait")
    before = {path.name: path.read_bytes() for path in output.iterdir() if path.is_file()}
    note = service.add_case_note("managed-case", "Keep analyst note", "Ada")
    monkeypatch.setattr("auto_forensics.service.run_case", lambda *args, **kwargs: pytest.fail("Sync must not run analysis"))
    service.sync_case_report("managed-case")
    assert service.check_case_integrity("managed-case")["match"] is True
    assert _finding(service)["analyst_verified"] is True
    assert service.list_case_notes("managed-case")[0]["note_id"] == note["note_id"]
    assert before == {path.name: path.read_bytes() for path in output.iterdir() if path.is_file()}


def test_saved_review_survives_a_database_failure_and_can_be_resynchronized(managed_service, monkeypatch):
    service = managed_service
    finding = _finding(service)
    def fail(*args, **kwargs):
        raise RuntimeError("Synthetic unavailable database")
    with monkeypatch.context() as patch:
        patch.setattr(service.db, "update_finding_reviews", fail)
        with pytest.raises(ReviewError, match="was saved.*sync-report"):
            service.review_finding("managed-case", finding_id=finding["finding_id"], decision="accept", actor="Ada")
    assert _finding(service)["analyst_verified"] is False
    assert service.check_case_integrity("managed-case")["match"] is False
    service.sync_case_report("managed-case")
    assert _finding(service)["analyst_verified"] is True
    assert service.check_case_integrity("managed-case")["match"] is True


def test_changed_evidence_cannot_be_synced_into_a_clean_database_view(managed_service):
    service = managed_service
    case = service.require_case("managed-case")
    evidence = Path(case["evidence_dir"]) / "payload.bin"
    evidence.write_bytes(b"changed evidence")
    before = service.db.get_findings("managed-case")
    integrity = service.check_case_integrity("managed-case")
    assert integrity["match"] is False and integrity["custody_changes"]["modified"] == ["payload.bin"]
    assert integrity["run"]["input_match"] is False
    with pytest.raises(SecurityError, match="custody"):
        service.sync_case_report("managed-case")
    assert service.db.get_findings("managed-case") == before


def test_imported_report_can_restore_missing_database_views_without_changing_original_hashes(managed_service, tmp_path):
    service = managed_service
    finding = _finding(service)
    service.review_finding("managed-case", finding_id=finding["finding_id"], decision="accept", actor="Ada")
    original = Path(service.require_case("managed-case")["output_dir"]) / "case_report.json"
    digest = hashlib.sha256(original.read_bytes()).hexdigest()
    archive = tmp_path / "case.zip"
    service.export_case_archive("managed-case", archive)
    service.import_case_archive(archive, case_id_override="imported-case")
    assert service.check_case_integrity("imported-case")["projection_match"] is False
    service.sync_case_report("imported-case")
    assert service.check_case_integrity("imported-case")["match"] is True
    assert service.db.get_findings("imported-case")[0]["analyst_verified"] is True
    copied = Path(service.require_case("imported-case")["output_dir"]) / "case_report.json"
    assert hashlib.sha256(copied.read_bytes()).hexdigest() == digest


def test_cli_managed_review_and_integrity_commands(managed_service, monkeypatch, capsys):
    service = managed_service
    monkeypatch.setattr("auto_forensics.cli.AutoForensicsService", lambda config: service)
    finding = _finding(service)
    monkeypatch.setattr(sys, "argv", ["auto-forensics", "review", "--case-id", "managed-case", "--finding-id",
                                    finding["finding_id"], "--decision", "accept", "--actor", "Ada"])
    main()
    assert json.loads(capsys.readouterr().out)["action"] == "accept"
    monkeypatch.setattr(sys, "argv", ["auto-forensics", "check-case", "--case-id", "managed-case"])
    main()
    assert json.loads(capsys.readouterr().out)["match"] is True


def test_review_api_is_guarded_validated_and_updates_case_views(tmp_path, offline_enrichment):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from auto_forensics.api import create_app

    config = _config(tmp_path)
    config.api_key_hash = hashlib.sha256(b"disposable-test-api-key").hexdigest()
    headers = {"X-API-Key": "disposable-test-api-key"}
    with TestClient(create_app(config), base_url="http://127.0.0.1") as client:
        assert client.post("/api/cases", json={"case_id": "api-review"}, headers=headers).status_code == 200
        source = tmp_path / "source"
        source.mkdir()
        (source / "payload.bin").write_bytes(b"MZ powershell synthetic evidence")
        assert client.post("/api/cases/api-review/ingest", json={"source_dir": str(source)}, headers=headers).status_code == 200
        assert client.post("/api/cases/api-review/analyze", json={"enable_llama": False}, headers=headers).status_code == 200
        finding_id = client.get("/api/cases/api-review", headers=headers).json()["findings"][0]["finding_id"]
        path = f"/api/cases/api-review/findings/{finding_id}/review"
        body = {"decision": "accept", "actor": "Ada"}
        assert client.post(path, json=body).status_code == 401
        assert client.get("/api/cases/api-review/integrity").status_code == 401
        assert client.post("/api/cases/api-review/sync-report").status_code == 401
        assert client.post(path, json={**body, "decision": "invent"}, headers=headers).status_code == 422
        assert client.post(path, json={**body, "actor": ""}, headers=headers).status_code == 422
        assert client.post(path, json=body, headers=headers).status_code == 200
        conflict = client.post(path, json={**body, "decision": "reject"}, headers=headers)
        assert conflict.status_code == 409 and conflict.json()["error"] == "conflict"
        assert client.get("/api/cases/api-review", headers=headers).json()["findings"][0]["analyst_verified"] is True
        assert client.get("/api/cases/api-review/integrity", headers=headers).json()["match"] is True
