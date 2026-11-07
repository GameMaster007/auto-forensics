"""Unprojectable actor/note text is refused before any saved analyst mutation."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import test_projection_corruption as existing
from auto_forensics.reviews import ReviewError
from auto_forensics.security import SecurityError

database_backend = existing.database_backend


def _snapshot(service):
    output = Path(service.require_case("corruption-case")["output_dir"])
    return (
        {path.name: path.read_bytes() for path in output.iterdir() if path.is_file()},
        service.db.get_findings("corruption-case"), service.db.get_audit_log("corruption-case"),
        service.list_case_notes("corruption-case"),
    )


@pytest.mark.parametrize("actor", ["Ada\x00Bea", "Ada\ud800", "Ada\udfff"], ids=["nul", "high-surrogate", "low-surrogate"])
def test_invalid_actor_cannot_save_a_review_before_audit_failure(database_backend, tmp_path, monkeypatch, actor):
    import auto_forensics.api as api
    TestClient = pytest.importorskip("fastapi.testclient").TestClient
    service = existing._case(database_backend, tmp_path)
    finding_id = database_backend.get_findings("corruption-case")[0]["finding_id"]
    before = _snapshot(service)
    with pytest.raises(ReviewError):
        service.review_finding("corruption-case", finding_id=finding_id, decision="accept", actor=actor)
    assert _snapshot(service) == before
    monkeypatch.setattr(api, "AutoForensicsService", lambda config: service)
    with TestClient(api.create_app(service.config), base_url="http://127.0.0.1", raise_server_exceptions=False) as client:
        response = client.post(
            f"/api/cases/corruption-case/findings/{finding_id}/review",
            content=json.dumps({"decision": "accept", "actor": actor}).encode(),
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 422
    assert _snapshot(service) == before


@pytest.mark.parametrize("field", ["author", "content"])
def test_case_note_nul_is_refused_before_note_or_audit_writes(database_backend, tmp_path, monkeypatch, field):
    import auto_forensics.api as api
    TestClient = pytest.importorskip("fastapi.testclient").TestClient
    service = existing._case(database_backend, tmp_path)
    payload = {"author": "Ada", "content": "Analyst note"}
    payload[field] += "\x00tail"
    before = _snapshot(service)
    with pytest.raises(SecurityError, match="NUL"):
        service.add_case_note("corruption-case", **payload)
    assert _snapshot(service) == before
    monkeypatch.setattr(api, "AutoForensicsService", lambda config: service)
    with TestClient(api.create_app(service.config), base_url="http://127.0.0.1", raise_server_exceptions=False) as client:
        assert client.post("/api/cases/corruption-case/notes", json=payload).status_code == 422
    assert _snapshot(service) == before


def test_json_only_finding_review_note_retains_nul_and_audit(database_backend, tmp_path, monkeypatch):
    import auto_forensics.api as api
    from auto_forensics.replay import replay_manifest

    TestClient = pytest.importorskip("fastapi.testclient").TestClient
    service = existing._case(database_backend, tmp_path)
    finding_id = database_backend.get_findings("corruption-case")[0]["finding_id"]
    monkeypatch.setattr(api, "AutoForensicsService", lambda config: service)
    with TestClient(api.create_app(service.config), base_url="http://127.0.0.1") as client:
        response = client.post(
            f"/api/cases/corruption-case/findings/{finding_id}/review",
            json={"decision": "accept", "actor": "Ada", "note": "before\x00after"},
        )
        assert response.status_code == 200
    assert database_backend.get_findings("corruption-case")[0]["review_note"] == "before\x00after"
    assert any(row["action"] == "finding_reviewed" for row in database_backend.get_audit_log("corruption-case"))
    assert service.check_case_integrity("corruption-case")["match"] is True
    output = Path(service.require_case("corruption-case")["output_dir"])
    assert b"\\u0000" in (output / "analyst_reviews.jsonl").read_bytes()
    assert b"\x00" not in (output / "analyst_reviews.jsonl").read_bytes()
    assert replay_manifest(output / "run_manifest.json")["match"] is True


@pytest.mark.parametrize("suffix", ["\x00tail", "\ud800", "\udfff"])
def test_invalid_finding_identifier_is_refused_before_any_review_mutation(database_backend, tmp_path, monkeypatch, suffix):
    service = existing._case(database_backend, tmp_path)
    finding_id = database_backend.get_findings("corruption-case")[0]["finding_id"]
    before = _snapshot(service)
    with pytest.raises(ReviewError, match="NUL|Unicode"):
        service.review_finding("corruption-case", finding_id=finding_id + suffix, decision="accept", actor="Ada")
    assert _snapshot(service) == before
    if suffix.startswith("\x00"):
        import auto_forensics.api as api

        TestClient = pytest.importorskip("fastapi.testclient").TestClient
        monkeypatch.setattr(api, "AutoForensicsService", lambda config: service)
        with TestClient(api.create_app(service.config), base_url="http://127.0.0.1") as client:
            response = client.post(
                f"/api/cases/corruption-case/findings/{finding_id}%00tail/review",
                json={"decision": "accept", "actor": "Ada"},
            )
            assert response.status_code == 409
        assert _snapshot(service) == before


@pytest.mark.parametrize("note", ["invalid\ud800", "invalid\udfff"])
def test_invalid_review_note_unicode_is_refused_before_any_saved_mutation(database_backend, tmp_path, note):
    service = existing._case(database_backend, tmp_path)
    finding_id = database_backend.get_findings("corruption-case")[0]["finding_id"]
    before = _snapshot(service)
    with pytest.raises(ReviewError, match="Unicode"):
        service.review_finding("corruption-case", finding_id=finding_id, decision="annotate", actor="Ada", note=note)
    assert _snapshot(service) == before
