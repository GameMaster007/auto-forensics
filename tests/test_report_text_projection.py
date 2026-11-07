"""SQL text portability is checked before publishing or synchronizing a report."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import test_projection_corruption as existing
from auto_forensics.integrity import verify_run
from auto_forensics.manifest import canonical_report_sha256, hash_output_files, serialize_report, write_run_manifest
from auto_forensics.security import SecurityError

database_backend = existing.database_backend


def _publish_untrusted_json(output, report):
    path = output / "case_report.json"
    path.write_text(json.dumps(report))
    manifest = json.loads((output / "run_manifest.json").read_text())
    manifest["output"]["sha256"] = canonical_report_sha256(report)
    manifest["artifacts"] = hash_output_files(output)
    write_run_manifest(output / "run_manifest.json", manifest)


@pytest.mark.parametrize("section,field", [("findings", "title"), ("timeline", "description"), ("timeline", "source"), ("iocs", "value")])
def test_nul_scalar_report_is_refused_before_publication_or_projection(database_backend, tmp_path, monkeypatch, section, field):
    import auto_forensics.api as api
    TestClient = pytest.importorskip("fastapi.testclient").TestClient
    service = existing._case(database_backend, tmp_path)
    output = Path(service.require_case("corruption-case")["output_dir"])
    report = json.loads((output / "case_report.json").read_text())
    report[section][0][field] += "\x00tail"
    with pytest.raises(SecurityError, match="NUL"):
        serialize_report(report)
    _publish_untrusted_json(output, report)
    before = (database_backend.get_findings("corruption-case"), database_backend.get_timeline("corruption-case"), database_backend.get_case_iocs("corruption-case"))
    assert verify_run(output / "run_manifest.json")["match"] is False
    monkeypatch.setattr(api, "AutoForensicsService", lambda config: service)
    with TestClient(api.create_app(service.config), base_url="http://127.0.0.1", raise_server_exceptions=False) as client:
        assert client.post("/api/cases/corruption-case/sync-report").status_code == 409
    assert (database_backend.get_findings("corruption-case"), database_backend.get_timeline("corruption-case"), database_backend.get_case_iocs("corruption-case")) == before


@pytest.mark.parametrize("field", ["description", "source"])
def test_natural_nul_text_fails_with_a_domain_error_before_report_publication(database_backend, tmp_path, monkeypatch, field):
    import auto_forensics.api as api
    from test_archive_integrity import _service
    TestClient = pytest.importorskip("fastapi.testclient").TestClient
    service = _service(tmp_path)
    service.db = database_backend
    service.create_case("nul-case")
    source = tmp_path / "source"
    source.mkdir()
    row = {"event_type": "fixture", "description": "Observed event", "source": "fixture"}
    row[field] += "\x00tail"
    data = json.dumps([row]).encode()
    (source / "events.json").write_bytes(data)
    service.ingest_case("nul-case", source)
    monkeypatch.setattr(api, "AutoForensicsService", lambda config: service)
    with TestClient(api.create_app(service.config), base_url="http://127.0.0.1", raise_server_exceptions=False) as client:
        response = client.post("/api/cases/nul-case/analyze", json={"enable_llama": False})
        assert response.status_code == 400 and "NUL" in response.json()["detail"]
    case = service.require_case("nul-case")
    assert (Path(case["evidence_dir"]) / "events.json").read_bytes() == data
    assert not (Path(case["output_dir"]) / "run_manifest.json").exists()
    assert not (Path(case["output_dir"]) / "case_report.json").exists()


def test_raw_json_metadata_can_retain_nul_without_loss(database_backend, tmp_path):
    service = existing._case(database_backend, tmp_path)
    output = Path(service.require_case("corruption-case")["output_dir"])
    report = json.loads((output / "case_report.json").read_text())
    report["timeline"][0]["related"]["raw_control"] = "before\x00after"
    assert serialize_report(report)
    _publish_untrusted_json(output, report)
    service.sync_case_report("corruption-case")
    assert database_backend.get_timeline("corruption-case")[0]["related"]["raw_control"] == "before\x00after"
    assert service.check_case_integrity("corruption-case")["match"] is True
