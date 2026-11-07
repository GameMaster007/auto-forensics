"""Display defaults retain diagnostics and never prove database integrity."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

import pytest

import test_case_scoped_findings as existing
from auto_forensics.case_integrity import _timeline_matches, finding_projection_changes
from auto_forensics.db import Database
from auto_forensics.models import CaseReport, Finding, TimelineEvent, decode_finding_row, decode_row_json

database_backend = existing.database_backend


def _update(db, table: str, field: str, value: str):
    if isinstance(db, Database):
        with db.connect() as con:
            con.execute(f"UPDATE {table} SET {field}=?", (value,))
    else:
        with db.engine.begin() as con:
            con.execute(db.sa.text(f"UPDATE {table} SET {field}=:value"), {"value": value})


def _case(db, root: Path):
    from test_archive_integrity import _service

    service = _service(root)
    service.db = db
    service.create_case("corruption-case")
    source = root / "source"
    source.mkdir()
    (source / "payload.bin").write_bytes(b"MZ powershell VirtualAlloc synthetic evidence")
    (source / "events.json").write_text(json.dumps([{"event_type": "fixture", "description": "Search needle", "source": "fixture"}]))
    service.ingest_case("corruption-case", source)
    service.analyze_case("corruption-case", enable_llama=False)
    assert service.check_case_integrity("corruption-case")["match"] is True
    return service


def test_finding_coercions_cannot_match_an_empty_expected_value():
    finding = Finding("finding", "Fixture", "low", 0.5, "fixture")
    report = CaseReport("fixture", "2026-01-01T00:00:00Z", [], [finding], [], {})
    row = asdict(finding)
    row["evidence_json"] = "{"
    decoded = decode_finding_row(row)
    assert decoded["evidence"] == [] and decoded["_json_errors"] == ["evidence_json"]
    assert finding_projection_changes(report, [decoded])["modified"] == ["finding"]


def test_timeline_corruption_cannot_match_default_empty_containers():
    event = TimelineEvent(None, "fixture", "fixture", "Fixture")
    report = CaseReport("fixture", "2026-01-01T00:00:00Z", [], [], [event], {})
    row = asdict(event)
    row.update(tags_json="{", related_json="{")
    decode_row_json(row, "tags_json", "tags", list)
    decode_row_json(row, "related_json", "related", dict)
    assert row["tags"] == [] and row["related"] == {}
    assert _timeline_matches(report, [row]) is False


def test_typed_finding_corruption_is_visible_and_sync_restores_it(database_backend, tmp_path):
    service = _case(database_backend, tmp_path)
    db = database_backend
    if isinstance(db, Database):
        with db.connect() as con:
            raw = con.execute("SELECT details_json FROM findings LIMIT 1").fetchone()[0]
    else:
        with db.engine.begin() as con:
            raw = con.exec_driver_sql("SELECT details_json FROM findings LIMIT 1").scalar_one()
    details = json.loads(raw)
    details["analyst_verified"] = "damaged"
    _update(db, "findings", "details_json", json.dumps(details))
    result = service.check_case_integrity("corruption-case")
    assert result["match"] is False and result["projection_match"] is False
    assert any("details_json.analyst_verified" in row.get("_json_errors", []) for row in db.get_findings("corruption-case"))
    json.dumps(service.case_overview("corruption-case"), allow_nan=False)
    service.sync_case_report("corruption-case")
    assert service.check_case_integrity("corruption-case")["match"] is True


@pytest.mark.parametrize("table,field", [("timeline", "tags_json"), ("timeline", "related_json"), ("case_iocs", "sources_json"), ("audit_log", "details_json"), ("artifacts", "metadata_json")])
def test_corrupt_projection_json_keeps_case_views_available(database_backend, tmp_path, table, field):
    service = _case(database_backend, tmp_path)
    _update(database_backend, table, field, "{")
    overview = service.case_overview("corruption-case")
    json.dumps(overview, allow_nan=False)
    json.dumps(service.search_case("corruption-case", "needle"), allow_nan=False)
    key = {"timeline": "timeline", "case_iocs": "iocs", "audit_log": "audit_log", "artifacts": "artifacts"}[table]
    assert any(field in row.get("_json_errors", []) for row in overview[key])
    if table in {"timeline", "artifacts"}:
        assert service.check_case_integrity("corruption-case")["match"] is False


@pytest.mark.parametrize("raw", ["1" * 5000, "[" * 10_000 + "0" + "]" * 10_000, "NaN", "[]"], ids=["large-integer", "deep-json", "nonfinite", "wrong-shape"])
def test_corrupt_job_results_are_safe_and_diagnosed(database_backend, tmp_path, raw):
    service = _case(database_backend, tmp_path)
    db = database_backend
    db.upsert_analysis_job("corrupt-job", "corruption-case", "analysis", "complete", 100, "Finished", result={"findings": 1})
    _update(db, "analysis_jobs", "result_json", raw)
    status = service.get_case_status("corruption-case")
    assert status["result"] is None and status["_json_errors"] == ["result_json"]
    json.dumps(status, allow_nan=False)
