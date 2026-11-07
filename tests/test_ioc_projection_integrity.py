"""Every saved IOC field participates in checking and projection recovery."""
from __future__ import annotations

import urllib.request

import pytest

import test_projection_corruption as existing
from auto_forensics.db import Database
from auto_forensics.models import IOC

database_backend = existing.database_backend


@pytest.fixture(autouse=True)
def forbid_network(monkeypatch):
    def reject(*args, **kwargs):
        raise AssertionError("Unstubbed network is forbidden")
    monkeypatch.setattr(urllib.request, "urlopen", reject)


def mutate_iocs(db, mutation):
    if mutation == "missing":
        statement = "DELETE FROM case_iocs WHERE case_id='corruption-case'"
    elif mutation == "changed_value":
        statement = "UPDATE case_iocs SET value='tampered-value' WHERE case_id='corruption-case'"
    elif mutation == "bad_sources":
        statement = "UPDATE case_iocs SET sources_json='{' WHERE case_id='corruption-case'"
    elif mutation == "bad_metadata":
        statement = "UPDATE case_iocs SET metadata_json='[]' WHERE case_id='corruption-case'"
    else:
        columns = "case_id,ioc_id,ioc_type,value,first_seen,last_seen,sources_json,metadata_json,created_at"
        statement = f"INSERT INTO case_iocs({columns}) SELECT {columns} FROM case_iocs WHERE case_id='corruption-case' LIMIT 1"
    if isinstance(db, Database):
        with db.connect() as con:
            con.execute(statement)
    else:
        with db.engine.begin() as con:
            con.exec_driver_sql(statement)


@pytest.mark.parametrize("mutation", ["missing", "changed_value", "bad_sources", "bad_metadata", "duplicate"])
def test_check_case_detects_ioc_projection_damage(database_backend, tmp_path, mutation):
    service = existing._case(database_backend, tmp_path)
    assert database_backend.get_case_iocs("corruption-case")
    mutate_iocs(database_backend, mutation)
    result = service.check_case_integrity("corruption-case")
    assert result["match"] is False and result["projection_match"] is False


@pytest.mark.parametrize("mutation", ["missing", "changed_value", "bad_sources", "bad_metadata", "duplicate"])
def test_sync_report_restores_ioc_projection(database_backend, tmp_path, mutation):
    service = existing._case(database_backend, tmp_path)
    original = database_backend.get_case_iocs("corruption-case")
    assert original
    mutate_iocs(database_backend, mutation)
    service.sync_case_report("corruption-case")
    assert database_backend.get_case_iocs("corruption-case") == original


@pytest.mark.parametrize("field", ["origin", "review_status", "worker"])
def test_finding_core_display_coercion_does_not_prove_integrity(database_backend, tmp_path, field):
    service = existing._case(database_backend, tmp_path)
    existing._update(database_backend, "findings", field, "")
    assert service.check_case_integrity("corruption-case")["match"] is False


def test_ioc_projection_without_report_is_not_a_clean_empty_case(database_backend, tmp_path):
    from test_archive_integrity import _service
    service = _service(tmp_path)
    service.db = database_backend
    service.create_case("orphan-ioc")
    database_backend.replace_case_iocs("orphan-ioc", [IOC("unexpected", "ip", "192.0.2.1")])
    assert service.check_case_integrity("orphan-ioc")["match"] is False


def test_whole_report_projection_rolls_back_when_ioc_insertion_fails(database_backend, tmp_path):
    from dataclasses import replace

    from auto_forensics.models import Finding, TimelineEvent

    db = database_backend
    db.create_case("atomic-projection", tmp_path / "evidence", tmp_path / "output")
    original = Finding("atomic-finding", "Original finding", "low", 0.5, "fixture")
    event = TimelineEvent(None, "fixture", "original", "Original event")
    ioc = IOC("original-ioc", "ip", "192.0.2.1")
    db.replace_report_projection("atomic-projection", [original], [event], [ioc])
    before = (db.get_findings("atomic-projection"), db.get_timeline("atomic-projection"), db.get_case_iocs("atomic-projection"))
    sqlite = isinstance(db, Database) or db.engine.dialect.name == "sqlite"
    if sqlite:
        statement = "CREATE TRIGGER reject_ioc BEFORE INSERT ON case_iocs WHEN NEW.value='192.0.2.2' BEGIN SELECT RAISE(ABORT, 'injected IOC failure'); END"
        if isinstance(db, Database):
            with db.connect() as con:
                con.execute(statement)
        else:
            with db.engine.begin() as con:
                con.exec_driver_sql(statement)
    else:
        with db.engine.begin() as con:
            con.exec_driver_sql("ALTER TABLE case_iocs ADD CONSTRAINT reject_ioc CHECK(value <> '192.0.2.2')")
    try:
        with pytest.raises(Exception) as error:
            db.replace_report_projection("atomic-projection", [replace(original, title="Replacement")], [replace(event, description="Replacement")], [replace(ioc, value="192.0.2.2")])
        assert error.value.__class__.__name__ == "IntegrityError"
        assert (db.get_findings("atomic-projection"), db.get_timeline("atomic-projection"), db.get_case_iocs("atomic-projection")) == before
    finally:
        statement = "DROP TRIGGER reject_ioc" if sqlite else "ALTER TABLE case_iocs DROP CONSTRAINT reject_ioc"
        if isinstance(db, Database):
            with db.connect() as con:
                con.execute(statement)
        else:
            with db.engine.begin() as con:
                con.exec_driver_sql(statement)
    db.replace_report_projection("atomic-projection", [replace(original, title="Replacement")], [replace(event, description="Replacement")], [replace(ioc, value="192.0.2.2")])
    assert db.get_findings("atomic-projection")[0]["title"] == "Replacement"
    assert db.get_timeline("atomic-projection")[0]["description"] == "Replacement"
    assert db.get_case_iocs("atomic-projection")[0]["value"] == "192.0.2.2"
