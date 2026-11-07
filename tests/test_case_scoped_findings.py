"""Stable finding IDs are scoped to a case, including in existing databases."""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
from pathlib import Path

import pytest

from auto_forensics.db import SCHEMA_SQL, Database
from auto_forensics.db_sqlalchemy import SQLAlchemyDatabase
from auto_forensics.migrations import (
    LATEST_SCHEMA_VERSION,
    MIGRATION_STEPS,
    SchemaCompatibilityError,
    SchemaVersionError,
)
from auto_forensics.models import FINDING_DETAIL_FIELDS, Citation, Finding, TimelineEvent, decode_finding_row
from auto_forensics.pipeline import _unique_finding_ids


@pytest.fixture(params=["sqlite", "sqlalchemy-sqlite", "postgres"])
def database_backend(request: pytest.FixtureRequest, tmp_path: Path):
    if request.param == "sqlite":
        yield Database(tmp_path / "plain.db")
        return
    sa = pytest.importorskip("sqlalchemy")
    if request.param == "sqlalchemy-sqlite":
        db = SQLAlchemyDatabase(f"sqlite:///{tmp_path / 'sqlalchemy.db'}")
        try:
            yield db
        finally:
            db.engine.dispose()
        return
    url = os.environ.get("AUTO_FORENSICS_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("AUTO_FORENSICS_TEST_POSTGRES_URL not set")
    schema = "af_test_" + uuid.uuid4().hex
    engine = sa.create_engine(url)
    with engine.begin() as con:
        con.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
    scoped = sa.engine.make_url(url).update_query_dict({"options": f"-csearch_path={schema}"})
    db = None
    try:
        db = SQLAlchemyDatabase(scoped.render_as_string(hide_password=False))
        yield db
    finally:
        if db is not None:
            db.engine.dispose()
        with engine.begin() as con:
            con.exec_driver_sql(f'DROP SCHEMA "{schema}" CASCADE')
        engine.dispose()


def _finding(title: str = "Synthetic finding") -> Finding:
    return Finding(
        "same-stable-id", title, "medium", 0.12345678901234567, "execution",
        evidence=["synthetic evidence"],
        citations=[Citation("synthetic", "fixture.json", "a" * 64, row=1)],
        worker="reverse-analysis",
    )


def _cases(db, root: Path) -> None:
    for case in ("case-one", "case-two"):
        db.create_case(case, root / case / "evidence", root / case / "output")


def test_identical_finding_ids_in_different_cases_are_independent(database_backend, tmp_path: Path):
    db = database_backend
    _cases(db, tmp_path)
    db.replace_findings_and_timeline("case-one", [_finding("First case")], [])
    db.replace_findings_and_timeline("case-two", [_finding("Second case")], [])
    assert db.get_findings("case-one")[0]["title"] == "First case"
    assert db.get_findings("case-two")[0]["title"] == "Second case"
    db.replace_findings_and_timeline("case-one", [_finding("Updated first case")], [])
    assert db.get_findings("case-two")[0]["title"] == "Second case"
    assert db.get_findings("case-one")[0]["citations"][0]["sha256"] == "a" * 64


def test_database_timeline_is_chronological_across_offsets_with_unknowns_last(database_backend, tmp_path: Path):
    db = database_backend
    _cases(db, tmp_path)
    events = [
        TimelineEvent(None, "fixture", "unknown", "Unknown first"),
        TimelineEvent("2026-11-06T23:45:00Z", "fixture", "middle", "Middle"),
        TimelineEvent("2026-11-07T00:30:00.1000000+01:00", "fixture", "earliest", "Earlier offset clock"),
        TimelineEvent("2026-11-07T00:00:00.1Z", "fixture", "latest", "Latest"),
        TimelineEvent("invalid", "fixture", "invalid", "Invalid clock"),
    ]
    db.replace_findings_and_timeline("case-one", [], events)
    assert [event["event_type"] for event in db.get_timeline("case-one")] == ["earliest", "middle", "latest", "unknown", "invalid"]


def test_duplicate_ids_within_one_case_roll_back_the_replacement(database_backend, tmp_path: Path):
    db = database_backend
    _cases(db, tmp_path)
    db.replace_findings_and_timeline("case-one", [_finding("Original")], [])
    with pytest.raises(Exception) as error:
        db.replace_findings_and_timeline("case-one", [_finding("Replacement"), _finding("Duplicate")], [])
    assert error.value.__class__.__name__ == "IntegrityError"
    assert [row["title"] for row in db.get_findings("case-one")] == ["Original"]


def test_finding_details_and_review_projection_round_trip_without_cross_case_updates(database_backend, tmp_path: Path):
    db = database_backend
    _cases(db, tmp_path)
    original = replace(_finding(), technique_id="T1059", sub_technique="T1059.001", ioc_refs=["ioc-1"],
                       confidence_low=0.1, confidence_high=0.9, verification="supported")
    for case in ("case-one", "case-two"):
        db.replace_findings_and_timeline(case, [original], [])
    before = db.get_findings("case-one")[0]
    assert {key: before[key] for key in asdict(original)} == asdict(original)
    reviewed = replace(original, review_status="accepted", analyst_verified=True,
                       review_actor="Ada", review_at="2026-11-07T01:00:00Z", review_note="Checked source",
                       machine_verification="supported")
    db.update_finding_reviews("case-one", [reviewed])
    after = db.get_findings("case-one")[0]
    assert {key: after[key] for key in asdict(reviewed)} == asdict(reviewed)
    assert after["created_at"] == before["created_at"]
    assert db.get_findings("case-two")[0]["review_status"] == "unverified"
    with pytest.raises(ValueError, match="not indexed"):
        db.update_finding_reviews("case-one", [original, replace(original, finding_id="missing")])
    assert db.get_findings("case-one")[0] == after
    searched = db.search_case("case-one", "Synthetic")["findings"][0]
    assert {key: searched[key] for key in asdict(reviewed)} == asdict(reviewed)


@pytest.mark.parametrize("raw", ["{bad", "[]", "null", 12])
def test_corrupt_finding_details_have_safe_defaults(raw):
    row = decode_finding_row({"details_json": raw, "review_status": "unverified"})
    assert row["analyst_verified"] is False
    assert row["ioc_refs"] == []
    assert row["confidence_low"] is None


def test_finding_details_cannot_override_core_fields_or_invent_an_accepted_decision():
    row = decode_finding_row({"title": "Original", "review_status": "rejected", "details_json": json.dumps({
        "title": "Injected", "review_status": "accepted", "analyst_verified": True,
        "confidence_low": 10 ** 400, "confidence_high": True, "ioc_refs": ["ioc-1", 4],
    })})
    assert row["title"] == "Original"
    assert row["review_status"] == "rejected"
    assert row["analyst_verified"] is False
    assert row["confidence_low"] is None and row["confidence_high"] is None
    assert row["ioc_refs"] == ["ioc-1"]
    assert set(FINDING_DETAIL_FIELDS).issubset(row)


def test_review_detail_migration_rolls_back_and_retries_without_losing_legacy_rows(database_backend, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    import auto_forensics.db as plain
    import auto_forensics.db_sqlalchemy as sqlalchemy

    db = database_backend
    _cases(db, tmp_path)
    db.replace_findings_and_timeline("case-one", [_finding("Legacy data")], [])
    plain_backend = isinstance(db, Database)
    if plain_backend:
        with db.connect() as con:
            con.execute("ALTER TABLE findings DROP COLUMN details_json")
            con.execute("DELETE FROM schema_migrations WHERE version >= 7")
            con.execute("PRAGMA user_version=6")
    else:
        with db.engine.begin() as con:
            con.exec_driver_sql("ALTER TABLE findings DROP COLUMN details_json")
            con.execute(db.schema_migrations.delete().where(db.schema_migrations.c.version >= 7))
            if db.engine.dialect.name == "sqlite":
                con.exec_driver_sql("PRAGMA user_version=6")
    step = next(step for step in MIGRATION_STEPS if step.version == 7)
    broken = replace(step, sql_statements=step.sql_statements + ("SELECT * FROM missing_detail_migration_table",))
    with monkeypatch.context() as patch:
        patch.setattr(plain if plain_backend else sqlalchemy, "MIGRATION_STEPS", (broken,))
        with pytest.raises(Exception) as error:
            db.run_migrations()
        assert error.value.__class__.__name__ in {"OperationalError", "ProgrammingError"}
    assert db.get_schema_version() == 6
    if plain_backend:
        with db.connect() as con:
            assert "details_json" not in {row[1] for row in con.execute("PRAGMA table_info(findings)")}
    else:
        with db.engine.begin() as con:
            assert "details_json" not in {column["name"] for column in db.sa.inspect(con).get_columns("findings")}
    assert db.run_migrations()["current_version"] == LATEST_SCHEMA_VERSION
    row = db.get_findings("case-one")[0]
    assert row["title"] == "Legacy data" and row["analyst_verified"] is False


def test_pipeline_keeps_distinct_cited_rows_and_deduplicates_identical_submissions():
    first = _finding()
    second = _finding()
    second.citations[0].row = 2
    forward = _unique_finding_ids([first, second])
    assert len(forward) == 2
    by_row = {item.citations[0].row: item.finding_id for item in forward}
    assert len(set(by_row.values())) == 2
    reverse_first = _finding()
    reverse_second = _finding()
    reverse_second.citations[0].row = 2
    reverse = _unique_finding_ids([reverse_second, reverse_first])
    assert {item.citations[0].row: item.finding_id for item in reverse} == by_row
    duplicate = _finding()
    assert len(_unique_finding_ids([duplicate, duplicate])) == 1


def test_foreign_keys_are_enforced_and_deleting_one_case_preserves_the_other(database_backend, tmp_path: Path):
    db = database_backend
    _cases(db, tmp_path)
    for case in ("case-one", "case-two"):
        db.replace_findings_and_timeline(case, [_finding()], [])
    with pytest.raises(Exception) as error:
        db.replace_findings_and_timeline("nonexistent-case", [_finding()], [])
    assert error.value.__class__.__name__ == "IntegrityError"
    if isinstance(db, Database):
        with db.connect() as con:
            con.execute("DELETE FROM cases WHERE case_id = ?", ("case-one",))
    else:
        with db.engine.begin() as con:
            con.execute(db.cases.delete().where(db.cases.c.case_id == "case-one"))
    assert db.get_findings("case-one") == []
    assert len(db.get_findings("case-two")) == 1


def _legacy_database(path: Path) -> None:
    legacy = SCHEMA_SQL.replace("finding_id TEXT NOT NULL,", "finding_id TEXT PRIMARY KEY,", 1)
    legacy = legacy.replace("    PRIMARY KEY(case_id, finding_id),\n", "", 1)
    with sqlite3.connect(path) as con:
        con.executescript(legacy)
        for step in MIGRATION_STEPS:
            if step.version > 5:
                break
            for statement in step.sql_statements:
                con.execute(statement)
            con.execute("INSERT INTO schema_migrations VALUES(?, ?, ?)", (step.version, step.name, "2026-01-01T00:00:00Z"))
        con.execute("PRAGMA user_version=5")
        con.execute(
            "INSERT INTO cases VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("legacy-case", "2026-01-01", "2026-01-01", "complete", "evidence", "output", None),
        )
        con.execute(
            """INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            ("same-stable-id", "legacy-case", "Preserve this finding", "medium", 0.12345678901234567,
             "execution", '["original evidence"]', "Inspect cited row", "2026-01-01",
             '[{"artifact_id":"e1","source_file":"evidence.json","sha256":"' + "a" * 64 + '","row":1}]',
             "detector", "unverified", "legacy-worker"),
        )


@pytest.mark.parametrize("backend", ["sqlite", "sqlalchemy"])
def test_existing_v5_database_migrates_without_losing_findings_and_reopens(tmp_path: Path, backend: str):
    path = tmp_path / "legacy.db"
    _legacy_database(path)
    with sqlite3.connect(path) as con:
        query = con.execute("SELECT * FROM findings")
        original_row = dict(zip((column[0] for column in query.description), query.fetchone()))
    factory = (lambda: Database(path)) if backend == "sqlite" else (lambda: SQLAlchemyDatabase(f"sqlite:///{path}"))
    db = factory()
    row = db.get_findings("legacy-case")[0]
    with sqlite3.connect(path) as con:
        query = con.execute("SELECT * FROM findings")
        migrated = dict(zip((column[0] for column in query.description), query.fetchone()))
        assert {key: migrated[key] for key in original_row} == original_row
    assert row["title"] == "Preserve this finding"
    assert row["confidence"] == 0.12345678901234567
    assert row["evidence"] == ["original evidence"]
    assert row["worker"] == "legacy-worker"
    assert row["citations"][0]["row"] == 1
    db.create_case("second-case", tmp_path / "second/evidence", tmp_path / "second/output")
    db.replace_findings_and_timeline("second-case", [_finding("Other case")], [])
    assert db.get_findings("legacy-case")[0] == row
    if backend == "sqlalchemy":
        db.engine.dispose()
    reopened = factory()
    assert reopened.get_schema_version() == LATEST_SCHEMA_VERSION
    assert reopened.get_findings("legacy-case")[0] == row
    assert reopened.run_migrations()["applied"] == []
    if backend == "sqlalchemy":
        reopened.engine.dispose()


@pytest.mark.parametrize("backend", ["sqlite", "sqlalchemy"])
def test_failed_rebuild_rolls_back_table_data_and_migration_version(tmp_path: Path, backend: str, monkeypatch: pytest.MonkeyPatch):
    import auto_forensics.db as plain
    import auto_forensics.db_sqlalchemy as sqlalchemy

    path = tmp_path / "rollback.db"
    _legacy_database(path)
    step = next(step for step in MIGRATION_STEPS if step.version == 6)
    broken = replace(step, sql_statements=step.sql_statements[:3] + ("SELECT * FROM nonexistent_migration_table",))
    steps = tuple(step for step in MIGRATION_STEPS if step.version < 6) + (broken,)
    module = plain if backend == "sqlite" else sqlalchemy
    with monkeypatch.context() as patch:
        patch.setattr(module, "MIGRATION_STEPS", steps)
        with pytest.raises(Exception) as error:
            if backend == "sqlite":
                Database(path)
            else:
                SQLAlchemyDatabase(f"sqlite:///{path}")
        assert error.value.__class__.__name__ == "OperationalError"
    with sqlite3.connect(path) as con:
        assert con.execute("SELECT title FROM findings").fetchone()[0] == "Preserve this finding"
        assert con.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 5
        assert not con.execute("SELECT name FROM sqlite_master WHERE name='findings_case_scoped'").fetchall()
        assert [row[1] for row in con.execute("PRAGMA table_info(findings)") if row[5]] == ["finding_id"]
    assert Database(path).get_schema_version() == LATEST_SCHEMA_VERSION


@pytest.mark.parametrize("backend", ["sqlite", "sqlalchemy"])
def test_unrecognized_legacy_columns_are_preserved_by_refusing_the_rebuild(tmp_path: Path, backend: str):
    path = tmp_path / "custom-layout.db"
    _legacy_database(path)
    with sqlite3.connect(path) as con:
        con.execute("ALTER TABLE findings ADD COLUMN external_annotation TEXT")
        con.execute("UPDATE findings SET external_annotation='preserve custom data'")
    with pytest.raises(SchemaCompatibilityError, match="refusing to discard data"):
        Database(path) if backend == "sqlite" else SQLAlchemyDatabase(f"sqlite:///{path}")
    with sqlite3.connect(path) as con:
        assert con.execute("SELECT external_annotation FROM findings").fetchone()[0] == "preserve custom data"
        assert con.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 5


@pytest.mark.parametrize("backend", ["sqlite", "sqlalchemy"])
def test_legacy_rebuild_refuses_to_cascade_delete_external_annotations(tmp_path: Path, backend: str):
    path = tmp_path / "external-notes.db"
    _legacy_database(path)
    with sqlite3.connect(path) as con:
        con.execute("PRAGMA foreign_keys=ON")
        con.execute("CREATE TABLE external_notes (finding_id TEXT REFERENCES findings(finding_id) ON DELETE CASCADE, note TEXT)")
        con.execute("INSERT INTO external_notes VALUES ('same-stable-id', 'Preserve annotation')")
    with pytest.raises(SchemaCompatibilityError, match="dependent data"):
        Database(path) if backend == "sqlite" else SQLAlchemyDatabase(f"sqlite:///{path}")
    with sqlite3.connect(path) as con:
        assert con.execute("SELECT * FROM external_notes").fetchall() == [("same-stable-id", "Preserve annotation")]
        assert con.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 5
        assert con.execute("SELECT title FROM findings").fetchone()[0] == "Preserve this finding"


def test_shared_ioc_cache_upsert_is_atomic(database_backend):
    import threading

    from auto_forensics.models import IOCEnrichment

    db = database_backend
    barrier = threading.Barrier(2)
    # Force the former UPDATE/INSERT implementation to observe the absent
    # key twice; an atomic INSERT has no separate UPDATE to pause.
    def pause_after_update(conn, cursor, statement, parameters, context, executemany):
        if statement.startswith("UPDATE ioc_enrichment_cache SET"):
            barrier.wait(timeout=5)

    sqlalchemy = isinstance(db, SQLAlchemyDatabase)
    if sqlalchemy:
        db.sa.event.listen(db.engine, "after_cursor_execute", pause_after_update)
    def write(index):
        db.upsert_ioc_enrichment_cache("domain", "synthetic.test", IOCEnrichment(
            str(index), "ioc", "fixture", "unknown", 0.5, details={"writer": index},
        ))
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(write, range(2)))
    finally:
        if sqlalchemy:
            db.sa.event.remove(db.engine, "after_cursor_execute", pause_after_update)
    cached = db.get_cached_ioc_enrichment("domain", "synthetic.test", "fixture", ttl_minutes=60)
    assert cached is not None and cached.details["writer"] in {0, 1}


@pytest.mark.parametrize("table", ["artifacts", "evidence_hash_log", "audit_log"])
def test_import_database_failure_rolls_back_custody_and_allows_retry(database_backend, tmp_path: Path, table: str):
    from test_archive_integrity import _archive, _row, _service

    db = database_backend
    service = _service(tmp_path)
    service.db = db
    payload = b"synthetic imported evidence"
    archive = _archive(service, tmp_path / "import.zip", [_row("evidence/note.txt", payload)], [("evidence/note.txt", payload)])
    plain = isinstance(db, Database)
    def reject_insert(conn, cursor, statement, parameters, context, executemany):
        if statement.startswith(f"INSERT INTO {table} "):
            raise RuntimeError("injected import persistence failure")
    if plain:
        with db.connect() as con:
            con.execute(f"CREATE TRIGGER refuse_import BEFORE INSERT ON {table} BEGIN SELECT RAISE(ABORT, 'injected import persistence failure'); END")
    else:
        db.sa.event.listen(db.engine, "before_cursor_execute", reject_insert)
    try:
        with pytest.raises(Exception, match="injected import persistence failure"):
            service.import_case_archive(archive)
        assert db.get_case("archive-case") is None
        assert db.get_artifacts("archive-case") == []
        assert db.get_evidence_hash_log("archive-case") == []
        assert not (service.config.cases_dir / "archive-case").exists()
    finally:
        if plain:
            with db.connect() as con:
                con.execute("DROP TRIGGER refuse_import")
        else:
            db.sa.event.remove(db.engine, "before_cursor_execute", reject_insert)
    service.import_case_archive(archive)
    assert service.check_case_integrity("archive-case")["match"] is True
    assert db.get_case("archive-case")["status"] == "ready"
    assert db.get_audit_log("archive-case")[0]["action"] == "case_imported"


def test_import_preserves_evidence_after_lost_commit_acknowledgement(database_backend, tmp_path: Path, monkeypatch):
    from auto_forensics.security import SecurityError
    from test_archive_integrity import _archive, _row, _service

    service = _service(tmp_path)
    service.db = database_backend
    payload = b"synthetic imported evidence"
    archive = _archive(service, tmp_path / "import.zip", [_row("evidence/note.txt", payload)], [("evidence/note.txt", payload)])
    original = service.db.import_case_records
    def commit_then_raise(*args, **kwargs):
        original(*args, **kwargs)
        raise RuntimeError("lost commit acknowledgement")
    monkeypatch.setattr(service.db, "import_case_records", commit_then_raise)
    with pytest.raises(SecurityError, match="may have committed"):
        service.import_case_archive(archive)
    assert (service.config.cases_dir / "archive-case/evidence/note.txt").read_bytes() == payload
    assert service.check_case_integrity("archive-case")["match"] is True


@pytest.mark.parametrize("backend", ["sqlite", "sqlalchemy"])
def test_concurrent_initializers_share_a_consistent_schema(tmp_path: Path, backend: str):
    path = tmp_path / "concurrent.db"

    def initialize(_: int):
        db = Database(path) if backend == "sqlite" else SQLAlchemyDatabase(f"sqlite:///{path}")
        try:
            return db.get_schema_version()
        finally:
            if backend == "sqlalchemy":
                db.engine.dispose()

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert list(pool.map(initialize, range(8))) == [LATEST_SCHEMA_VERSION] * 8


def test_migration_does_not_commit_a_callers_existing_transaction(tmp_path: Path):
    db = Database(tmp_path / "caller.db")
    with pytest.raises(RuntimeError, match="rollback caller"):
        with db.connect() as con:
            con.execute("INSERT INTO cases VALUES(?, ?, ?, ?, ?, ?, ?)", ("pending-case", "now", "now", "created", "e", "o", None))
            con.execute("PRAGMA user_version=5")
            con.execute("DELETE FROM schema_migrations WHERE version>=6")
            db.run_migrations(con)
            raise RuntimeError("rollback caller")
    assert db.get_case("pending-case") is None
    assert db.get_schema_version() == LATEST_SCHEMA_VERSION


def test_sqlite_backends_can_reopen_each_others_database_without_reapplying_migrations(tmp_path: Path):
    path = tmp_path / "shared.db"
    db = SQLAlchemyDatabase(f"sqlite:///{path}")
    db.create_case("shared-case", tmp_path / "evidence", tmp_path / "output")
    db.replace_findings_and_timeline("shared-case", [_finding()], [])
    history = db.list_schema_migrations()
    db.engine.dispose()
    plain = Database(path)
    assert plain.run_migrations()["applied"] == []
    assert plain.list_schema_migrations() == history
    reopened = SQLAlchemyDatabase(f"sqlite:///{path}")
    assert reopened.run_migrations()["applied"] == []
    assert reopened.list_schema_migrations() == history
    reopened.engine.dispose()


@pytest.mark.parametrize("marker", ["history", "pragma", "both"])
def test_a_newer_sqlite_schema_is_not_downgraded(tmp_path: Path, marker: str):
    path = tmp_path / "newer.db"
    db = Database(path)
    db.create_case("preserved-case", tmp_path / "evidence", tmp_path / "output")
    with db.connect() as con:
        if marker in {"history", "both"}:
            con.execute("UPDATE schema_migrations SET version=999 WHERE version=?", (LATEST_SCHEMA_VERSION,))
        if marker in {"pragma", "both"}:
            con.execute("PRAGMA user_version=999")
    for factory in (lambda: Database(path), lambda: SQLAlchemyDatabase(f"sqlite:///{path}")):
        with pytest.raises(SchemaVersionError, match="refusing a downgrade"):
            factory()
    with sqlite3.connect(path) as con:
        assert con.execute("SELECT case_id FROM cases").fetchone()[0] == "preserved-case"
        assert con.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == (999 if marker != "pragma" else LATEST_SCHEMA_VERSION)
        assert con.execute("PRAGMA user_version").fetchone()[0] == (999 if marker != "history" else LATEST_SCHEMA_VERSION)


@pytest.mark.parametrize("database_backend", ["postgres"], indirect=True)
@pytest.mark.parametrize("fail_first", [False, True])
def test_existing_postgres_database_rebuild_is_transactional(database_backend, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fail_first: bool):
    import auto_forensics.db_sqlalchemy as module

    db = database_backend
    _cases(db, tmp_path)
    db.replace_findings_and_timeline("case-one", [_finding("Retain PostgreSQL data")], [])
    original = db.get_findings("case-one")[0]
    with db.engine.begin() as con:
        original_row = dict(con.exec_driver_sql("SELECT * FROM findings").fetchone()._mapping)
        original_row.pop("details_json", None)
        constraint = db.sa.inspect(con).get_pk_constraint("findings")["name"]
        quoted = db.engine.dialect.identifier_preparer.quote(constraint)
        con.exec_driver_sql(f"ALTER TABLE findings DROP CONSTRAINT {quoted}")
        con.exec_driver_sql("ALTER TABLE findings ADD PRIMARY KEY (finding_id)")
        con.exec_driver_sql("ALTER TABLE findings DROP COLUMN details_json")
        con.execute(db.schema_migrations.delete().where(db.schema_migrations.c.version >= 6))
    if fail_first:
        step = next(step for step in MIGRATION_STEPS if step.version == 6)
        broken = replace(step, sql_statements=step.sql_statements[:3] + ("SELECT * FROM nonexistent_migration_table",))
        with monkeypatch.context() as patch:
            patch.setattr(module, "MIGRATION_STEPS", tuple(step for step in MIGRATION_STEPS if step.version < 6) + (broken,))
            with pytest.raises(db.sa.exc.ProgrammingError):
                db.run_migrations()
        assert db.get_schema_version() == 5
        with db.engine.begin() as con:
            assert dict(con.exec_driver_sql("SELECT * FROM findings").fetchone()._mapping) == original_row
            assert db.sa.inspect(con).get_pk_constraint("findings")["constrained_columns"] == ["finding_id"]
            assert not db.sa.inspect(con).has_table("findings_case_scoped")
    assert db.run_migrations()["current_version"] == LATEST_SCHEMA_VERSION
    with db.engine.begin() as con:
        migrated = dict(con.exec_driver_sql("SELECT * FROM findings").fetchone()._mapping)
        assert {key: migrated[key] for key in original_row} == original_row
    db.replace_findings_and_timeline("case-two", [_finding("Independent PostgreSQL case")], [])
    assert db.get_findings("case-one")[0] == original


@pytest.mark.parametrize("backend", ["sqlite", "sqlalchemy"])
def test_api_analysis_of_identical_evidence_in_two_cases_can_be_replayed(tmp_path: Path, backend: str, offline_enrichment: None):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from auto_forensics.api import create_app
    from auto_forensics.config import AppConfig
    from auto_forensics.replay import replay_manifest
    from auto_forensics.security import SecurityPolicy

    data = tmp_path / "data"
    config = AppConfig(
        data_dir=data, cases_dir=data / "cases", db_path=data / "app.db",
        host="127.0.0.1", port=8765, production=False, api_key_hash=None,
        allowed_origins=[], trusted_hosts=["127.0.0.1"], allowed_ingest_roots=[tmp_path],
        rate_limit_per_minute=240, llama_endpoint="http://localhost:11434", llama_model="test",
        security_policy=SecurityPolicy(),
        database_url=f"sqlite:///{tmp_path / 'api-sa.db'}" if backend == "sqlalchemy" else None,
    )
    source = tmp_path / "source"
    source.mkdir()
    (source / "sample.bin").write_bytes(b"MZ powershell synthetic evidence")
    (source / "events.json").write_text(json.dumps([
        {"artifact_id": "reused-id", "timestamp": f"2026-01-01T00:00:0{index}Z", "source": "sysmon",
         "event_type": "process_start", "description": "Repeated synthetic process"}
        for index in range(2)
    ]))
    ids = []
    with TestClient(create_app(config), base_url="http://127.0.0.1") as client:
        for case in ("api-case-one", "api-case-two"):
            assert client.post("/api/cases", json={"case_id": case}).status_code == 200
            assert client.post(f"/api/cases/{case}/ingest", json={"source_dir": str(source)}).status_code == 200
            analyzed = client.post(f"/api/cases/{case}/analyze", json={"enable_llama": False})
            assert analyzed.status_code == 200
            findings = client.get(f"/api/cases/{case}").json()["findings"]
            ids.append([finding["finding_id"] for finding in findings])
            assert len(ids[-1]) == len(set(ids[-1])) == 3
            assert replay_manifest(Path(analyzed.json()["output_manifest"]))["match"] is True
        assert ids[0] == ids[1] and ids[0]
