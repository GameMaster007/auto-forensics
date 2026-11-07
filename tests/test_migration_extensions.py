"""Unknown legacy schema behavior must survive or be explicitly refused."""
from __future__ import annotations

import sqlite3

import pytest

import test_case_scoped_findings as existing
from auto_forensics.db import Database
from auto_forensics.db_sqlalchemy import SQLAlchemyDatabase
from auto_forensics.migrations import SchemaCompatibilityError

database_backend = existing.database_backend


@pytest.mark.parametrize("backend", ["sqlite", "sqlalchemy"])
@pytest.mark.parametrize("customization", ["unique_index", "audit_trigger", "check_constraint", "outgoing_foreign_key"])
def test_sqlite_custom_schema_is_preserved_or_refused(tmp_path, backend, customization):
    path = tmp_path / "legacy.db"
    original_schema = existing.SCHEMA_SQL
    if customization == "check_constraint":
        existing.SCHEMA_SQL = original_schema.replace("confidence REAL NOT NULL,", "confidence REAL NOT NULL CHECK(confidence BETWEEN 0 AND 1),", 1)
    if customization == "outgoing_foreign_key":
        existing.SCHEMA_SQL = original_schema.replace("    PRIMARY KEY(case_id, finding_id),", "    FOREIGN KEY(tactic) REFERENCES external_workers(name),\n    PRIMARY KEY(case_id, finding_id),", 1)
    try:
        # The helper uses FK enforcement. Create the referenced table before its schema.
        if customization == "outgoing_foreign_key":
            with sqlite3.connect(path) as con:
                con.execute("CREATE TABLE external_workers(name TEXT PRIMARY KEY)")
                con.execute("INSERT INTO external_workers VALUES ('execution')")
        existing._legacy_database(path)
    finally:
        existing.SCHEMA_SQL = original_schema
    with sqlite3.connect(path) as con:
        if customization == "unique_index":
            con.execute("CREATE UNIQUE INDEX external_unique_title ON findings(case_id, title)")
        if customization == "audit_trigger":
            con.execute("CREATE TABLE external_audit (finding_id TEXT, title TEXT)")
            con.execute("CREATE TRIGGER external_audit_update AFTER UPDATE ON findings BEGIN INSERT INTO external_audit VALUES (new.finding_id, new.title); END")
            con.execute("UPDATE findings SET title='Before migration'")
            assert con.execute("SELECT COUNT(*) FROM external_audit").fetchone()[0] == 1
        before_objects = con.execute("SELECT type, name, sql FROM sqlite_master WHERE tbl_name='findings' ORDER BY type,name").fetchall()
    db = None
    try:
        db = Database(path) if backend == "sqlite" else SQLAlchemyDatabase(f"sqlite:///{path}")
    except SchemaCompatibilityError:
        with sqlite3.connect(path) as con:
            assert con.execute("SELECT type, name, sql FROM sqlite_master WHERE tbl_name='findings' ORDER BY type,name").fetchall() == before_objects
        return
    finally:
        if isinstance(db, SQLAlchemyDatabase):
            db.engine.dispose()
    with sqlite3.connect(path) as con:
        if customization == "unique_index":
            assert con.execute("SELECT name FROM sqlite_master WHERE name='external_unique_title'").fetchone() is not None
        elif customization == "audit_trigger":
            con.execute("UPDATE findings SET title='After migration'")
            assert con.execute("SELECT COUNT(*) FROM external_audit").fetchone()[0] == 2
        elif customization == "check_constraint":
            with pytest.raises(sqlite3.IntegrityError):
                con.execute("UPDATE findings SET confidence=2")
        else:
            con.execute("PRAGMA foreign_keys=ON")
            with pytest.raises(sqlite3.IntegrityError):
                con.execute("UPDATE findings SET tactic='unregistered'")


@pytest.mark.parametrize("database_backend", ["postgres"], indirect=True)
@pytest.mark.parametrize("customization", ["unique_index", "audit_trigger", "check_constraint", "outgoing_foreign_key"])
def test_postgres_custom_schema_is_preserved_or_refused(database_backend, tmp_path, customization):
    db = database_backend
    existing._cases(db, tmp_path)
    db.replace_findings_and_timeline("case-one", [existing._finding()], [])
    with db.engine.begin() as con:
        constraint = db.sa.inspect(con).get_pk_constraint("findings")["name"]
        quoted = db.engine.dialect.identifier_preparer.quote(constraint)
        con.exec_driver_sql(f"ALTER TABLE findings DROP CONSTRAINT {quoted}")
        con.exec_driver_sql("ALTER TABLE findings ADD PRIMARY KEY (finding_id)")
        con.exec_driver_sql("ALTER TABLE findings DROP COLUMN details_json")
        con.execute(db.schema_migrations.delete().where(db.schema_migrations.c.version >= 6))
        if customization == "unique_index":
            con.exec_driver_sql("CREATE UNIQUE INDEX external_unique_title ON findings(case_id,title)")
        elif customization == "audit_trigger":
            con.exec_driver_sql("CREATE TABLE external_audit (finding_id TEXT,title TEXT)")
            con.exec_driver_sql("CREATE FUNCTION external_audit_fn() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN INSERT INTO external_audit VALUES (NEW.finding_id, NEW.title); RETURN NEW; END $$")
            con.exec_driver_sql("CREATE TRIGGER external_audit_update AFTER UPDATE ON findings FOR EACH ROW EXECUTE FUNCTION external_audit_fn()")
            con.exec_driver_sql("UPDATE findings SET title='Before migration'")
        elif customization == "check_constraint":
            con.exec_driver_sql("ALTER TABLE findings ADD CONSTRAINT external_confidence_check CHECK(confidence BETWEEN 0 AND 1)")
        else:
            con.exec_driver_sql("CREATE TABLE external_workers (name TEXT PRIMARY KEY)")
            con.exec_driver_sql("INSERT INTO external_workers VALUES ('reverse-analysis')")
            con.exec_driver_sql("ALTER TABLE findings ADD CONSTRAINT external_worker_fk FOREIGN KEY(worker) REFERENCES external_workers(name)")
    try:
        db.run_migrations()
    except SchemaCompatibilityError:
        assert db.get_schema_version() == 5
        return
    with db.engine.begin() as con:
        inspector = db.sa.inspect(con)
        if customization == "unique_index":
            assert any(index["name"] == "external_unique_title" for index in inspector.get_indexes("findings"))
        elif customization == "audit_trigger":
            con.exec_driver_sql("UPDATE findings SET title='After migration'")
            assert con.exec_driver_sql("SELECT COUNT(*) FROM external_audit").scalar_one() == 2
        elif customization == "check_constraint":
            assert any(check["name"] == "external_confidence_check" for check in inspector.get_check_constraints("findings"))
        else:
            assert any(fk["name"] == "external_worker_fk" for fk in inspector.get_foreign_keys("findings"))


@pytest.mark.parametrize("backend", ["sqlite", "sqlalchemy"])
def test_custom_column_collation_is_preserved_or_refused(tmp_path, backend):
    path = tmp_path / "legacy.db"
    original = existing.SCHEMA_SQL
    existing.SCHEMA_SQL = original.replace("title TEXT NOT NULL,", "title TEXT NOT NULL COLLATE NOCASE,", 1)
    try:
        existing._legacy_database(path)
    finally:
        existing.SCHEMA_SQL = original
    query = "SELECT COUNT(*) FROM findings WHERE title='preserve this finding'"
    with sqlite3.connect(path) as con:
        assert con.execute(query).fetchone()[0] == 1
    db = None
    try:
        db = Database(path) if backend == "sqlite" else SQLAlchemyDatabase(f"sqlite:///{path}")
    except SchemaCompatibilityError:
        return
    finally:
        if isinstance(db, SQLAlchemyDatabase):
            db.engine.dispose()
    with sqlite3.connect(path) as con:
        assert con.execute(query).fetchone()[0] == 1


@pytest.mark.parametrize("database_backend", ["postgres"], indirect=True)
@pytest.mark.parametrize("customization", ["audit_rule", "row_security", "column_annotation"])
def test_additional_pg_schema_objects_are_preserved_or_refused(database_backend, tmp_path, customization):
    db = database_backend
    existing._cases(db, tmp_path)
    db.replace_findings_and_timeline("case-one", [existing._finding()], [])
    with db.engine.begin() as con:
        constraint = db.sa.inspect(con).get_pk_constraint("findings")["name"]
        quoted = db.engine.dialect.identifier_preparer.quote(constraint)
        con.exec_driver_sql(f"ALTER TABLE findings DROP CONSTRAINT {quoted}")
        con.exec_driver_sql("ALTER TABLE findings ADD PRIMARY KEY (finding_id)")
        con.exec_driver_sql("ALTER TABLE findings DROP COLUMN details_json")
        con.execute(db.schema_migrations.delete().where(db.schema_migrations.c.version >= 6))
        if customization == "audit_rule":
            con.exec_driver_sql("CREATE TABLE external_audit (finding_id TEXT,title TEXT)")
            con.exec_driver_sql("CREATE RULE external_audit_update AS ON UPDATE TO findings DO ALSO INSERT INTO external_audit VALUES (NEW.finding_id, NEW.title)")
            con.exec_driver_sql("UPDATE findings SET title='Before migration'")
            assert con.exec_driver_sql("SELECT COUNT(*) FROM external_audit").scalar_one() == 1
        elif customization == "row_security":
            con.exec_driver_sql("ALTER TABLE findings ENABLE ROW LEVEL SECURITY")
            con.exec_driver_sql("CREATE POLICY external_case_scope ON findings USING (case_id='case-one')")
        else:
            con.exec_driver_sql("COMMENT ON COLUMN findings.evidence_json IS 'Retain original evidence annotation'")
    try:
        db.run_migrations()
    except SchemaCompatibilityError:
        assert db.get_schema_version() == 5
        return
    with db.engine.begin() as con:
        if customization == "audit_rule":
            con.exec_driver_sql("UPDATE findings SET title='After migration'")
            assert con.exec_driver_sql("SELECT COUNT(*) FROM external_audit").scalar_one() == 2
        elif customization == "row_security":
            assert con.exec_driver_sql("SELECT relrowsecurity FROM pg_class WHERE oid='findings'::regclass").scalar_one() is True
            assert con.exec_driver_sql("SELECT COUNT(*) FROM pg_policy WHERE polrelid='findings'::regclass").scalar_one() == 1
        else:
            columns = db.sa.inspect(con).get_columns("findings")
            assert next(c for c in columns if c["name"] == "evidence_json")["comment"] == "Retain original evidence annotation"


@pytest.mark.parametrize("field", ["evidence_json", "citations_json", "details_json"])
@pytest.mark.parametrize("raw", ["[" * 10000 + "0" + "]" * 10000, "1" * 5000], ids=["deep-nesting", "oversized-integer"])
def test_malformed_finding_json_does_not_hide_remaining_findings(database_backend, tmp_path, field, raw):
    db = database_backend
    existing._cases(db, tmp_path)
    db.replace_findings_and_timeline("case-one", [existing._finding()], [])
    if isinstance(db, Database):
        with db.connect() as con:
            con.execute(f"UPDATE findings SET {field}=?", (raw,))
    else:
        with db.engine.begin() as con:
            con.execute(db.findings.update().values(**{field: raw}))
    rows = db.get_findings("case-one")
    assert len(rows) == 1


@pytest.mark.parametrize("database_backend", ["postgres"], indirect=True)
@pytest.mark.parametrize("target", ["artifacts", "evidence_hash_log", "audit_log"])
def test_postgres_real_statement_failure_rolls_back_import(database_backend, tmp_path, target):
    from test_archive_integrity import _archive, _row, _service
    service = _service(tmp_path)
    db = database_backend
    service.db = db
    payload = b"Imported disposable PostgreSQL evidence"
    archive = _archive(service, tmp_path / "import.zip", [_row("evidence/note.txt", payload)], [("evidence/note.txt", payload)])
    with db.engine.begin() as con:
        con.exec_driver_sql(f"ALTER TABLE {target} ADD CONSTRAINT reject_import CHECK(case_id <> 'archive-case')")
    try:
        with pytest.raises(db.sa.exc.IntegrityError):
            service.import_case_archive(archive)
        assert db.get_case("archive-case") is None
        assert db.get_artifacts("archive-case") == []
        assert db.get_evidence_hash_log("archive-case") == []
        assert db.get_audit_log("archive-case") == []
        assert not (service.config.cases_dir / "archive-case").exists()
    finally:
        with db.engine.begin() as con:
            con.exec_driver_sql(f"ALTER TABLE {target} DROP CONSTRAINT reject_import")
    service.import_case_archive(archive)
    assert service.check_case_integrity("archive-case")["match"] is True


@pytest.mark.parametrize("database_backend", ["postgres"], indirect=True)
def test_postgres_commit_and_recovery_read_failure_preserves_files(database_backend, tmp_path, monkeypatch):
    from auto_forensics.security import SecurityError
    from test_archive_integrity import _archive, _row, _service
    service = _service(tmp_path)
    db = database_backend
    service.db = db
    payload = b"Evidence after uncertain acknowledgement"
    archive = _archive(service, tmp_path / "import.zip", [_row("evidence/note.txt", payload)], [("evidence/note.txt", payload)])
    original_import = db.import_case_records
    original_get = db.get_case
    read_calls = 0
    def commit_then_raise(*args, **kwargs):
        original_import(*args, **kwargs)
        raise RuntimeError("lost commit acknowledgement")
    def get_case(case_id):
        nonlocal read_calls
        read_calls += 1
        if read_calls > 1:
            raise RuntimeError("recovery read unavailable")
        return original_get(case_id)
    with monkeypatch.context() as patch:
        patch.setattr(db, "import_case_records", commit_then_raise)
        patch.setattr(db, "get_case", get_case)
        with pytest.raises(SecurityError, match="uncertain"):
            service.import_case_archive(archive)
    assert (service.config.cases_dir / "archive-case/evidence/note.txt").read_bytes() == payload
    assert service.check_case_integrity("archive-case")["match"] is True
