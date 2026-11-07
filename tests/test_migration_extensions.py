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
