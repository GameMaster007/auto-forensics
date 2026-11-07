"""Noncanonical column metadata must not be silently converted by rebuild."""
import sqlite3

import pytest

import test_case_scoped_findings as existing
from auto_forensics.db import Database
from auto_forensics.db_sqlalchemy import SQLAlchemyDatabase
from auto_forensics.migrations import SchemaCompatibilityError

database_backend = existing.database_backend
PRECISE = "0.123456789012345678901234567890"


@pytest.mark.parametrize("backend", ["sqlite", "sqlalchemy"])
def test_noncanonical_sqlite_confidence_type_preserves_exact_data_or_refuses(tmp_path, backend):
    path = tmp_path / "noncanonical.db"
    canonical = existing.SCHEMA_SQL
    existing.SCHEMA_SQL = canonical.replace("confidence REAL NOT NULL,", "confidence TEXT NOT NULL,", 1)
    try:
        existing._legacy_database(path)
    finally:
        existing.SCHEMA_SQL = canonical
    with sqlite3.connect(path) as con:
        con.execute("UPDATE findings SET confidence=?", (PRECISE,))
        before = con.execute("SELECT confidence,typeof(confidence) FROM findings").fetchone()
    assert before == (PRECISE, "text")
    db = None
    try:
        db = Database(path) if backend == "sqlite" else SQLAlchemyDatabase(f"sqlite:///{path}")
    except SchemaCompatibilityError:
        with sqlite3.connect(path) as con:
            assert con.execute("SELECT confidence,typeof(confidence) FROM findings").fetchone() == before
        return
    finally:
        if isinstance(db, SQLAlchemyDatabase):
            db.engine.dispose()
    with sqlite3.connect(path) as con:
        assert con.execute("SELECT confidence,typeof(confidence) FROM findings").fetchone() == before


def make_pg_legacy(db, root):
    existing._cases(db, root)
    db.replace_findings_and_timeline("case-one", [existing._finding()], [])
    with db.engine.begin() as con:
        constraint = db.sa.inspect(con).get_pk_constraint("findings")["name"]
        quoted = db.engine.dialect.identifier_preparer.quote(constraint)
        con.exec_driver_sql(f"ALTER TABLE findings DROP CONSTRAINT {quoted}")
        con.exec_driver_sql("ALTER TABLE findings ADD PRIMARY KEY (finding_id)")
        con.exec_driver_sql("ALTER TABLE findings DROP COLUMN details_json")
        con.execute(db.schema_migrations.delete().where(db.schema_migrations.c.version >= 6))


@pytest.mark.parametrize("database_backend", ["postgres"], indirect=True)
def test_noncanonical_postgres_numeric_precision_is_preserved_or_refused(database_backend, tmp_path):
    db = database_backend
    make_pg_legacy(db, tmp_path)
    with db.engine.begin() as con:
        con.exec_driver_sql("ALTER TABLE findings ALTER COLUMN confidence TYPE NUMERIC(40,30)")
        con.exec_driver_sql("UPDATE findings SET confidence=" + PRECISE)
        assert con.exec_driver_sql("SELECT confidence::text FROM findings").scalar_one() == PRECISE
    try:
        db.run_migrations()
    except SchemaCompatibilityError:
        with db.engine.begin() as con:
            assert con.exec_driver_sql("SELECT confidence::text FROM findings").scalar_one() == PRECISE
        return
    with db.engine.begin() as con:
        assert con.exec_driver_sql("SELECT confidence::text FROM findings").scalar_one() == PRECISE


@pytest.mark.parametrize("database_backend", ["postgres"], indirect=True)
def test_postgres_domain_constraint_is_preserved_or_refused(database_backend, tmp_path):
    db = database_backend
    make_pg_legacy(db, tmp_path)
    with db.engine.begin() as con:
        con.exec_driver_sql("CREATE DOMAIN forensic_confidence AS DOUBLE PRECISION CHECK(VALUE BETWEEN 0 AND 1)")
        con.exec_driver_sql("ALTER TABLE findings ALTER COLUMN confidence TYPE forensic_confidence")
    try:
        db.run_migrations()
    except SchemaCompatibilityError:
        return
    with db.engine.begin() as con:
        with pytest.raises(db.sa.exc.IntegrityError):
            con.exec_driver_sql("UPDATE findings SET confidence=2")


@pytest.mark.parametrize("backend", ["sqlite", "sqlalchemy"])
@pytest.mark.parametrize("customization", ["nullable", "default", "hidden"])
def test_sqlite_unknown_column_attributes_are_refused_transactionally(tmp_path, backend, customization):
    path = tmp_path / "custom-attributes.db"
    original = existing.SCHEMA_SQL
    replacements = {
        "nullable": ("title TEXT NOT NULL,", "title TEXT,"),
        "default": ("title TEXT NOT NULL,", "title TEXT NOT NULL DEFAULT 'custom',"),
        "hidden": ("title TEXT NOT NULL,", "title TEXT NOT NULL, hidden_title TEXT GENERATED ALWAYS AS (title) VIRTUAL,"),
    }
    old, new = replacements[customization]
    existing.SCHEMA_SQL = original.replace(old, new, 1)
    try:
        existing._legacy_database(path)
    finally:
        existing.SCHEMA_SQL = original
    with sqlite3.connect(path) as con:
        before = con.execute("SELECT sql FROM sqlite_master WHERE name='findings'").fetchone()
    with pytest.raises(SchemaCompatibilityError):
        if backend == "sqlite":
            Database(path)
        else:
            SQLAlchemyDatabase(f"sqlite:///{path}")
    with sqlite3.connect(path) as con:
        assert con.execute("SELECT sql FROM sqlite_master WHERE name='findings'").fetchone() == before
        assert con.execute("PRAGMA user_version").fetchone()[0] == 5


@pytest.mark.parametrize("database_backend", ["postgres"], indirect=True)
def test_canonical_column_types_and_defaults_survive_the_key_migration(database_backend, tmp_path):
    db = database_backend
    make_pg_legacy(db, tmp_path)
    with db.engine.begin() as con:
        before = db.sa.inspect(con).get_columns("findings")
    db.run_migrations()
    with db.engine.begin() as con:
        after = {column["name"]: column for column in db.sa.inspect(con).get_columns("findings")}
        for column in before:
            result = after[column["name"]]
            assert str(result["type"]) == str(column["type"])
            assert result["nullable"] == column["nullable"]
            assert result["default"] == column["default"]


@pytest.mark.parametrize("backend", ["sqlite", "sqlalchemy"])
def test_known_sqlalchemy_sqlite_column_variants_survive_rebuild(tmp_path, backend):
    path = tmp_path / "sqlalchemy-legacy.db"
    original = existing.SCHEMA_SQL
    modified = original.replace("confidence REAL NOT NULL,", "confidence FLOAT NOT NULL,", 1)
    for name, length in (("finding_id", 128), ("case_id", 128), ("severity", 32), ("tactic", 128)):
        # Only the findings declaration changes; the native fixture's ID rewrite
        # still needs its expected finding_id declaration.
        if name != "finding_id":
            start = modified.index("CREATE TABLE IF NOT EXISTS findings")
            prefix, body = modified[:start], modified[start:]
            modified = prefix + body.replace(f"{name} TEXT NOT NULL,", f"{name} VARCHAR({length}) NOT NULL,", 1)
    existing.SCHEMA_SQL = modified
    try:
        existing._legacy_database(path)
    finally:
        existing.SCHEMA_SQL = original
    with sqlite3.connect(path) as con:
        before = {row[1]: (row[2], row[4]) for row in con.execute("PRAGMA table_info(findings)")}
    db = Database(path) if backend == "sqlite" else SQLAlchemyDatabase(f"sqlite:///{path}")
    try:
        with sqlite3.connect(path) as con:
            after = {row[1]: (row[2], row[4]) for row in con.execute("PRAGMA table_info(findings)")}
        assert all(after[name] == metadata for name, metadata in before.items())
    finally:
        if isinstance(db, SQLAlchemyDatabase):
            db.engine.dispose()
