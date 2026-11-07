from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .migrations import (
    LATEST_SCHEMA_VERSION,
    MIGRATION_STEPS,
    SchemaVersionError,
    added_column,
    validate_finding_rebuild,
)
from .models import (
    IOC,
    Finding,
    IOCEnrichment,
    TimelineEvent,
    citations_as_json,
    decode_finding_row,
    decode_json_object,
    finding_details_as_json,
    utc_now_iso,
)
from .timeline import timeline_sort_key


class SQLAlchemyDatabase:
    def __init__(
        self,
        database_url: str,
        pool_size: int = 5,
        max_overflow: int = 10,
        pool_timeout_seconds: int = 30,
        pool_recycle_seconds: int = 1800,
    ):
        try:
            import sqlalchemy as sa  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(
                "SQLAlchemy is required for DATABASE_URL backends. "
                "Install with: pip install -e .[db]"
            ) from exc

        self.sa = sa
        engine_kwargs: dict[str, Any] = {
            "future": True,
            "pool_pre_ping": True,
        }
        if database_url.startswith("sqlite"):
            engine_kwargs["connect_args"] = {"check_same_thread": False}
        else:
            engine_kwargs["pool_size"] = max(1, int(pool_size))
            engine_kwargs["max_overflow"] = max(0, int(max_overflow))
            engine_kwargs["pool_timeout"] = max(1, int(pool_timeout_seconds))
            engine_kwargs["pool_recycle"] = max(60, int(pool_recycle_seconds))
        self.engine = sa.create_engine(database_url, **engine_kwargs)
        if self.engine.dialect.name == "sqlite":
            @sa.event.listens_for(self.engine, "connect")
            def enable_foreign_keys(connection: Any, record: Any) -> None:
                del record
                cursor = connection.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.close()
        md = sa.MetaData()

        self.cases = sa.Table(
            "cases",
            md,
            sa.Column("case_id", sa.String(128), primary_key=True),
            sa.Column("created_at", sa.Text, nullable=False),
            sa.Column("updated_at", sa.Text, nullable=False),
            sa.Column("status", sa.String(64), nullable=False),
            sa.Column("evidence_dir", sa.Text, nullable=False),
            sa.Column("output_dir", sa.Text, nullable=False),
            sa.Column("last_error", sa.Text, nullable=True),
        )

        self.artifacts = sa.Table(
            "artifacts",
            md,
            sa.Column("artifact_pk", sa.Integer, primary_key=True, autoincrement=True),
            sa.Column("case_id", sa.String(128), sa.ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False),
            sa.Column("rel_path", sa.Text, nullable=False),
            sa.Column("artifact_type", sa.String(64), nullable=False),
            sa.Column("size_bytes", sa.Integer, nullable=False),
            sa.Column("sha256", sa.String(128), nullable=False),
            sa.Column("ingested_at", sa.Text, nullable=False),
            sa.Column("metadata_json", sa.Text, nullable=False),
        )

        self.findings = sa.Table(
            "findings",
            md,
            sa.Column("finding_id", sa.String(128), nullable=False),
            sa.Column("case_id", sa.String(128), sa.ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False),
            sa.Column("title", sa.Text, nullable=False),
            sa.Column("severity", sa.String(32), nullable=False),
            sa.Column("confidence", sa.Float, nullable=False),
            sa.Column("tactic", sa.String(128), nullable=False),
            sa.Column("evidence_json", sa.Text, nullable=False),
            sa.Column("recommendation", sa.Text, nullable=False),
            sa.Column("created_at", sa.Text, nullable=False),
            sa.Column("citations_json", sa.Text, nullable=False, server_default=sa.text("'[]'")),
            sa.Column("origin", sa.String(32), nullable=False, server_default=sa.text("'detector'")),
            sa.Column("review_status", sa.String(32), nullable=False, server_default=sa.text("'unverified'")),
            sa.Column("worker", sa.String(64), nullable=False, server_default=sa.text("'pipeline'")),
            sa.Column("details_json", sa.Text, nullable=False, server_default=sa.text("'{}'")),
            sa.PrimaryKeyConstraint("case_id", "finding_id"),
        )

        self.timeline = sa.Table(
            "timeline",
            md,
            sa.Column("timeline_pk", sa.Integer, primary_key=True, autoincrement=True),
            sa.Column("case_id", sa.String(128), sa.ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False),
            sa.Column("timestamp", sa.Text, nullable=True),
            sa.Column("source", sa.Text, nullable=False),
            sa.Column("event_type", sa.Text, nullable=False),
            sa.Column("description", sa.Text, nullable=False),
            sa.Column("risk_score", sa.Float, nullable=False),
            sa.Column("tags_json", sa.Text, nullable=False),
            sa.Column("related_json", sa.Text, nullable=False),
            sa.Column("created_at", sa.Text, nullable=False),
        )

        self.case_iocs = sa.Table(
            "case_iocs",
            md,
            sa.Column("ioc_pk", sa.Integer, primary_key=True, autoincrement=True),
            sa.Column("case_id", sa.String(128), sa.ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False),
            sa.Column("ioc_id", sa.String(128), nullable=False),
            sa.Column("ioc_type", sa.String(64), nullable=False),
            sa.Column("value", sa.Text, nullable=False),
            sa.Column("first_seen", sa.Text, nullable=True),
            sa.Column("last_seen", sa.Text, nullable=True),
            sa.Column("sources_json", sa.Text, nullable=False),
            sa.Column("metadata_json", sa.Text, nullable=False),
            sa.Column("created_at", sa.Text, nullable=False),
        )

        self.ioc_enrichment_cache = sa.Table(
            "ioc_enrichment_cache",
            md,
            sa.Column("cache_pk", sa.Integer, primary_key=True, autoincrement=True),
            sa.Column("ioc_type", sa.String(64), nullable=False),
            sa.Column("value", sa.Text, nullable=False),
            sa.Column("provider", sa.String(64), nullable=False),
            sa.Column("verdict", sa.String(64), nullable=False),
            sa.Column("confidence", sa.Float, nullable=False),
            sa.Column("details_json", sa.Text, nullable=False),
            sa.Column("fetched_at", sa.Text, nullable=False),
            sa.UniqueConstraint("ioc_type", "value", "provider", name="uq_ioc_cache"),
        )

        self.analyst_notes = sa.Table(
            "analyst_notes",
            md,
            sa.Column("note_pk", sa.Integer, primary_key=True, autoincrement=True),
            sa.Column("case_id", sa.String(128), sa.ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False),
            sa.Column("note_id", sa.String(64), nullable=False),
            sa.Column("author", sa.String(128), nullable=False),
            sa.Column("content", sa.Text, nullable=False),
            sa.Column("created_at", sa.Text, nullable=False),
        )

        self.evidence_hash_log = sa.Table(
            "evidence_hash_log",
            md,
            sa.Column("hash_pk", sa.Integer, primary_key=True, autoincrement=True),
            sa.Column("case_id", sa.String(128), sa.ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False),
            sa.Column("rel_path", sa.Text, nullable=False),
            sa.Column("sha256", sa.String(128), nullable=False),
            sa.Column("size_bytes", sa.Integer, nullable=False),
            sa.Column("logged_at", sa.Text, nullable=False),
        )

        self.audit_log = sa.Table(
            "audit_log",
            md,
            sa.Column("audit_pk", sa.Integer, primary_key=True, autoincrement=True),
            sa.Column("case_id", sa.String(128), nullable=True),
            sa.Column("action", sa.String(128), nullable=False),
            sa.Column("actor", sa.String(128), nullable=False),
            sa.Column("details_json", sa.Text, nullable=False),
            sa.Column("created_at", sa.Text, nullable=False),
        )

        self.schema_migrations = sa.Table(
            "schema_migrations",
            md,
            sa.Column("version", sa.Integer, primary_key=True),
            sa.Column("name", sa.String(255), nullable=False),
            sa.Column("applied_at", sa.Text, nullable=False),
        )

        self.analysis_jobs = sa.Table(
            "analysis_jobs",
            md,
            sa.Column("job_id", sa.String(128), primary_key=True),
            sa.Column("case_id", sa.String(128), sa.ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False),
            sa.Column("job_type", sa.String(64), nullable=False, default="analysis"),
            sa.Column("state", sa.String(64), nullable=False),
            sa.Column("progress", sa.Integer, nullable=False, default=0),
            sa.Column("message", sa.Text, nullable=False, default=""),
            sa.Column("error", sa.Text, nullable=True),
            sa.Column("result_json", sa.Text, nullable=True),
            sa.Column("created_at", sa.Text, nullable=False),
            sa.Column("updated_at", sa.Text, nullable=False),
        )

        try:
            with self.engine.begin() as con:
                self._lock_schema(con)
                md.create_all(con)
                self._run_migrations(con)
        except Exception:
            self.engine.dispose()
            raise

    def _rows(self, result: Any) -> list[dict[str, Any]]:
        return [dict(row._mapping) for row in result]

    def get_schema_version(self) -> int:
        stmt = self.sa.select(self.sa.func.max(self.schema_migrations.c.version))
        with self.engine.begin() as con:
            value = con.execute(stmt).scalar_one_or_none()
        return int(value or 0)

    def list_schema_migrations(self) -> list[dict[str, Any]]:
        stmt = (
            self.sa.select(
                self.schema_migrations.c.version,
                self.schema_migrations.c.name,
                self.schema_migrations.c.applied_at,
            )
            .order_by(self.schema_migrations.c.version.asc())
        )
        with self.engine.begin() as con:
            return self._rows(con.execute(stmt))

    def _lock_schema(self, con: Any) -> None:
        if self.engine.dialect.name == "sqlite":
            con.exec_driver_sql("BEGIN IMMEDIATE")
        elif self.engine.dialect.name == "postgresql":
            # One transaction-scoped application lock per database prevents
            # concurrent workers from applying the same schema migration.
            con.exec_driver_sql("SELECT pg_advisory_xact_lock(4707763809633354309)")

    def run_migrations(self) -> dict[str, Any]:
        with self.engine.begin() as con:
            self._lock_schema(con)
            return self._run_migrations(con)

    def _run_migrations(self, con: Any) -> dict[str, Any]:
        current = int(con.execute(self.sa.select(self.sa.func.max(self.schema_migrations.c.version))).scalar_one_or_none() or 0)
        if self.engine.dialect.name == "sqlite":
            current = max(current, int(con.exec_driver_sql("PRAGMA user_version").scalar_one()))
        if current > LATEST_SCHEMA_VERSION:
            raise SchemaVersionError("Database schema is newer than this program; refusing a downgrade")
        applied: list[dict[str, Any]] = []
        for step in MIGRATION_STEPS:
            if step.version <= current:
                continue
            primary_key = set(self.sa.inspect(con).get_pk_constraint("findings")["constrained_columns"])
            statements = () if step.name == "scope_finding_ids_to_case" and primary_key == {"case_id", "finding_id"} else step.sql_statements
            if step.name == "scope_finding_ids_to_case" and statements:
                inspector = self.sa.inspect(con)
                incoming = any(
                    foreign_key.get("referred_table", "").lower() == "findings"
                    for table in inspector.get_table_names()
                    for foreign_key in inspector.get_foreign_keys(table)
                )
                if self.engine.dialect.name == "sqlite":
                    triggers = con.exec_driver_sql("SELECT 1 FROM sqlite_master WHERE type='trigger' AND tbl_name='findings'").first()
                    table_sql = con.exec_driver_sql("SELECT sql FROM sqlite_master WHERE type='table' AND name='findings'").scalar_one()
                    custom_metadata = bool(re.search(r"\bCOLLATE\b", table_sql, re.IGNORECASE))
                else:
                    triggers = con.exec_driver_sql(
                        "SELECT 1 FROM information_schema.triggers WHERE event_object_table='findings' AND event_object_schema=current_schema()"
                    ).first()
                    # Dropping/recreating a PostgreSQL relation also discards
                    # row policies, rules, grants, annotations and column
                    # collations that ordinary reflection does not expose.
                    custom_metadata = bool(con.exec_driver_sql("""
                        SELECT c.relrowsecurity OR c.relforcerowsecurity OR c.relacl IS NOT NULL
                            OR c.reloptions IS NOT NULL OR c.relkind <> 'r' OR c.relispartition
                            OR pg_get_userbyid(c.relowner) <> current_user
                            OR EXISTS (SELECT 1 FROM pg_policy WHERE polrelid=c.oid)
                            OR EXISTS (SELECT 1 FROM pg_rewrite WHERE ev_class=c.oid)
                            OR EXISTS (SELECT 1 FROM pg_description WHERE objoid=c.oid AND classoid='pg_class'::regclass)
                            OR EXISTS (SELECT 1 FROM pg_seclabel WHERE objoid=c.oid AND classoid='pg_class'::regclass)
                            OR EXISTS (
                                SELECT 1 FROM pg_attribute a JOIN pg_type t ON t.oid=a.atttypid
                                WHERE a.attrelid=c.oid AND a.attnum > 0 AND NOT a.attisdropped
                                  AND (a.attcollation <> t.typcollation OR a.attidentity <> '' OR a.attgenerated <> ''
                                       OR a.attoptions IS NOT NULL OR a.attfdwoptions IS NOT NULL)
                            )
                        FROM pg_class c WHERE c.oid='findings'::regclass
                    """).scalar_one())
                foreign_keys = inspector.get_foreign_keys("findings")
                extra_schema = bool(inspector.get_check_constraints("findings") or inspector.get_unique_constraints("findings") or triggers or custom_metadata)
                extra_schema = extra_schema or any(
                    key.get("referred_schema") not in {None, inspector.default_schema_name} for key in foreign_keys
                )
                validate_finding_rebuild(
                    {item["name"] for item in inspector.get_columns("findings")}, incoming_references=incoming,
                    indexes=inspector.get_indexes("findings"), foreign_keys=foreign_keys, extra_constraints=extra_schema,
                )
            for statement in statements:
                column = added_column(statement)
                if column and column[1] in {item["name"] for item in self.sa.inspect(con).get_columns(column[0])}:
                    continue
                con.exec_driver_sql(statement)
            applied_at = utc_now_iso()
            con.execute(
                self.schema_migrations.insert().values(
                    version=step.version,
                    name=step.name,
                    applied_at=applied_at,
                )
            )
            current = step.version
            applied.append({"version": step.version, "name": step.name, "applied_at": applied_at})

        if current >= 6 and set(self.sa.inspect(con).get_pk_constraint("findings")["constrained_columns"]) != {"case_id", "finding_id"}:
            raise RuntimeError("Finding key schema disagrees with the recorded migration version")
        if self.engine.dialect.name == "sqlite":
            con.exec_driver_sql(f"PRAGMA user_version = {current}")
        return {
            "current_version": current,
            "latest_version": LATEST_SCHEMA_VERSION,
            "applied": applied,
        }

    def create_case(self, case_id: str, evidence_dir: Path, output_dir: Path) -> None:
        now = utc_now_iso()
        with self.engine.begin() as con:
            con.execute(
                self.cases.insert().values(
                    case_id=case_id,
                    created_at=now,
                    updated_at=now,
                    status="created",
                    evidence_dir=str(evidence_dir),
                    output_dir=str(output_dir),
                    last_error=None,
                )
            )

    def import_case_records(
        self, case_id: str, evidence_dir: Path, output_dir: Path,
        artifacts: list[dict[str, Any]], provenance: dict[str, Any],
    ) -> None:
        """Commit the imported identity, custody baseline, and audit together."""
        now = utc_now_iso()
        with self.engine.begin() as con:
            con.execute(self.cases.insert().values(
                case_id=case_id, created_at=now, updated_at=now, status="ready",
                evidence_dir=str(evidence_dir), output_dir=str(output_dir), last_error=None,
            ))
            self._write_artifact_custody(con, case_id, artifacts, now)
            con.execute(self.audit_log.insert().values(
                case_id=case_id, action="case_imported", actor="system", details_json=json.dumps(provenance), created_at=now,
            ))

    def _write_artifact_custody(self, con: Any, case_id: str, artifacts: list[dict[str, Any]], now: str) -> None:
        con.execute(self.artifacts.delete().where(self.artifacts.c.case_id == case_id))
        if artifacts:
            con.execute(self.artifacts.insert(), [{
                "case_id": case_id, "rel_path": item["rel_path"], "artifact_type": item["artifact_type"],
                "size_bytes": item["size_bytes"], "sha256": item["sha256"], "ingested_at": now,
                "metadata_json": json.dumps(item.get("metadata", {})),
            } for item in artifacts])
            con.execute(self.evidence_hash_log.insert(), [{
                "case_id": case_id, "rel_path": item["rel_path"], "sha256": item["sha256"],
                "size_bytes": item["size_bytes"], "logged_at": now,
            } for item in artifacts])

    def ingest_case_records(self, case_id: str, artifacts: list[dict[str, Any]], provenance: dict[str, Any]) -> None:
        now = utc_now_iso()
        with self.engine.begin() as con:
            result = con.execute(self.cases.update().where(self.cases.c.case_id == case_id).values(
                status="ready", last_error=None, updated_at=now,
            ))
            if result.rowcount != 1:
                raise ValueError("Case disappeared before ingest persistence")
            self._write_artifact_custody(con, case_id, artifacts, now)
            con.execute(self.audit_log.insert().values(
                case_id=case_id, action="case_ingested", actor="system", details_json=json.dumps(provenance), created_at=now,
            ))

    def list_cases(self) -> list[dict[str, Any]]:
        stmt = self.sa.select(self.cases).order_by(self.cases.c.updated_at.desc())
        with self.engine.begin() as con:
            rows = con.execute(stmt)
            return self._rows(rows)

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        stmt = self.sa.select(self.cases).where(self.cases.c.case_id == case_id)
        with self.engine.begin() as con:
            row = con.execute(stmt).first()
        return dict(row._mapping) if row else None

    def set_case_status(self, case_id: str, status: str, last_error: str | None = None) -> None:
        now = utc_now_iso()
        stmt = (
            self.cases.update()
            .where(self.cases.c.case_id == case_id)
            .values(status=status, updated_at=now, last_error=last_error)
        )
        with self.engine.begin() as con:
            con.execute(stmt)

    def replace_artifacts(self, case_id: str, artifacts: list[dict[str, Any]]) -> None:
        now = utc_now_iso()
        with self.engine.begin() as con:
            con.execute(self.artifacts.delete().where(self.artifacts.c.case_id == case_id))
            if artifacts:
                con.execute(
                    self.artifacts.insert(),
                    [
                        {
                            "case_id": case_id,
                            "rel_path": str(item["rel_path"]),
                            "artifact_type": str(item["artifact_type"]),
                            "size_bytes": int(item["size_bytes"]),
                            "sha256": str(item["sha256"]),
                            "ingested_at": now,
                            "metadata_json": json.dumps(item.get("metadata", {})),
                        }
                        for item in artifacts
                    ],
                )

    def replace_findings_and_timeline(
        self, case_id: str, findings: list[Finding], timeline: list[TimelineEvent]
    ) -> None:
        now = utc_now_iso()
        with self.engine.begin() as con:
            con.execute(self.findings.delete().where(self.findings.c.case_id == case_id))
            con.execute(self.timeline.delete().where(self.timeline.c.case_id == case_id))

            if findings:
                con.execute(
                    self.findings.insert(),
                    [
                        {
                            "finding_id": f.finding_id,
                            "case_id": case_id,
                            "title": f.title,
                            "severity": f.severity,
                            "confidence": f.confidence,
                            "tactic": f.tactic,
                            "evidence_json": json.dumps(f.evidence),
                            "recommendation": f.recommendation,
                            "created_at": now,
                            "citations_json": citations_as_json(f.citations),
                            "origin": f.origin,
                            "review_status": f.review_status,
                            "worker": f.worker,
                            "details_json": finding_details_as_json(f),
                        }
                        for f in findings
                    ],
                )

            if timeline:
                con.execute(
                    self.timeline.insert(),
                    [
                        {
                            "case_id": case_id,
                            "timestamp": t.timestamp,
                            "source": t.source,
                            "event_type": t.event_type,
                            "description": t.description,
                            "risk_score": t.risk_score,
                            "tags_json": json.dumps(t.tags),
                            "related_json": json.dumps(t.related),
                            "created_at": now,
                        }
                        for t in timeline
                    ],
                )

    def get_artifacts(self, case_id: str) -> list[dict[str, Any]]:
        stmt = (
            self.sa.select(
                self.artifacts.c.rel_path,
                self.artifacts.c.artifact_type,
                self.artifacts.c.size_bytes,
                self.artifacts.c.sha256,
                self.artifacts.c.metadata_json,
            )
            .where(self.artifacts.c.case_id == case_id)
            .order_by(self.artifacts.c.artifact_pk.asc())
        )
        with self.engine.begin() as con:
            rows = self._rows(con.execute(stmt))
        out: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["metadata"] = decode_json_object(item.pop("metadata_json"))
            out.append(item)
        return out

    def get_findings(self, case_id: str) -> list[dict[str, Any]]:
        stmt = (
            self.sa.select(
                self.findings.c.finding_id,
                self.findings.c.title,
                self.findings.c.severity,
                self.findings.c.confidence,
                self.findings.c.tactic,
                self.findings.c.evidence_json,
                self.findings.c.recommendation,
                self.findings.c.created_at,
                self.findings.c.citations_json,
                self.findings.c.origin,
                self.findings.c.review_status,
                self.findings.c.worker,
                self.findings.c.details_json,
            )
            .where(self.findings.c.case_id == case_id)
            .order_by(self.findings.c.created_at.desc())
        )
        with self.engine.begin() as con:
            rows = self._rows(con.execute(stmt))
        return [decode_finding_row(row) for row in rows]

    def update_finding_reviews(self, case_id: str, findings: list[Finding]) -> None:
        with self.engine.begin() as con:
            for finding in findings:
                result = con.execute(
                    self.findings.update().where(
                        (self.findings.c.case_id == case_id) & (self.findings.c.finding_id == finding.finding_id)
                    ).values(review_status=finding.review_status, details_json=finding_details_as_json(finding))
                )
                if result.rowcount != 1:
                    raise ValueError("A reviewed finding is not indexed in this case")

    def get_timeline(self, case_id: str) -> list[dict[str, Any]]:
        stmt = (
            self.sa.select(
                self.timeline.c.timestamp,
                self.timeline.c.source,
                self.timeline.c.event_type,
                self.timeline.c.description,
                self.timeline.c.risk_score,
                self.timeline.c.tags_json,
                self.timeline.c.related_json,
                self.timeline.c.created_at,
            )
            .where(self.timeline.c.case_id == case_id)
            .order_by(self.timeline.c.timeline_pk.asc())
        )
        with self.engine.begin() as con:
            rows = self._rows(con.execute(stmt))
        out: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["tags"] = json.loads(item.pop("tags_json"))
            item["related"] = json.loads(item.pop("related_json"))
            out.append(item)
        out.sort(key=lambda row: timeline_sort_key(row.get("timestamp")))
        return out

    def replace_case_iocs(self, case_id: str, iocs: list[IOC]) -> None:
        now = utc_now_iso()
        with self.engine.begin() as con:
            con.execute(self.case_iocs.delete().where(self.case_iocs.c.case_id == case_id))
            if iocs:
                con.execute(
                    self.case_iocs.insert(),
                    [
                        {
                            "case_id": case_id,
                            "ioc_id": ioc.ioc_id,
                            "ioc_type": ioc.ioc_type,
                            "value": ioc.value,
                            "first_seen": ioc.first_seen,
                            "last_seen": ioc.last_seen,
                            "sources_json": json.dumps(ioc.sources),
                            "metadata_json": json.dumps(ioc.metadata),
                            "created_at": now,
                        }
                        for ioc in iocs
                    ],
                )

    def get_case_iocs(self, case_id: str) -> list[dict[str, Any]]:
        stmt = (
            self.sa.select(
                self.case_iocs.c.ioc_id,
                self.case_iocs.c.ioc_type,
                self.case_iocs.c.value,
                self.case_iocs.c.first_seen,
                self.case_iocs.c.last_seen,
                self.case_iocs.c.sources_json,
                self.case_iocs.c.metadata_json,
            )
            .where(self.case_iocs.c.case_id == case_id)
            .order_by(self.case_iocs.c.ioc_type.asc(), self.case_iocs.c.value.asc())
        )
        with self.engine.begin() as con:
            rows = self._rows(con.execute(stmt))
        out: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["sources"] = json.loads(item.pop("sources_json"))
            item["metadata"] = json.loads(item.pop("metadata_json"))
            out.append(item)
        return out

    def get_cached_ioc_enrichment(
        self,
        ioc_type: str,
        value: str,
        provider: str,
        ttl_minutes: int,
    ) -> IOCEnrichment | None:
        stmt = self.sa.select(
            self.ioc_enrichment_cache.c.verdict,
            self.ioc_enrichment_cache.c.confidence,
            self.ioc_enrichment_cache.c.details_json,
            self.ioc_enrichment_cache.c.fetched_at,
        ).where(
            self.ioc_enrichment_cache.c.ioc_type == ioc_type,
            self.ioc_enrichment_cache.c.value == value,
            self.ioc_enrichment_cache.c.provider == provider,
        )
        with self.engine.begin() as con:
            row = con.execute(stmt).first()
        if row is None:
            return None

        fetched_at = str(row._mapping["fetched_at"])
        if ttl_minutes > 0:
            clean = fetched_at.replace("Z", "+00:00")
            try:
                fetched_dt = datetime.fromisoformat(clean)
            except ValueError:
                return None
            if fetched_dt.tzinfo is None:
                fetched_dt = fetched_dt.replace(tzinfo=timezone.utc)
            if (datetime.now(timezone.utc) - fetched_dt).total_seconds() > (ttl_minutes * 60):
                return None

        return IOCEnrichment(
            enrichment_id=f"cache-{ioc_type}-{provider}",
            ioc_id="",
            provider=provider,
            verdict=str(row._mapping["verdict"]),
            confidence=float(row._mapping["confidence"]),
            details=json.loads(str(row._mapping["details_json"])),
            fetched_at=fetched_at,
        )

    def upsert_ioc_enrichment_cache(self, ioc_type: str, value: str, enrichment: IOCEnrichment) -> None:
        now = enrichment.fetched_at or utc_now_iso()
        values = {
            "ioc_type": ioc_type, "value": value, "provider": enrichment.provider,
            "verdict": enrichment.verdict, "confidence": enrichment.confidence,
            "details_json": json.dumps(enrichment.details), "fetched_at": now,
        }
        # Cache entries are shared between cases; a case lock cannot make a
        # separate UPDATE/INSERT pair atomic for concurrent provider results.
        if self.engine.dialect.name == "postgresql":
            from sqlalchemy.dialects.postgresql import insert
        else:
            from sqlalchemy.dialects.sqlite import insert
        statement = insert(self.ioc_enrichment_cache).values(**values)
        statement = statement.on_conflict_do_update(
            index_elements=["ioc_type", "value", "provider"],
            set_={key: getattr(statement.excluded, key) for key in ("verdict", "confidence", "details_json", "fetched_at")},
        )
        with self.engine.begin() as con:
            con.execute(statement)

    def get_case_ioc_enrichments(self, case_id: str) -> list[dict[str, Any]]:
        stmt = (
            self.sa.select(
                self.case_iocs.c.ioc_id,
                self.case_iocs.c.ioc_type,
                self.case_iocs.c.value,
                self.ioc_enrichment_cache.c.provider,
                self.ioc_enrichment_cache.c.verdict,
                self.ioc_enrichment_cache.c.confidence,
                self.ioc_enrichment_cache.c.details_json,
                self.ioc_enrichment_cache.c.fetched_at,
            )
            .select_from(
                self.case_iocs.join(
                    self.ioc_enrichment_cache,
                    self.sa.and_(
                        self.case_iocs.c.ioc_type == self.ioc_enrichment_cache.c.ioc_type,
                        self.case_iocs.c.value == self.ioc_enrichment_cache.c.value,
                    ),
                )
            )
            .where(self.case_iocs.c.case_id == case_id)
            .order_by(
                self.case_iocs.c.ioc_type.asc(),
                self.case_iocs.c.value.asc(),
                self.ioc_enrichment_cache.c.provider.asc(),
            )
        )
        with self.engine.begin() as con:
            rows = self._rows(con.execute(stmt))
        out: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["details"] = json.loads(item.pop("details_json"))
            out.append(item)
        return out

    def append_evidence_hash_log(self, case_id: str, entries: list[dict[str, Any]]) -> None:
        now = utc_now_iso()
        if not entries:
            return
        with self.engine.begin() as con:
            con.execute(
                self.evidence_hash_log.insert(),
                [
                    {
                        "case_id": case_id,
                        "rel_path": str(item.get("rel_path", "")),
                        "sha256": str(item.get("sha256", "")),
                        "size_bytes": int(item.get("size_bytes", 0) or 0),
                        "logged_at": now,
                    }
                    for item in entries
                ],
            )

    def get_evidence_hash_log(self, case_id: str) -> list[dict[str, Any]]:
        stmt = (
            self.sa.select(
                self.evidence_hash_log.c.rel_path,
                self.evidence_hash_log.c.sha256,
                self.evidence_hash_log.c.size_bytes,
                self.evidence_hash_log.c.logged_at,
            )
            .where(self.evidence_hash_log.c.case_id == case_id)
            .order_by(self.evidence_hash_log.c.hash_pk.asc())
        )
        with self.engine.begin() as con:
            return self._rows(con.execute(stmt))

    def add_analyst_note(self, case_id: str, author: str, content: str) -> dict[str, Any]:
        now = utc_now_iso()
        note_id = uuid.uuid4().hex[:16]
        with self.engine.begin() as con:
            con.execute(
                self.analyst_notes.insert().values(
                    case_id=case_id,
                    note_id=note_id,
                    author=author,
                    content=content,
                    created_at=now,
                )
            )
        return {
            "note_id": note_id,
            "author": author,
            "content": content,
            "created_at": now,
        }

    def get_analyst_notes(self, case_id: str) -> list[dict[str, Any]]:
        stmt = (
            self.sa.select(
                self.analyst_notes.c.note_id,
                self.analyst_notes.c.author,
                self.analyst_notes.c.content,
                self.analyst_notes.c.created_at,
            )
            .where(self.analyst_notes.c.case_id == case_id)
            .order_by(self.analyst_notes.c.note_pk.asc())
        )
        with self.engine.begin() as con:
            return self._rows(con.execute(stmt))

    def append_audit_log(
        self,
        action: str,
        actor: str,
        details: dict[str, Any] | None = None,
        case_id: str | None = None,
    ) -> None:
        with self.engine.begin() as con:
            con.execute(
                self.audit_log.insert().values(
                    case_id=case_id,
                    action=action,
                    actor=actor,
                    details_json=json.dumps(details or {}),
                    created_at=utc_now_iso(),
                )
            )

    def get_audit_log(self, case_id: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        stmt = self.sa.select(
            self.audit_log.c.case_id,
            self.audit_log.c.action,
            self.audit_log.c.actor,
            self.audit_log.c.details_json,
            self.audit_log.c.created_at,
        )
        if case_id is not None:
            stmt = stmt.where(self.audit_log.c.case_id == case_id)
        stmt = stmt.order_by(self.audit_log.c.audit_pk.desc()).limit(limit)
        with self.engine.begin() as con:
            rows = self._rows(con.execute(stmt))
        out: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["details"] = json.loads(item.pop("details_json"))
            out.append(item)
        return out

    def upsert_analysis_job(
        self,
        job_id: str,
        case_id: str,
        job_type: str,
        state: str,
        progress: int,
        message: str,
        error: str | None = None,
        result: dict[str, Any] | None = None,
    ) -> None:
        now = utc_now_iso()
        with self.engine.begin() as con:
            update_stmt = (
                self.analysis_jobs.update()
                .where(self.analysis_jobs.c.job_id == job_id)
                .values(
                    job_type=job_type,
                    state=state,
                    progress=int(progress),
                    message=message,
                    error=error,
                    result_json=json.dumps(result) if result is not None else None,
                    updated_at=now,
                )
            )
            update_result = con.execute(update_stmt)
            if int(update_result.rowcount or 0) == 0:
                con.execute(
                    self.analysis_jobs.insert().values(
                        job_id=job_id,
                        case_id=case_id,
                        job_type=job_type,
                        state=state,
                        progress=int(progress),
                        message=message,
                        error=error,
                        result_json=json.dumps(result) if result is not None else None,
                        created_at=now,
                        updated_at=now,
                    )
                )

    def get_case_latest_job(self, case_id: str, job_type: str = "analysis") -> dict[str, Any] | None:
        stmt = (
            self.sa.select(
                self.analysis_jobs.c.job_id,
                self.analysis_jobs.c.case_id,
                self.analysis_jobs.c.job_type,
                self.analysis_jobs.c.state,
                self.analysis_jobs.c.progress,
                self.analysis_jobs.c.message,
                self.analysis_jobs.c.error,
                self.analysis_jobs.c.result_json,
                self.analysis_jobs.c.created_at,
                self.analysis_jobs.c.updated_at,
            )
            .where(self.analysis_jobs.c.case_id == case_id, self.analysis_jobs.c.job_type == job_type)
            .order_by(self.analysis_jobs.c.updated_at.desc())
            .limit(1)
        )
        with self.engine.begin() as con:
            row = con.execute(stmt).first()
        if row is None:
            return None
        item = dict(row._mapping)
        result_json = item.pop("result_json", None)
        try:
            item["result"] = json.loads(result_json) if result_json else None
        except (json.JSONDecodeError, TypeError):
            item["result"] = None
        return item

    def list_case_jobs(
        self,
        case_id: str,
        job_type: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        limit = max(1, min(1000, int(limit)))
        stmt = self.sa.select(
            self.analysis_jobs.c.job_id,
            self.analysis_jobs.c.case_id,
            self.analysis_jobs.c.job_type,
            self.analysis_jobs.c.state,
            self.analysis_jobs.c.progress,
            self.analysis_jobs.c.message,
            self.analysis_jobs.c.error,
            self.analysis_jobs.c.result_json,
            self.analysis_jobs.c.created_at,
            self.analysis_jobs.c.updated_at,
        ).where(self.analysis_jobs.c.case_id == case_id)
        if job_type:
            stmt = stmt.where(self.analysis_jobs.c.job_type == job_type)
        stmt = stmt.order_by(self.analysis_jobs.c.updated_at.desc()).limit(limit)
        with self.engine.begin() as con:
            rows = self._rows(con.execute(stmt))
        out: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            result_json = item.pop("result_json", None)
            try:
                item["result"] = json.loads(result_json) if result_json else None
            except (json.JSONDecodeError, TypeError):
                item["result"] = None
            out.append(item)
        return out

    def cleanup_analysis_jobs(self, retention_days: int, job_type: str | None = None) -> int:
        retention_days = max(0, int(retention_days))
        cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat().replace(
            "+00:00", "Z"
        )
        stmt = self.analysis_jobs.delete().where(
            self.sa.func.coalesce(self.analysis_jobs.c.updated_at, self.analysis_jobs.c.created_at) < cutoff
        )
        if job_type:
            stmt = stmt.where(self.analysis_jobs.c.job_type == job_type)
        with self.engine.begin() as con:
            result = con.execute(stmt)
        return int(result.rowcount or 0)

    def search_case(self, case_id: str, query: str, limit: int = 100) -> dict[str, list[dict[str, Any]]]:
        needle = f"%{query}%"

        finding_stmt = (
            self.sa.select(
                self.findings.c.finding_id,
                self.findings.c.title,
                self.findings.c.severity,
                self.findings.c.confidence,
                self.findings.c.tactic,
                self.findings.c.evidence_json,
                self.findings.c.recommendation,
                self.findings.c.created_at,
                self.findings.c.citations_json,
                self.findings.c.origin,
                self.findings.c.review_status,
                self.findings.c.worker,
                self.findings.c.details_json,
            )
            .where(
                self.findings.c.case_id == case_id,
                self.sa.or_(
                    self.findings.c.title.like(needle),
                    self.findings.c.evidence_json.like(needle),
                    self.findings.c.recommendation.like(needle),
                    self.findings.c.tactic.like(needle),
                ),
            )
            .order_by(self.findings.c.created_at.desc())
            .limit(limit)
        )

        timeline_stmt = (
            self.sa.select(
                self.timeline.c.timestamp,
                self.timeline.c.source,
                self.timeline.c.event_type,
                self.timeline.c.description,
                self.timeline.c.risk_score,
                self.timeline.c.tags_json,
                self.timeline.c.related_json,
                self.timeline.c.created_at,
            )
            .where(
                self.timeline.c.case_id == case_id,
                self.sa.or_(
                    self.timeline.c.source.like(needle),
                    self.timeline.c.event_type.like(needle),
                    self.timeline.c.description.like(needle),
                    self.timeline.c.related_json.like(needle),
                ),
            )
            .order_by(self.timeline.c.created_at.asc())
            .limit(limit)
        )

        ioc_stmt = (
            self.sa.select(
                self.case_iocs.c.ioc_id,
                self.case_iocs.c.ioc_type,
                self.case_iocs.c.value,
                self.case_iocs.c.first_seen,
                self.case_iocs.c.last_seen,
                self.case_iocs.c.sources_json,
                self.case_iocs.c.metadata_json,
            )
            .where(
                self.case_iocs.c.case_id == case_id,
                self.sa.or_(
                    self.case_iocs.c.ioc_type.like(needle),
                    self.case_iocs.c.value.like(needle),
                    self.case_iocs.c.metadata_json.like(needle),
                ),
            )
            .order_by(self.case_iocs.c.ioc_type.asc(), self.case_iocs.c.value.asc())
            .limit(limit)
        )

        with self.engine.begin() as con:
            finding_rows = self._rows(con.execute(finding_stmt))
            timeline_rows = self._rows(con.execute(timeline_stmt))
            ioc_rows = self._rows(con.execute(ioc_stmt))

        finding_out = [decode_finding_row(row) for row in finding_rows]

        timeline_out: list[dict[str, Any]] = []
        for row in timeline_rows:
            item = dict(row)
            item["tags"] = json.loads(item.pop("tags_json"))
            item["related"] = json.loads(item.pop("related_json"))
            timeline_out.append(item)

        ioc_out: list[dict[str, Any]] = []
        for row in ioc_rows:
            item = dict(row)
            item["sources"] = json.loads(item.pop("sources_json"))
            item["metadata"] = json.loads(item.pop("metadata_json"))
            ioc_out.append(item)

        return {
            "findings": finding_out,
            "timeline": timeline_out,
            "iocs": ioc_out,
        }
