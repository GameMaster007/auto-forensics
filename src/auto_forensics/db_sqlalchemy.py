from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .migrations import LATEST_SCHEMA_VERSION, MIGRATION_STEPS
from .models import IOC, IOCEnrichment, Finding, TimelineEvent, utc_now_iso


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
            sa.Column("finding_id", sa.String(128), primary_key=True),
            sa.Column("case_id", sa.String(128), sa.ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False),
            sa.Column("title", sa.Text, nullable=False),
            sa.Column("severity", sa.String(32), nullable=False),
            sa.Column("confidence", sa.Float, nullable=False),
            sa.Column("tactic", sa.String(128), nullable=False),
            sa.Column("evidence_json", sa.Text, nullable=False),
            sa.Column("recommendation", sa.Text, nullable=False),
            sa.Column("created_at", sa.Text, nullable=False),
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

        md.create_all(self.engine)
        self.run_migrations()

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

    def run_migrations(self) -> dict[str, Any]:
        current = self.get_schema_version()
        applied: list[dict[str, Any]] = []
        with self.engine.begin() as con:
            for step in MIGRATION_STEPS:
                if step.version <= current:
                    continue
                for statement in step.sql_statements:
                    try:
                        con.exec_driver_sql(statement)
                    except Exception as exc:
                        text = str(exc).lower()
                        if "duplicate column" in text or "already exists" in text:
                            continue
                        raise
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
            item["metadata"] = json.loads(item.pop("metadata_json"))
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
            )
            .where(self.findings.c.case_id == case_id)
            .order_by(self.findings.c.created_at.desc())
        )
        with self.engine.begin() as con:
            rows = self._rows(con.execute(stmt))
        out: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["evidence"] = json.loads(item.pop("evidence_json"))
            out.append(item)
        return out

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
            .order_by(self.timeline.c.created_at.asc())
        )
        with self.engine.begin() as con:
            rows = self._rows(con.execute(stmt))
        out: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["tags"] = json.loads(item.pop("tags_json"))
            item["related"] = json.loads(item.pop("related_json"))
            out.append(item)
        out.sort(key=lambda x: (x.get("timestamp") or x.get("created_at") or ""))
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
        with self.engine.begin() as con:
            update_stmt = (
                self.ioc_enrichment_cache.update()
                .where(
                    self.ioc_enrichment_cache.c.ioc_type == ioc_type,
                    self.ioc_enrichment_cache.c.value == value,
                    self.ioc_enrichment_cache.c.provider == enrichment.provider,
                )
                .values(
                    verdict=enrichment.verdict,
                    confidence=enrichment.confidence,
                    details_json=json.dumps(enrichment.details),
                    fetched_at=now,
                )
            )
            result = con.execute(update_stmt)
            if int(result.rowcount or 0) == 0:
                con.execute(
                    self.ioc_enrichment_cache.insert().values(
                        ioc_type=ioc_type,
                        value=value,
                        provider=enrichment.provider,
                        verdict=enrichment.verdict,
                        confidence=enrichment.confidence,
                        details_json=json.dumps(enrichment.details),
                        fetched_at=now,
                    )
                )

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

        finding_out: list[dict[str, Any]] = []
        for row in finding_rows:
            item = dict(row)
            item["evidence"] = json.loads(item.pop("evidence_json"))
            finding_out.append(item)

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
