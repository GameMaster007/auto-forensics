from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ._db_sqlalchemy_tables import define_tables
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

        tables = define_tables(sa, md)
        self.cases = tables["cases"]
        self.artifacts = tables["artifacts"]
        self.findings = tables["findings"]
        self.timeline = tables["timeline"]
        self.case_iocs = tables["case_iocs"]
        self.ioc_enrichment_cache = tables["ioc_enrichment_cache"]
        self.analyst_notes = tables["analyst_notes"]
        self.workspace_views = tables["workspace_views"]
        self.notebook_entries = tables["notebook_entries"]
        self.agent_sessions = tables["agent_sessions"]
        self.agent_steps = tables["agent_steps"]
        self.agent_recommendations = tables["agent_recommendations"]
        self.graph_nodes = tables["graph_nodes"]
        self.graph_edges = tables["graph_edges"]
        self.evidence_hash_log = tables["evidence_hash_log"]
        self.audit_log = tables["audit_log"]
        self.schema_migrations = tables["schema_migrations"]
        self.analysis_jobs = tables["analysis_jobs"]

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

    def delete_case(self, case_id: str) -> bool:
        """Delete a case and all associated data (relies on ON DELETE CASCADE).

        Returns True if a row was deleted, False if the case didn't exist.
        """
        stmt = self.cases.delete().where(self.cases.c.case_id == case_id)
        with self.engine.begin() as con:
            result = con.execute(stmt)
        return int(result.rowcount or 0) > 0

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

    def list_workspace_views(self, case_id: str) -> list[dict[str, Any]]:
        stmt = (
            self.sa.select(
                self.workspace_views.c.view_id,
                self.workspace_views.c.name,
                self.workspace_views.c.section,
                self.workspace_views.c.filters_json,
                self.workspace_views.c.sort_json,
                self.workspace_views.c.layout_json,
                self.workspace_views.c.created_at,
                self.workspace_views.c.updated_at,
            )
            .where(self.workspace_views.c.case_id == case_id)
            .order_by(self.workspace_views.c.updated_at.desc(), self.workspace_views.c.name.asc())
        )
        with self.engine.begin() as con:
            rows = self._rows(con.execute(stmt))
        output: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["filters"] = json.loads(item.pop("filters_json"))
            item["sort"] = json.loads(item.pop("sort_json"))
            item["layout"] = json.loads(item.pop("layout_json"))
            output.append(item)
        return output

    def upsert_workspace_view(
        self,
        case_id: str,
        name: str,
        section: str,
        filters: dict[str, Any],
        sort: dict[str, Any],
        layout: dict[str, Any],
        view_id: str | None = None,
    ) -> dict[str, Any]:
        now = utc_now_iso()
        clean_view_id = view_id or uuid.uuid4().hex[:16]
        with self.engine.begin() as con:
            update_stmt = (
                self.workspace_views.update()
                .where(self.workspace_views.c.view_id == clean_view_id)
                .values(
                    case_id=case_id,
                    name=name,
                    section=section,
                    filters_json=json.dumps(filters or {}),
                    sort_json=json.dumps(sort or {}),
                    layout_json=json.dumps(layout or {}),
                    updated_at=now,
                )
            )
            result = con.execute(update_stmt)
            if int(result.rowcount or 0) == 0:
                con.execute(
                    self.workspace_views.insert().values(
                        view_id=clean_view_id,
                        case_id=case_id,
                        name=name,
                        section=section,
                        filters_json=json.dumps(filters or {}),
                        sort_json=json.dumps(sort or {}),
                        layout_json=json.dumps(layout or {}),
                        created_at=now,
                        updated_at=now,
                    )
                )
        return {
            "view_id": clean_view_id,
            "name": name,
            "section": section,
            "filters": filters or {},
            "sort": sort or {},
            "layout": layout or {},
            "created_at": now,
            "updated_at": now,
        }

    def delete_workspace_view(self, case_id: str, view_id: str) -> bool:
        stmt = self.workspace_views.delete().where(
            self.workspace_views.c.case_id == case_id,
            self.workspace_views.c.view_id == view_id,
        )
        with self.engine.begin() as con:
            result = con.execute(stmt)
        return int(result.rowcount or 0) > 0

    def list_notebook_entries(self, case_id: str) -> list[dict[str, Any]]:
        stmt = (
            self.sa.select(
                self.notebook_entries.c.entry_id,
                self.notebook_entries.c.kind,
                self.notebook_entries.c.title,
                self.notebook_entries.c.body,
                self.notebook_entries.c.links_json,
                self.notebook_entries.c.created_at,
                self.notebook_entries.c.updated_at,
            )
            .where(self.notebook_entries.c.case_id == case_id)
            .order_by(self.notebook_entries.c.updated_at.desc(), self.notebook_entries.c.created_at.desc())
        )
        with self.engine.begin() as con:
            rows = self._rows(con.execute(stmt))
        output: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["links"] = json.loads(item.pop("links_json"))
            output.append(item)
        return output

    def create_notebook_entry(
        self,
        case_id: str,
        kind: str,
        title: str,
        body: str,
        links: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = utc_now_iso()
        entry_id = uuid.uuid4().hex[:16]
        with self.engine.begin() as con:
            con.execute(
                self.notebook_entries.insert().values(
                    entry_id=entry_id,
                    case_id=case_id,
                    kind=kind,
                    title=title,
                    body=body,
                    links_json=json.dumps(links or {}),
                    created_at=now,
                    updated_at=now,
                )
            )
        return {
            "entry_id": entry_id,
            "kind": kind,
            "title": title,
            "body": body,
            "links": links or {},
            "created_at": now,
            "updated_at": now,
        }

    def update_notebook_entry(
        self,
        case_id: str,
        entry_id: str,
        title: str | None = None,
        body: str | None = None,
        kind: str | None = None,
        links: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        stmt = self.sa.select(self.notebook_entries).where(
            self.notebook_entries.c.case_id == case_id,
            self.notebook_entries.c.entry_id == entry_id,
        )
        with self.engine.begin() as con:
            row = con.execute(stmt).first()
            if row is None:
                return None
            current = dict(row._mapping)
            now = utc_now_iso()
            next_kind = kind if kind is not None else str(current.get("kind") or "note")
            next_title = title if title is not None else str(current.get("title") or "")
            next_body = body if body is not None else str(current.get("body") or "")
            next_links = links if links is not None else json.loads(str(current.get("links_json") or "{}"))
            con.execute(
                self.notebook_entries.update()
                .where(
                    self.notebook_entries.c.case_id == case_id,
                    self.notebook_entries.c.entry_id == entry_id,
                )
                .values(
                    kind=next_kind,
                    title=next_title,
                    body=next_body,
                    links_json=json.dumps(next_links),
                    updated_at=now,
                )
            )
        return {
            "entry_id": entry_id,
            "kind": next_kind,
            "title": next_title,
            "body": next_body,
            "links": next_links,
            "created_at": current.get("created_at"),
            "updated_at": now,
        }

    def create_agent_session(
        self,
        case_id: str,
        goal: str,
        status: str,
        model_config: dict[str, Any],
        summary: str = "",
        error: str | None = None,
        session_id: str | None = None,
    ) -> dict[str, Any]:
        now = utc_now_iso()
        clean_session_id = session_id or uuid.uuid4().hex[:16]
        with self.engine.begin() as con:
            con.execute(
                self.agent_sessions.insert().values(
                    session_id=clean_session_id,
                    case_id=case_id,
                    goal=goal,
                    status=status,
                    model_config_json=json.dumps(model_config or {}),
                    summary=summary,
                    error=error,
                    created_at=now,
                    updated_at=now,
                    completed_at=None,
                )
            )
        return {
            "session_id": clean_session_id,
            "case_id": case_id,
            "goal": goal,
            "status": status,
            "model_config": model_config or {},
            "summary": summary,
            "error": error,
            "created_at": now,
            "updated_at": now,
            "completed_at": None,
        }

    def update_agent_session(
        self,
        session_id: str,
        status: str | None = None,
        summary: str | None = None,
        error: str | None = None,
        completed_at: str | None = None,
    ) -> dict[str, Any] | None:
        stmt = self.sa.select(self.agent_sessions).where(self.agent_sessions.c.session_id == session_id)
        with self.engine.begin() as con:
            row = con.execute(stmt).first()
            if row is None:
                return None
            current = dict(row._mapping)
            now = utc_now_iso()
            con.execute(
                self.agent_sessions.update()
                .where(self.agent_sessions.c.session_id == session_id)
                .values(
                    status=status if status is not None else current["status"],
                    summary=summary if summary is not None else current["summary"],
                    error=error if error is not None else current["error"],
                    updated_at=now,
                    completed_at=(
                        completed_at if completed_at is not None else current["completed_at"]
                    ),
                )
            )
        current["status"] = status if status is not None else current["status"]
        current["summary"] = summary if summary is not None else current["summary"]
        current["error"] = error if error is not None else current["error"]
        current["updated_at"] = now
        current["completed_at"] = (
            completed_at if completed_at is not None else current["completed_at"]
        )
        current["model_config"] = json.loads(str(current.pop("model_config_json") or "{}"))
        return current

    def list_agent_sessions(self, case_id: str) -> list[dict[str, Any]]:
        stmt = (
            self.sa.select(self.agent_sessions)
            .where(self.agent_sessions.c.case_id == case_id)
            .order_by(self.agent_sessions.c.updated_at.desc())
        )
        with self.engine.begin() as con:
            rows = self._rows(con.execute(stmt))
        output: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["model_config"] = json.loads(item.pop("model_config_json"))
            output.append(item)
        return output

    def get_agent_session(self, case_id: str, session_id: str) -> dict[str, Any] | None:
        stmt = self.sa.select(self.agent_sessions).where(
            self.agent_sessions.c.case_id == case_id,
            self.agent_sessions.c.session_id == session_id,
        )
        with self.engine.begin() as con:
            row = con.execute(stmt).first()
        if row is None:
            return None
        item = dict(row._mapping)
        item["model_config"] = json.loads(item.pop("model_config_json"))
        return item

    def replace_agent_steps(self, session_id: str, steps: list[dict[str, Any]]) -> None:
        with self.engine.begin() as con:
            con.execute(self.agent_steps.delete().where(self.agent_steps.c.session_id == session_id))
            if steps:
                con.execute(
                    self.agent_steps.insert(),
                    [
                        {
                            "step_id": str(step.get("step_id") or uuid.uuid4().hex[:16]),
                            "session_id": session_id,
                            "step_index": int(step.get("step_index", 0) or 0),
                            "title": str(step.get("title") or ""),
                            "rationale": str(step.get("rationale") or ""),
                            "linked_entities_json": json.dumps(step.get("linked_entities") or {}),
                            "proposed_action_json": json.dumps(step.get("proposed_action") or {}),
                            "approval_state": str(step.get("approval_state") or "not_required"),
                            "result_json": json.dumps(step.get("result") or {}),
                            "created_at": str(step.get("created_at") or utc_now_iso()),
                            "updated_at": str(step.get("updated_at") or utc_now_iso()),
                        }
                        for step in steps
                    ],
                )

    def list_agent_steps(self, session_id: str) -> list[dict[str, Any]]:
        stmt = (
            self.sa.select(self.agent_steps)
            .where(self.agent_steps.c.session_id == session_id)
            .order_by(self.agent_steps.c.step_index.asc(), self.agent_steps.c.created_at.asc())
        )
        with self.engine.begin() as con:
            rows = self._rows(con.execute(stmt))
        output: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["linked_entities"] = json.loads(item.pop("linked_entities_json"))
            item["proposed_action"] = json.loads(item.pop("proposed_action_json"))
            item["result"] = json.loads(item.pop("result_json"))
            output.append(item)
        return output

    def replace_agent_recommendations(
        self,
        session_id: str,
        case_id: str,
        recommendations: list[dict[str, Any]],
    ) -> None:
        with self.engine.begin() as con:
            con.execute(
                self.agent_recommendations.delete().where(
                    self.agent_recommendations.c.session_id == session_id
                )
            )
            if recommendations:
                con.execute(
                    self.agent_recommendations.insert(),
                    [
                        {
                            "recommendation_id": str(item.get("recommendation_id") or uuid.uuid4().hex[:16]),
                            "session_id": session_id,
                            "case_id": case_id,
                            "priority": int(item.get("priority", 0) or 0),
                            "title": str(item.get("title") or ""),
                            "reason": str(item.get("reason") or ""),
                            "linked_entities_json": json.dumps(item.get("linked_entities") or {}),
                            "suggested_action_json": json.dumps(item.get("suggested_action") or {}),
                            "status": str(item.get("status") or "pending"),
                            "confidence": float(item.get("confidence", 0) or 0),
                            "evidence_count": int(item.get("evidence_count", 0) or 0),
                            "created_at": str(item.get("created_at") or utc_now_iso()),
                            "updated_at": str(item.get("updated_at") or utc_now_iso()),
                        }
                        for item in recommendations
                    ],
                )

    def list_agent_recommendations(self, session_id: str) -> list[dict[str, Any]]:
        stmt = (
            self.sa.select(self.agent_recommendations)
            .where(self.agent_recommendations.c.session_id == session_id)
            .order_by(
                self.agent_recommendations.c.priority.desc(),
                self.agent_recommendations.c.updated_at.desc(),
            )
        )
        with self.engine.begin() as con:
            rows = self._rows(con.execute(stmt))
        output: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["linked_entities"] = json.loads(item.pop("linked_entities_json"))
            item["suggested_action"] = json.loads(item.pop("suggested_action_json"))
            output.append(item)
        return output

    def replace_case_graph(
        self,
        case_id: str,
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
    ) -> None:
        with self.engine.begin() as con:
            con.execute(self.graph_nodes.delete().where(self.graph_nodes.c.case_id == case_id))
            con.execute(self.graph_edges.delete().where(self.graph_edges.c.case_id == case_id))
            if nodes:
                con.execute(
                    self.graph_nodes.insert(),
                    [
                        {
                            "node_id": str(node.get("node_id") or uuid.uuid4().hex[:16]),
                            "case_id": case_id,
                            "node_type": str(node.get("node_type") or ""),
                            "label": str(node.get("label") or ""),
                            "score": float(node.get("score", 0) or 0),
                            "metadata_json": json.dumps(node.get("metadata") or {}),
                            "created_at": str(node.get("created_at") or utc_now_iso()),
                        }
                        for node in nodes
                    ],
                )
            if edges:
                con.execute(
                    self.graph_edges.insert(),
                    [
                        {
                            "edge_id": str(edge.get("edge_id") or uuid.uuid4().hex[:16]),
                            "case_id": case_id,
                            "source_node_id": str(edge.get("source_node_id") or ""),
                            "target_node_id": str(edge.get("target_node_id") or ""),
                            "relation": str(edge.get("relation") or ""),
                            "confidence": float(edge.get("confidence", 0) or 0),
                            "metadata_json": json.dumps(edge.get("metadata") or {}),
                            "created_at": str(edge.get("created_at") or utc_now_iso()),
                        }
                        for edge in edges
                    ],
                )

    def get_case_graph(self, case_id: str) -> dict[str, list[dict[str, Any]]]:
        node_stmt = (
            self.sa.select(self.graph_nodes)
            .where(self.graph_nodes.c.case_id == case_id)
            .order_by(self.graph_nodes.c.score.desc(), self.graph_nodes.c.label.asc())
        )
        edge_stmt = (
            self.sa.select(self.graph_edges)
            .where(self.graph_edges.c.case_id == case_id)
            .order_by(self.graph_edges.c.confidence.desc(), self.graph_edges.c.relation.asc())
        )
        with self.engine.begin() as con:
            node_rows = self._rows(con.execute(node_stmt))
            edge_rows = self._rows(con.execute(edge_stmt))
        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []
        for row in node_rows:
            item = dict(row)
            item["metadata"] = json.loads(item.pop("metadata_json"))
            nodes.append(item)
        for row in edge_rows:
            item = dict(row)
            item["metadata"] = json.loads(item.pop("metadata_json"))
            edges.append(item)
        return {"nodes": nodes, "edges": edges}

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
