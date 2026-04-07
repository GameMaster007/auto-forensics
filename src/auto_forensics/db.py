from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

logger = logging.getLogger(__name__)

from .migrations import LATEST_SCHEMA_VERSION, MIGRATION_STEPS
from .models import IOC, IOCEnrichment, Finding, TimelineEvent, utc_now_iso


def _loads_json(raw: Any, default: Any) -> Any:
    try:
        return json.loads(raw) if raw is not None else default
    except (json.JSONDecodeError, TypeError):
        return default


SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    status TEXT NOT NULL,
    evidence_dir TEXT NOT NULL,
    output_dir TEXT NOT NULL,
    last_error TEXT
);

CREATE TABLE IF NOT EXISTS artifacts (
    artifact_pk INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    rel_path TEXT NOT NULL,
    artifact_type TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    ingested_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_artifacts_case ON artifacts(case_id);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL,
    tactic TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    recommendation TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_findings_case ON findings(case_id);

CREATE TABLE IF NOT EXISTS timeline (
    timeline_pk INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    timestamp TEXT,
    source TEXT NOT NULL,
    event_type TEXT NOT NULL,
    description TEXT NOT NULL,
    risk_score REAL NOT NULL,
    tags_json TEXT NOT NULL,
    related_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_timeline_case ON timeline(case_id);

CREATE TABLE IF NOT EXISTS case_iocs (
    ioc_pk INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    ioc_id TEXT NOT NULL,
    ioc_type TEXT NOT NULL,
    value TEXT NOT NULL,
    first_seen TEXT,
    last_seen TEXT,
    sources_json TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_case_iocs_case ON case_iocs(case_id);
CREATE INDEX IF NOT EXISTS idx_case_iocs_value ON case_iocs(ioc_type, value);

CREATE TABLE IF NOT EXISTS ioc_enrichment_cache (
    cache_pk INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_type TEXT NOT NULL,
    value TEXT NOT NULL,
    provider TEXT NOT NULL,
    verdict TEXT NOT NULL,
    confidence REAL NOT NULL,
    details_json TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    UNIQUE(ioc_type, value, provider)
);

CREATE INDEX IF NOT EXISTS idx_ioc_cache_lookup ON ioc_enrichment_cache(ioc_type, value, provider, fetched_at);

CREATE TABLE IF NOT EXISTS analyst_notes (
    note_pk INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    note_id TEXT NOT NULL,
    author TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_notes_case ON analyst_notes(case_id);

CREATE TABLE IF NOT EXISTS workspace_views (
    view_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    name TEXT NOT NULL,
    section TEXT NOT NULL,
    filters_json TEXT NOT NULL,
    sort_json TEXT NOT NULL,
    layout_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_workspace_views_case
ON workspace_views(case_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS notebook_entries (
    entry_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    links_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_notebook_entries_case
ON notebook_entries(case_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS agent_sessions (
    session_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    goal TEXT NOT NULL,
    status TEXT NOT NULL,
    model_config_json TEXT NOT NULL,
    summary TEXT NOT NULL DEFAULT '',
    error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    completed_at TEXT,
    FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_agent_sessions_case
ON agent_sessions(case_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS agent_steps (
    step_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    step_index INTEGER NOT NULL,
    title TEXT NOT NULL,
    rationale TEXT NOT NULL,
    linked_entities_json TEXT NOT NULL,
    proposed_action_json TEXT NOT NULL,
    approval_state TEXT NOT NULL,
    result_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(session_id) REFERENCES agent_sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_agent_steps_session
ON agent_steps(session_id, step_index ASC);

CREATE TABLE IF NOT EXISTS agent_recommendations (
    recommendation_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    priority INTEGER NOT NULL,
    title TEXT NOT NULL,
    reason TEXT NOT NULL,
    linked_entities_json TEXT NOT NULL,
    suggested_action_json TEXT NOT NULL,
    status TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 0,
    evidence_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(session_id) REFERENCES agent_sessions(session_id) ON DELETE CASCADE,
    FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_agent_recommendations_session
ON agent_recommendations(session_id, priority DESC);

CREATE TABLE IF NOT EXISTS graph_nodes (
    node_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    node_type TEXT NOT NULL,
    label TEXT NOT NULL,
    score REAL NOT NULL DEFAULT 0,
    metadata_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_graph_nodes_case
ON graph_nodes(case_id, node_type);

CREATE TABLE IF NOT EXISTS graph_edges (
    edge_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    source_node_id TEXT NOT NULL,
    target_node_id TEXT NOT NULL,
    relation TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 0,
    metadata_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_graph_edges_case
ON graph_edges(case_id, relation);

CREATE TABLE IF NOT EXISTS evidence_hash_log (
    hash_pk INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    rel_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    logged_at TEXT NOT NULL,
    FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_evidence_hash_case ON evidence_hash_log(case_id);

CREATE TABLE IF NOT EXISTS audit_log (
    audit_pk INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT,
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    details_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_case ON audit_log(case_id);

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TEXT NOT NULL
);
"""


class Database:
    def __init__(self, path: Path | str):
        if isinstance(path, str):
            if path.startswith("sqlite:///"):
                raw = path[len("sqlite:///") :]
                self.path = Path(raw).expanduser().resolve()
            elif path.startswith("sqlite://"):
                raw = path[len("sqlite://") :]
                self.path = Path(raw).expanduser().resolve()
            elif "://" in path:
                raise ValueError(
                    "Only sqlite URLs are currently supported by this build. "
                    "Use sqlite:///absolute/path.db"
                )
            else:
                self.path = Path(path).expanduser().resolve()
        else:
            self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.init_schema()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        con = sqlite3.connect(self.path)
        con.execute("PRAGMA foreign_keys=ON")
        con.row_factory = sqlite3.Row
        try:
            yield con
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()

    def init_schema(self) -> None:
        with self.connect() as con:
            con.executescript(SCHEMA_SQL)
            self.run_migrations(con)

    def get_schema_version(self) -> int:
        with self.connect() as con:
            row = con.execute("PRAGMA user_version").fetchone()
        return int(row[0]) if row else 0

    def list_schema_migrations(self) -> list[dict[str, Any]]:
        with self.connect() as con:
            rows = con.execute(
                """
                SELECT version, name, applied_at
                FROM schema_migrations
                ORDER BY version ASC
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def run_migrations(self, con: sqlite3.Connection | None = None) -> dict[str, Any]:
        close_after = False
        if con is None:
            con = sqlite3.connect(self.path)
            con.row_factory = sqlite3.Row
            close_after = True

        try:
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    applied_at TEXT NOT NULL
                )
                """
            )
            row = con.execute("PRAGMA user_version").fetchone()
            current = int(row[0]) if row else 0
            applied: list[dict[str, Any]] = []

            for step in MIGRATION_STEPS:
                if step.version <= current:
                    continue
                for statement in step.sql_statements:
                    try:
                        con.executescript(statement)
                    except sqlite3.OperationalError as exc:
                        text = str(exc).lower()
                        if "duplicate column name" in text or "already exists" in text:
                            continue
                        raise
                applied_at = utc_now_iso()
                con.execute(
                    """
                    INSERT OR REPLACE INTO schema_migrations(version, name, applied_at)
                    VALUES(?, ?, ?)
                    """,
                    (step.version, step.name, applied_at),
                )
                con.execute(f"PRAGMA user_version = {step.version}")
                current = step.version
                applied.append({"version": step.version, "name": step.name, "applied_at": applied_at})

            if close_after:
                con.commit()
            return {
                "current_version": current,
                "latest_version": LATEST_SCHEMA_VERSION,
                "applied": applied,
            }
        finally:
            if close_after:
                con.close()

    def create_case(self, case_id: str, evidence_dir: Path, output_dir: Path) -> None:
        now = utc_now_iso()
        with self.connect() as con:
            con.execute(
                """
                INSERT INTO cases(case_id, created_at, updated_at, status, evidence_dir, output_dir, last_error)
                VALUES(?, ?, ?, 'created', ?, ?, NULL)
                """,
                (case_id, now, now, str(evidence_dir), str(output_dir)),
            )

    def list_cases(self) -> list[dict[str, Any]]:
        with self.connect() as con:
            rows = con.execute(
                "SELECT case_id, created_at, updated_at, status, evidence_dir, output_dir, last_error "
                "FROM cases ORDER BY updated_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        with self.connect() as con:
            row = con.execute(
                """
                SELECT case_id, created_at, updated_at, status, evidence_dir, output_dir, last_error
                FROM cases WHERE case_id = ?
                """,
                (case_id,),
            ).fetchone()
        return dict(row) if row else None

    def delete_case(self, case_id: str) -> bool:
        """Delete a case and all associated data (CASCADE).

        Returns True if a row was deleted, False if the case didn't exist.
        """
        with self.connect() as con:
            cur = con.execute("DELETE FROM cases WHERE case_id = ?", (case_id,))
        return int(cur.rowcount or 0) > 0

    def set_case_status(self, case_id: str, status: str, last_error: str | None = None) -> None:
        now = utc_now_iso()
        with self.connect() as con:
            con.execute(
                "UPDATE cases SET status = ?, updated_at = ?, last_error = ? WHERE case_id = ?",
                (status, now, last_error, case_id),
            )

    def replace_artifacts(self, case_id: str, artifacts: list[dict[str, Any]]) -> None:
        now = utc_now_iso()
        with self.connect() as con:
            con.execute("DELETE FROM artifacts WHERE case_id = ?", (case_id,))
            con.executemany(
                """
                INSERT INTO artifacts(case_id, rel_path, artifact_type, size_bytes, sha256, ingested_at, metadata_json)
                VALUES(?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        case_id,
                        str(item["rel_path"]),
                        str(item["artifact_type"]),
                        int(item["size_bytes"]),
                        str(item["sha256"]),
                        now,
                        json.dumps(item.get("metadata", {})),
                    )
                    for item in artifacts
                ],
            )

    def replace_findings_and_timeline(
        self, case_id: str, findings: list[Finding], timeline: list[TimelineEvent]
    ) -> None:
        now = utc_now_iso()
        with self.connect() as con:
            con.execute("DELETE FROM findings WHERE case_id = ?", (case_id,))
            con.execute("DELETE FROM timeline WHERE case_id = ?", (case_id,))
            con.executemany(
                """
                INSERT INTO findings(
                    finding_id, case_id, title, severity, confidence, tactic,
                    evidence_json, recommendation, created_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        f.finding_id,
                        case_id,
                        f.title,
                        f.severity,
                        f.confidence,
                        f.tactic,
                        json.dumps(f.evidence),
                        f.recommendation,
                        now,
                    )
                    for f in findings
                ],
            )
            con.executemany(
                """
                INSERT INTO timeline(
                    case_id, timestamp, source, event_type, description,
                    risk_score, tags_json, related_json, created_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        case_id,
                        t.timestamp,
                        t.source,
                        t.event_type,
                        t.description,
                        t.risk_score,
                        json.dumps(t.tags),
                        json.dumps(t.related),
                        now,
                    )
                    for t in timeline
                ],
            )

    def get_artifacts(self, case_id: str) -> list[dict[str, Any]]:
        with self.connect() as con:
            rows = con.execute(
                "SELECT rel_path, artifact_type, size_bytes, sha256, metadata_json FROM artifacts WHERE case_id=?",
                (case_id,),
            ).fetchall()
        out: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["metadata"] = json.loads(item.pop("metadata_json"))
            out.append(item)
        return out

    def get_findings(self, case_id: str) -> list[dict[str, Any]]:
        with self.connect() as con:
            rows = con.execute(
                """
                SELECT finding_id, title, severity, confidence, tactic, evidence_json, recommendation, created_at
                FROM findings WHERE case_id = ? ORDER BY created_at DESC
                """,
                (case_id,),
            ).fetchall()
        out: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            raw = item.pop("evidence_json")
            try:
                item["evidence"] = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                logger.warning(
                    "Corrupted evidence_json for finding %s: %.100r",
                    item.get("finding_id"), raw,
                )
                item["evidence"] = []
            out.append(item)
        return out

    def get_timeline(self, case_id: str) -> list[dict[str, Any]]:
        with self.connect() as con:
            rows = con.execute(
                """
                SELECT timestamp, source, event_type, description, risk_score, tags_json, related_json, created_at
                FROM timeline WHERE case_id = ? ORDER BY COALESCE(timestamp, created_at) ASC
                """,
                (case_id,),
            ).fetchall()
        out: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            raw_tags = item.pop("tags_json")
            raw_related = item.pop("related_json")
            try:
                item["tags"] = json.loads(raw_tags)
            except (json.JSONDecodeError, TypeError):
                logger.warning(
                    "Corrupted tags_json for timeline event at %s: %.100r",
                    item.get("timestamp"), raw_tags,
                )
                item["tags"] = []
            try:
                item["related"] = json.loads(raw_related)
            except (json.JSONDecodeError, TypeError):
                logger.warning(
                    "Corrupted related_json for timeline event at %s: %.100r",
                    item.get("timestamp"), raw_related,
                )
                item["related"] = {}
            out.append(item)
        return out

    def replace_case_iocs(self, case_id: str, iocs: list[IOC]) -> None:
        now = utc_now_iso()
        with self.connect() as con:
            con.execute("DELETE FROM case_iocs WHERE case_id = ?", (case_id,))
            con.executemany(
                """
                INSERT INTO case_iocs(
                    case_id, ioc_id, ioc_type, value, first_seen, last_seen,
                    sources_json, metadata_json, created_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        case_id,
                        ioc.ioc_id,
                        ioc.ioc_type,
                        ioc.value,
                        ioc.first_seen,
                        ioc.last_seen,
                        json.dumps(ioc.sources),
                        json.dumps(ioc.metadata),
                        now,
                    )
                    for ioc in iocs
                ],
            )

    def get_case_iocs(self, case_id: str) -> list[dict[str, Any]]:
        with self.connect() as con:
            rows = con.execute(
                """
                SELECT ioc_id, ioc_type, value, first_seen, last_seen, sources_json, metadata_json
                FROM case_iocs WHERE case_id = ? ORDER BY ioc_type ASC, value ASC
                """,
                (case_id,),
            ).fetchall()
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
        with self.connect() as con:
            row = con.execute(
                """
                SELECT verdict, confidence, details_json, fetched_at
                FROM ioc_enrichment_cache
                WHERE ioc_type = ? AND value = ? AND provider = ?
                """,
                (ioc_type, value, provider),
            ).fetchone()
        if row is None:
            return None

        fetched_at = str(row["fetched_at"])
        if ttl_minutes > 0:
            clean = fetched_at.replace("Z", "+00:00")
            try:
                fetched_dt = datetime.fromisoformat(clean)
            except ValueError:
                return None
            now_dt = datetime.now(timezone.utc)
            if fetched_dt.tzinfo is None:
                fetched_dt = fetched_dt.replace(tzinfo=timezone.utc)
            age_seconds = (now_dt - fetched_dt).total_seconds()
            if age_seconds > (ttl_minutes * 60):
                return None

        return IOCEnrichment(
            enrichment_id=f"cache-{ioc_type}-{provider}",
            ioc_id="",
            provider=provider,
            verdict=str(row["verdict"]),
            confidence=float(row["confidence"]),
            details=json.loads(row["details_json"]),
            fetched_at=fetched_at,
        )

    def upsert_ioc_enrichment_cache(self, ioc_type: str, value: str, enrichment: IOCEnrichment) -> None:
        now = utc_now_iso()
        with self.connect() as con:
            con.execute(
                """
                INSERT INTO ioc_enrichment_cache(
                    ioc_type, value, provider, verdict, confidence, details_json, fetched_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ioc_type, value, provider) DO UPDATE SET
                    verdict=excluded.verdict,
                    confidence=excluded.confidence,
                    details_json=excluded.details_json,
                    fetched_at=excluded.fetched_at
                """,
                (
                    ioc_type,
                    value,
                    enrichment.provider,
                    enrichment.verdict,
                    enrichment.confidence,
                    json.dumps(enrichment.details),
                    enrichment.fetched_at or now,
                ),
            )

    def get_case_ioc_enrichments(self, case_id: str) -> list[dict[str, Any]]:
        with self.connect() as con:
            rows = con.execute(
                """
                SELECT ci.ioc_id, ci.ioc_type, ci.value, ec.provider, ec.verdict, ec.confidence, ec.details_json, ec.fetched_at
                FROM case_iocs ci
                JOIN ioc_enrichment_cache ec
                  ON ci.ioc_type = ec.ioc_type AND ci.value = ec.value
                WHERE ci.case_id = ?
                ORDER BY ci.ioc_type ASC, ci.value ASC, ec.provider ASC
                """,
                (case_id,),
            ).fetchall()
        out: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["details"] = json.loads(item.pop("details_json"))
            out.append(item)
        return out

    def append_evidence_hash_log(self, case_id: str, entries: list[dict[str, Any]]) -> None:
        now = utc_now_iso()
        with self.connect() as con:
            con.executemany(
                """
                INSERT INTO evidence_hash_log(case_id, rel_path, sha256, size_bytes, logged_at)
                VALUES(?, ?, ?, ?, ?)
                """,
                [
                    (
                        case_id,
                        str(item.get("rel_path", "")),
                        str(item.get("sha256", "")),
                        int(item.get("size_bytes", 0)),
                        now,
                    )
                    for item in entries
                ],
            )

    def get_evidence_hash_log(self, case_id: str) -> list[dict[str, Any]]:
        with self.connect() as con:
            rows = con.execute(
                """
                SELECT rel_path, sha256, size_bytes, logged_at
                FROM evidence_hash_log
                WHERE case_id = ?
                ORDER BY hash_pk ASC
                """,
                (case_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def add_analyst_note(self, case_id: str, author: str, content: str) -> dict[str, Any]:
        now = utc_now_iso()
        with self.connect() as con:
            cur = con.execute(
                """
                INSERT INTO analyst_notes(case_id, note_id, author, content, created_at)
                VALUES(?, hex(randomblob(8)), ?, ?, ?)
                """,
                (case_id, author, content, now),
            )
            row_id = int(cur.lastrowid or 0)
            row = con.execute(
                """
                SELECT note_id, author, content, created_at
                FROM analyst_notes WHERE note_pk = ?
                """,
                (row_id,),
            ).fetchone()
        return dict(row) if row else {"note_id": "", "author": author, "content": content, "created_at": now}

    def get_analyst_notes(self, case_id: str) -> list[dict[str, Any]]:
        with self.connect() as con:
            rows = con.execute(
                """
                SELECT note_id, author, content, created_at
                FROM analyst_notes
                WHERE case_id = ?
                ORDER BY note_pk ASC
                """,
                (case_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def list_workspace_views(self, case_id: str) -> list[dict[str, Any]]:
        with self.connect() as con:
            rows = con.execute(
                """
                SELECT view_id, name, section, filters_json, sort_json, layout_json,
                       created_at, updated_at
                FROM workspace_views
                WHERE case_id = ?
                ORDER BY updated_at DESC, name ASC
                """,
                (case_id,),
            ).fetchall()
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
        with self.connect() as con:
            con.execute(
                """
                INSERT INTO workspace_views(
                    view_id, case_id, name, section, filters_json, sort_json,
                    layout_json, created_at, updated_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(view_id) DO UPDATE SET
                    name=excluded.name,
                    section=excluded.section,
                    filters_json=excluded.filters_json,
                    sort_json=excluded.sort_json,
                    layout_json=excluded.layout_json,
                    updated_at=excluded.updated_at
                """,
                (
                    clean_view_id,
                    case_id,
                    name,
                    section,
                    json.dumps(filters or {}),
                    json.dumps(sort or {}),
                    json.dumps(layout or {}),
                    now,
                    now,
                ),
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
        with self.connect() as con:
            cur = con.execute(
                "DELETE FROM workspace_views WHERE case_id = ? AND view_id = ?",
                (case_id, view_id),
            )
        return int(cur.rowcount or 0) > 0

    def list_notebook_entries(self, case_id: str) -> list[dict[str, Any]]:
        with self.connect() as con:
            rows = con.execute(
                """
                SELECT entry_id, kind, title, body, links_json, created_at, updated_at
                FROM notebook_entries
                WHERE case_id = ?
                ORDER BY updated_at DESC, created_at DESC
                """,
                (case_id,),
            ).fetchall()
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
        with self.connect() as con:
            con.execute(
                """
                INSERT INTO notebook_entries(
                    entry_id, case_id, kind, title, body, links_json,
                    created_at, updated_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry_id,
                    case_id,
                    kind,
                    title,
                    body,
                    json.dumps(links or {}),
                    now,
                    now,
                ),
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
        current_rows = [
            item
            for item in self.list_notebook_entries(case_id)
            if str(item.get("entry_id")) == entry_id
        ]
        if not current_rows:
            return None
        current = current_rows[0]
        now = utc_now_iso()
        next_title = title if title is not None else str(current.get("title") or "")
        next_body = body if body is not None else str(current.get("body") or "")
        next_kind = kind if kind is not None else str(current.get("kind") or "note")
        next_links = links if links is not None else dict(current.get("links") or {})
        with self.connect() as con:
            con.execute(
                """
                UPDATE notebook_entries
                SET kind = ?, title = ?, body = ?, links_json = ?, updated_at = ?
                WHERE case_id = ? AND entry_id = ?
                """,
                (
                    next_kind,
                    next_title,
                    next_body,
                    json.dumps(next_links),
                    now,
                    case_id,
                    entry_id,
                ),
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
        with self.connect() as con:
            con.execute(
                """
                INSERT INTO agent_sessions(
                    session_id, case_id, goal, status, model_config_json, summary,
                    error, created_at, updated_at, completed_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    clean_session_id,
                    case_id,
                    goal,
                    status,
                    json.dumps(model_config or {}),
                    summary,
                    error,
                    now,
                    now,
                ),
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
        with self.connect() as con:
            row = con.execute(
                """
                SELECT session_id, case_id, goal, status, model_config_json, summary,
                       error, created_at, updated_at, completed_at
                FROM agent_sessions
                WHERE session_id = ?
                """,
                (session_id,),
            ).fetchone()
            if row is None:
                return None
            current = dict(row)
            now = utc_now_iso()
            con.execute(
                """
                UPDATE agent_sessions
                SET status = ?, summary = ?, error = ?, updated_at = ?, completed_at = ?
                WHERE session_id = ?
                """,
                (
                    status if status is not None else current["status"],
                    summary if summary is not None else current["summary"],
                    error if error is not None else current["error"],
                    now,
                    completed_at if completed_at is not None else current["completed_at"],
                    session_id,
                ),
            )
            current["status"] = status if status is not None else current["status"]
            current["summary"] = summary if summary is not None else current["summary"]
            current["error"] = error if error is not None else current["error"]
            current["updated_at"] = now
            current["completed_at"] = (
                completed_at if completed_at is not None else current["completed_at"]
            )
        current["model_config"] = json.loads(current.pop("model_config_json"))
        return current

    def list_agent_sessions(self, case_id: str) -> list[dict[str, Any]]:
        with self.connect() as con:
            rows = con.execute(
                """
                SELECT session_id, case_id, goal, status, model_config_json, summary,
                       error, created_at, updated_at, completed_at
                FROM agent_sessions
                WHERE case_id = ?
                ORDER BY updated_at DESC
                """,
                (case_id,),
            ).fetchall()
        output: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["model_config"] = json.loads(item.pop("model_config_json"))
            output.append(item)
        return output

    def get_agent_session(self, case_id: str, session_id: str) -> dict[str, Any] | None:
        sessions = self.list_agent_sessions(case_id)
        for item in sessions:
            if str(item.get("session_id")) == session_id:
                return item
        return None

    def replace_agent_steps(self, session_id: str, steps: list[dict[str, Any]]) -> None:
        with self.connect() as con:
            con.execute("DELETE FROM agent_steps WHERE session_id = ?", (session_id,))
            if not steps:
                return
            con.executemany(
                """
                INSERT INTO agent_steps(
                    step_id, session_id, step_index, title, rationale,
                    linked_entities_json, proposed_action_json, approval_state,
                    result_json, created_at, updated_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        str(step.get("step_id") or uuid.uuid4().hex[:16]),
                        session_id,
                        int(step.get("step_index", 0) or 0),
                        str(step.get("title") or ""),
                        str(step.get("rationale") or ""),
                        json.dumps(step.get("linked_entities") or {}),
                        json.dumps(step.get("proposed_action") or {}),
                        str(step.get("approval_state") or "not_required"),
                        json.dumps(step.get("result") or {}),
                        str(step.get("created_at") or utc_now_iso()),
                        str(step.get("updated_at") or utc_now_iso()),
                    )
                    for step in steps
                ],
            )

    def list_agent_steps(self, session_id: str) -> list[dict[str, Any]]:
        with self.connect() as con:
            rows = con.execute(
                """
                SELECT step_id, session_id, step_index, title, rationale,
                       linked_entities_json, proposed_action_json, approval_state,
                       result_json, created_at, updated_at
                FROM agent_steps
                WHERE session_id = ?
                ORDER BY step_index ASC, created_at ASC
                """,
                (session_id,),
            ).fetchall()
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
        with self.connect() as con:
            con.execute(
                "DELETE FROM agent_recommendations WHERE session_id = ?",
                (session_id,),
            )
            if not recommendations:
                return
            con.executemany(
                """
                INSERT INTO agent_recommendations(
                    recommendation_id, session_id, case_id, priority, title, reason,
                    linked_entities_json, suggested_action_json, status, confidence,
                    evidence_count, created_at, updated_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        str(item.get("recommendation_id") or uuid.uuid4().hex[:16]),
                        session_id,
                        case_id,
                        int(item.get("priority", 0) or 0),
                        str(item.get("title") or ""),
                        str(item.get("reason") or ""),
                        json.dumps(item.get("linked_entities") or {}),
                        json.dumps(item.get("suggested_action") or {}),
                        str(item.get("status") or "pending"),
                        float(item.get("confidence", 0) or 0),
                        int(item.get("evidence_count", 0) or 0),
                        str(item.get("created_at") or utc_now_iso()),
                        str(item.get("updated_at") or utc_now_iso()),
                    )
                    for item in recommendations
                ],
            )

    def list_agent_recommendations(self, session_id: str) -> list[dict[str, Any]]:
        with self.connect() as con:
            rows = con.execute(
                """
                SELECT recommendation_id, session_id, case_id, priority, title, reason,
                       linked_entities_json, suggested_action_json, status, confidence,
                       evidence_count, created_at, updated_at
                FROM agent_recommendations
                WHERE session_id = ?
                ORDER BY priority DESC, updated_at DESC
                """,
                (session_id,),
            ).fetchall()
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
        # Deduplicate nodes by node_id to prevent UNIQUE constraint failures.
        seen_node_ids: set[str] = set()
        unique_nodes: list[dict[str, Any]] = []
        for node in nodes:
            nid = str(node.get("node_id"))
            if nid not in seen_node_ids:
                seen_node_ids.add(nid)
                unique_nodes.append(node)
        now = utc_now_iso()
        with self.connect() as con:
            con.execute("DELETE FROM graph_nodes WHERE case_id = ?", (case_id,))
            con.execute("DELETE FROM graph_edges WHERE case_id = ?", (case_id,))
            if unique_nodes:
                con.executemany(
                    """
                    INSERT OR REPLACE INTO graph_nodes(
                        node_id, case_id, node_type, label, score, metadata_json, created_at
                    ) VALUES(?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            str(node.get("node_id") or uuid.uuid4().hex[:16]),
                            case_id,
                            str(node.get("node_type") or ""),
                            str(node.get("label") or ""),
                            float(node.get("score", 0) or 0),
                            json.dumps(node.get("metadata") or {}),
                            str(node.get("created_at") or now),
                        )
                        for node in unique_nodes
                    ],
                )
            if edges:
                con.executemany(
                    """
                    INSERT OR REPLACE INTO graph_edges(
                        edge_id, case_id, source_node_id, target_node_id, relation,
                        confidence, metadata_json, created_at
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            str(edge.get("edge_id") or uuid.uuid4().hex[:16]),
                            case_id,
                            str(edge.get("source_node_id") or ""),
                            str(edge.get("target_node_id") or ""),
                            str(edge.get("relation") or ""),
                            float(edge.get("confidence", 0) or 0),
                            json.dumps(edge.get("metadata") or {}),
                            str(edge.get("created_at") or now),
                        )
                        for edge in edges
                    ],
                )

    def get_case_graph(self, case_id: str) -> dict[str, list[dict[str, Any]]]:
        with self.connect() as con:
            node_rows = con.execute(
                """
                SELECT node_id, case_id, node_type, label, score, metadata_json, created_at
                FROM graph_nodes
                WHERE case_id = ?
                ORDER BY score DESC, label ASC
                """,
                (case_id,),
            ).fetchall()
            edge_rows = con.execute(
                """
                SELECT edge_id, case_id, source_node_id, target_node_id, relation,
                       confidence, metadata_json, created_at
                FROM graph_edges
                WHERE case_id = ?
                ORDER BY confidence DESC, relation ASC
                """,
                (case_id,),
            ).fetchall()
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
        now = utc_now_iso()
        with self.connect() as con:
            con.execute(
                """
                INSERT INTO audit_log(case_id, action, actor, details_json, created_at)
                VALUES(?, ?, ?, ?, ?)
                """,
                (case_id, action, actor, json.dumps(details or {}), now),
            )

    def get_audit_log(self, case_id: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        with self.connect() as con:
            if case_id is None:
                rows = con.execute(
                    """
                    SELECT case_id, action, actor, details_json, created_at
                    FROM audit_log
                    ORDER BY audit_pk DESC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
            else:
                rows = con.execute(
                    """
                    SELECT case_id, action, actor, details_json, created_at
                    FROM audit_log
                    WHERE case_id = ?
                    ORDER BY audit_pk DESC
                    LIMIT ?
                    """,
                    (case_id, limit),
                ).fetchall()
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
        with self.connect() as con:
            con.execute(
                """
                INSERT INTO analysis_jobs(
                    job_id, case_id, job_type, state, progress, message, error, result_json, created_at, updated_at
                )
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(job_id) DO UPDATE SET
                    job_type=excluded.job_type,
                    state=excluded.state,
                    progress=excluded.progress,
                    message=excluded.message,
                    error=excluded.error,
                    result_json=excluded.result_json,
                    updated_at=excluded.updated_at
                """,
                (
                    job_id,
                    case_id,
                    job_type,
                    state,
                    int(progress),
                    message,
                    error,
                    json.dumps(result) if result is not None else None,
                    now,
                    now,
                ),
            )

    def get_case_latest_job(self, case_id: str, job_type: str = "analysis") -> dict[str, Any] | None:
        with self.connect() as con:
            row = con.execute(
                """
                SELECT job_id, case_id, job_type, state, progress, message, error, result_json, created_at, updated_at
                FROM analysis_jobs
                WHERE case_id = ? AND job_type = ?
                ORDER BY updated_at DESC
                LIMIT 1
                """,
                (case_id, job_type),
            ).fetchone()
        if row is None:
            return None
        item = dict(row)
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
        with self.connect() as con:
            if job_type:
                rows = con.execute(
                    """
                    SELECT job_id, case_id, job_type, state, progress, message, error, result_json, created_at, updated_at
                    FROM analysis_jobs
                    WHERE case_id = ? AND job_type = ?
                    ORDER BY updated_at DESC
                    LIMIT ?
                    """,
                    (case_id, job_type, limit),
                ).fetchall()
            else:
                rows = con.execute(
                    """
                    SELECT job_id, case_id, job_type, state, progress, message, error, result_json, created_at, updated_at
                    FROM analysis_jobs
                    WHERE case_id = ?
                    ORDER BY updated_at DESC
                    LIMIT ?
                    """,
                    (case_id, limit),
                ).fetchall()
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
        with self.connect() as con:
            if job_type:
                cur = con.execute(
                    """
                    DELETE FROM analysis_jobs
                    WHERE job_type = ? AND COALESCE(updated_at, created_at) < ?
                    """,
                    (job_type, cutoff),
                )
            else:
                cur = con.execute(
                    """
                    DELETE FROM analysis_jobs
                    WHERE COALESCE(updated_at, created_at) < ?
                    """,
                    (cutoff,),
                )
        return int(cur.rowcount or 0)

    def search_case(self, case_id: str, query: str, limit: int = 100) -> dict[str, list[dict[str, Any]]]:
        # Escape LIKE special characters so literal % and _ in query are matched correctly.
        escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        needle = f"%{escaped}%"
        with self.connect() as con:
            finding_rows = con.execute(
                """
                SELECT finding_id, title, severity, confidence, tactic, evidence_json, recommendation, created_at
                FROM findings
                WHERE case_id = ?
                  AND (
                    title LIKE ? ESCAPE '\\'
                    OR evidence_json LIKE ? ESCAPE '\\'
                    OR recommendation LIKE ? ESCAPE '\\'
                    OR tactic LIKE ? ESCAPE '\\'
                  )
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (case_id, needle, needle, needle, needle, limit),
            ).fetchall()

            timeline_rows = con.execute(
                """
                SELECT timestamp, source, event_type, description, risk_score, tags_json, related_json, created_at
                FROM timeline
                WHERE case_id = ?
                  AND (
                    source LIKE ? ESCAPE '\\'
                    OR event_type LIKE ? ESCAPE '\\'
                    OR description LIKE ? ESCAPE '\\'
                    OR related_json LIKE ? ESCAPE '\\'
                  )
                ORDER BY COALESCE(timestamp, created_at) ASC
                LIMIT ?
                """,
                (case_id, needle, needle, needle, needle, limit),
            ).fetchall()

            ioc_rows = con.execute(
                """
                SELECT ioc_id, ioc_type, value, first_seen, last_seen, sources_json, metadata_json
                FROM case_iocs
                WHERE case_id = ?
                  AND (
                    ioc_type LIKE ? ESCAPE '\\'
                    OR value LIKE ? ESCAPE '\\'
                    OR metadata_json LIKE ? ESCAPE '\\'
                  )
                ORDER BY ioc_type ASC, value ASC
                LIMIT ?
                """,
                (case_id, needle, needle, needle, limit),
            ).fetchall()

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
