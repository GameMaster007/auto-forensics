from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from .migrations import LATEST_SCHEMA_VERSION, MIGRATION_STEPS
from .models import IOC, Finding, IOCEnrichment, TimelineEvent, citations_as_json, decode_finding_row, utc_now_iso

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
                    evidence_json, recommendation, created_at,
                    citations_json, origin, review_status, worker
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                        citations_as_json(f.citations),
                        f.origin,
                        f.review_status,
                        f.worker,
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
                SELECT finding_id, title, severity, confidence, tactic, evidence_json, recommendation,
                       created_at, citations_json, origin, review_status, worker
                FROM findings WHERE case_id = ? ORDER BY created_at DESC
                """,
                (case_id,),
            ).fetchall()
        return [decode_finding_row(dict(row)) for row in rows]

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
                item["tags"] = []
            try:
                item["related"] = json.loads(raw_related)
            except (json.JSONDecodeError, TypeError):
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
                SELECT finding_id, title, severity, confidence, tactic, evidence_json, recommendation,
                       created_at, citations_json, origin, review_status, worker
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

        finding_out = [decode_finding_row(dict(row)) for row in finding_rows]

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
