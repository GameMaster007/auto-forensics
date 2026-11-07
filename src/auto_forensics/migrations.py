from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class MigrationStep:
    version: int
    name: str
    sql_statements: tuple[str, ...]


class SchemaVersionError(RuntimeError):
    """This program cannot safely modify a database created by newer code."""


class SchemaCompatibilityError(RuntimeError):
    """A table has an unrecognized layout that must not be rebuilt blindly."""


FINDING_V5_COLUMNS = {
    "finding_id", "case_id", "title", "severity", "confidence", "tactic",
    "evidence_json", "recommendation", "created_at", "citations_json",
    "origin", "review_status", "worker",
}


def validate_finding_rebuild(columns: set[str]) -> None:
    if columns != FINDING_V5_COLUMNS:
        raise SchemaCompatibilityError("Findings has an unrecognized column layout; refusing to discard data")


MIGRATION_STEPS: tuple[MigrationStep, ...] = (
    MigrationStep(
        version=1,
        name="add_analysis_jobs_table",
        sql_statements=(
            """
            CREATE TABLE IF NOT EXISTS analysis_jobs (
                job_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                state TEXT NOT NULL,
                progress INTEGER NOT NULL DEFAULT 0,
                message TEXT NOT NULL DEFAULT '',
                error TEXT,
                result_json TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_analysis_jobs_case ON analysis_jobs(case_id)",
        ),
    ),
    MigrationStep(
        version=2,
        name="add_search_indexes",
        sql_statements=(
            "CREATE INDEX IF NOT EXISTS idx_findings_case_title ON findings(case_id, title)",
            "CREATE INDEX IF NOT EXISTS idx_timeline_case_event ON timeline(case_id, event_type)",
            "CREATE INDEX IF NOT EXISTS idx_case_iocs_case_value ON case_iocs(case_id, value)",
        ),
    ),
    MigrationStep(
        version=3,
        name="add_analysis_job_type",
        sql_statements=(
            "ALTER TABLE analysis_jobs ADD COLUMN job_type TEXT NOT NULL DEFAULT 'analysis'",
            "CREATE INDEX IF NOT EXISTS idx_analysis_jobs_case_type ON analysis_jobs(case_id, job_type, updated_at)",
        ),
    ),
    MigrationStep(
        version=4,
        name="add_finding_citations",
        sql_statements=(
            "ALTER TABLE findings ADD COLUMN citations_json TEXT NOT NULL DEFAULT '[]'",
            "ALTER TABLE findings ADD COLUMN origin TEXT NOT NULL DEFAULT 'detector'",
            "ALTER TABLE findings ADD COLUMN review_status TEXT NOT NULL DEFAULT 'unverified'",
        ),
    ),
    MigrationStep(
        version=5,
        name="add_finding_worker",
        sql_statements=("ALTER TABLE findings ADD COLUMN worker TEXT NOT NULL DEFAULT 'pipeline'",),
    ),
    MigrationStep(
        version=6,
        name="scope_finding_ids_to_case",
        sql_statements=(
            """
            CREATE TABLE findings_case_scoped (
                finding_id TEXT NOT NULL,
                case_id TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence DOUBLE PRECISION NOT NULL,
                tactic TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                created_at TEXT NOT NULL,
                citations_json TEXT NOT NULL DEFAULT '[]',
                origin TEXT NOT NULL DEFAULT 'detector',
                review_status TEXT NOT NULL DEFAULT 'unverified',
                worker TEXT NOT NULL DEFAULT 'pipeline',
                PRIMARY KEY(case_id, finding_id),
                FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE
            )
            """,
            """
            INSERT INTO findings_case_scoped (
                finding_id, case_id, title, severity, confidence, tactic,
                evidence_json, recommendation, created_at, citations_json,
                origin, review_status, worker
            ) SELECT finding_id, case_id, title, severity, confidence, tactic,
                evidence_json, recommendation, created_at, citations_json,
                origin, review_status, worker FROM findings
            """,
            "DROP TABLE findings",
            "ALTER TABLE findings_case_scoped RENAME TO findings",
            "CREATE INDEX idx_findings_case ON findings(case_id)",
            "CREATE INDEX idx_findings_case_title ON findings(case_id, title)",
        ),
    ),
)


LATEST_SCHEMA_VERSION = MIGRATION_STEPS[-1].version if MIGRATION_STEPS else 0


def added_column(statement: str) -> tuple[str, str] | None:
    """Recognize our ADD COLUMN steps so existing columns can be skipped safely.

    Catching a duplicate-column exception leaves PostgreSQL's transaction
    aborted. Inspect the schema before executing instead.
    """
    match = re.match(r"\s*ALTER\s+TABLE\s+(\w+)\s+ADD\s+COLUMN\s+(\w+)", statement, re.IGNORECASE)
    return (match[1], match[2]) if match else None
