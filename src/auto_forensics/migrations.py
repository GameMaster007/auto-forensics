from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


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


def validate_finding_rebuild(
    columns: set[str], *, incoming_references: bool = False,
    indexes: list[dict[str, Any]] | None = None, foreign_keys: list[dict[str, Any]] | None = None,
    extra_constraints: bool = False,
) -> None:
    if columns != FINDING_V5_COLUMNS:
        raise SchemaCompatibilityError("Findings has an unrecognized column layout; refusing to discard data")
    if incoming_references:
        raise SchemaCompatibilityError("Findings has external foreign-key references; refusing to discard dependent data")
    canonical_indexes = {"idx_findings_case": ["case_id"], "idx_findings_case_title": ["case_id", "title"]}
    for index in indexes or []:
        if (canonical_indexes.get(index["name"]) != index.get("column_names")
                or index.get("unique") or any((index.get("dialect_options") or {}).values())):
            extra_constraints = True
    if foreign_keys is not None:
        if len(foreign_keys) != 1:
            extra_constraints = True
        for foreign_key in foreign_keys:
            options = foreign_key.get("options") or {}
            if (foreign_key.get("constrained_columns") != ["case_id"]
                    or foreign_key.get("referred_table") != "cases"
                    or foreign_key.get("referred_columns") != ["case_id"]
                    or str(options.get("ondelete", "")).upper() != "CASCADE"
                    or str(options.get("onupdate") or "NO ACTION").upper() != "NO ACTION"
                    or options.get("deferrable")):
                extra_constraints = True
    if extra_constraints:
        raise SchemaCompatibilityError("Findings has custom indexes, triggers, or constraints; refusing to discard schema behavior")


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
    MigrationStep(
        version=7,
        name="preserve_finding_review_and_verification_details",
        sql_statements=("ALTER TABLE findings ADD COLUMN details_json TEXT NOT NULL DEFAULT '{}'",),
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
