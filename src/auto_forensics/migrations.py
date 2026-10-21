from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class MigrationStep:
    version: int
    name: str
    sql_statements: tuple[str, ...]


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
)


LATEST_SCHEMA_VERSION = MIGRATION_STEPS[-1].version if MIGRATION_STEPS else 0
