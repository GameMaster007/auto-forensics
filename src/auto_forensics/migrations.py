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
        name="add_workspace_tables",
        sql_statements=(
            """
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
            )
            """,
            """
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
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_workspace_views_case ON workspace_views(case_id, updated_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_notebook_entries_case ON notebook_entries(case_id, updated_at DESC)",
        ),
    ),
    MigrationStep(
        version=5,
        name="add_agent_session_tables",
        sql_statements=(
            """
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
            )
            """,
            """
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
            )
            """,
            """
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
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_agent_sessions_case ON agent_sessions(case_id, updated_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_agent_steps_session ON agent_steps(session_id, step_index ASC)",
            "CREATE INDEX IF NOT EXISTS idx_agent_recommendations_session ON agent_recommendations(session_id, priority DESC)",
        ),
    ),
    MigrationStep(
        version=6,
        name="add_graph_tables",
        sql_statements=(
            """
            CREATE TABLE IF NOT EXISTS graph_nodes (
                node_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                node_type TEXT NOT NULL,
                label TEXT NOT NULL,
                score REAL NOT NULL DEFAULT 0,
                metadata_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE
            )
            """,
            """
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
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_graph_nodes_case ON graph_nodes(case_id, node_type)",
            "CREATE INDEX IF NOT EXISTS idx_graph_edges_case ON graph_edges(case_id, relation)",
        ),
    ),
)


LATEST_SCHEMA_VERSION = MIGRATION_STEPS[-1].version if MIGRATION_STEPS else 0
