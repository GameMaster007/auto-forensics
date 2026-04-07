"""SQLAlchemy table definitions for auto_forensics.

This module is imported by db_sqlalchemy.py and should not be used directly.
"""

from __future__ import annotations

from typing import Any


def define_tables(sa: Any, md: Any) -> dict[str, Any]:
    """Define all database tables and return them as a dictionary.

    Args:
        sa: The sqlalchemy module.
        md: The MetaData object to attach tables to.

    Returns:
        Dictionary mapping table names to Table objects.
    """
    cases = sa.Table(
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

    artifacts = sa.Table(
        "artifacts",
        md,
        sa.Column("artifact_pk", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("case_id", sa.String(128), sa.ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False),
        sa.Column("rel_path", sa.Text, nullable=False),
        sa.Column("artifact_type", sa.Text, nullable=False),
        sa.Column("size_bytes", sa.Integer, nullable=False),
        sa.Column("sha256", sa.String(128), nullable=False),
        sa.Column("ingested_at", sa.Text, nullable=False),
        sa.Column("metadata_json", sa.Text, nullable=False),
    )

    findings = sa.Table(
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

    timeline = sa.Table(
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

    case_iocs = sa.Table(
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

    ioc_enrichment_cache = sa.Table(
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

    analyst_notes = sa.Table(
        "analyst_notes",
        md,
        sa.Column("note_pk", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("case_id", sa.String(128), sa.ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False),
        sa.Column("note_id", sa.String(64), nullable=False),
        sa.Column("author", sa.String(128), nullable=False),
        sa.Column("content", sa.Text, nullable=False),
        sa.Column("created_at", sa.Text, nullable=False),
    )

    workspace_views = sa.Table(
        "workspace_views",
        md,
        sa.Column("view_id", sa.String(64), primary_key=True),
        sa.Column("case_id", sa.String(128), sa.ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("section", sa.String(64), nullable=False),
        sa.Column("filters_json", sa.Text, nullable=False),
        sa.Column("sort_json", sa.Text, nullable=False),
        sa.Column("layout_json", sa.Text, nullable=False),
        sa.Column("created_at", sa.Text, nullable=False),
        sa.Column("updated_at", sa.Text, nullable=False),
    )

    notebook_entries = sa.Table(
        "notebook_entries",
        md,
        sa.Column("entry_id", sa.String(64), primary_key=True),
        sa.Column("case_id", sa.String(128), sa.ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False),
        sa.Column("kind", sa.String(64), nullable=False),
        sa.Column("title", sa.Text, nullable=False),
        sa.Column("body", sa.Text, nullable=False),
        sa.Column("links_json", sa.Text, nullable=False),
        sa.Column("created_at", sa.Text, nullable=False),
        sa.Column("updated_at", sa.Text, nullable=False),
    )

    agent_sessions = sa.Table(
        "agent_sessions",
        md,
        sa.Column("session_id", sa.String(64), primary_key=True),
        sa.Column("case_id", sa.String(128), sa.ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False),
        sa.Column("goal", sa.Text, nullable=False),
        sa.Column("status", sa.String(64), nullable=False),
        sa.Column("model_config_json", sa.Text, nullable=False),
        sa.Column("summary", sa.Text, nullable=False, default=""),
        sa.Column("error", sa.Text, nullable=True),
        sa.Column("created_at", sa.Text, nullable=False),
        sa.Column("updated_at", sa.Text, nullable=False),
        sa.Column("completed_at", sa.Text, nullable=True),
    )

    agent_steps = sa.Table(
        "agent_steps",
        md,
        sa.Column("step_id", sa.String(64), primary_key=True),
        sa.Column(
            "session_id",
            sa.String(64),
            sa.ForeignKey("agent_sessions.session_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("step_index", sa.Integer, nullable=False),
        sa.Column("title", sa.Text, nullable=False),
        sa.Column("rationale", sa.Text, nullable=False),
        sa.Column("linked_entities_json", sa.Text, nullable=False),
        sa.Column("proposed_action_json", sa.Text, nullable=False),
        sa.Column("approval_state", sa.String(64), nullable=False),
        sa.Column("result_json", sa.Text, nullable=False),
        sa.Column("created_at", sa.Text, nullable=False),
        sa.Column("updated_at", sa.Text, nullable=False),
    )

    agent_recommendations = sa.Table(
        "agent_recommendations",
        md,
        sa.Column("recommendation_id", sa.String(64), primary_key=True),
        sa.Column(
            "session_id",
            sa.String(64),
            sa.ForeignKey("agent_sessions.session_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("case_id", sa.String(128), sa.ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False),
        sa.Column("priority", sa.Integer, nullable=False),
        sa.Column("title", sa.Text, nullable=False),
        sa.Column("reason", sa.Text, nullable=False),
        sa.Column("linked_entities_json", sa.Text, nullable=False),
        sa.Column("suggested_action_json", sa.Text, nullable=False),
        sa.Column("status", sa.String(64), nullable=False),
        sa.Column("confidence", sa.Float, nullable=False, default=0.0),
        sa.Column("evidence_count", sa.Integer, nullable=False, default=0),
        sa.Column("created_at", sa.Text, nullable=False),
        sa.Column("updated_at", sa.Text, nullable=False),
    )

    graph_nodes = sa.Table(
        "graph_nodes",
        md,
        sa.Column("node_id", sa.String(64), primary_key=True),
        sa.Column("case_id", sa.String(128), sa.ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False),
        sa.Column("node_type", sa.String(64), nullable=False),
        sa.Column("label", sa.Text, nullable=False),
        sa.Column("score", sa.Float, nullable=False, default=0.0),
        sa.Column("metadata_json", sa.Text, nullable=False),
        sa.Column("created_at", sa.Text, nullable=False),
    )

    graph_edges = sa.Table(
        "graph_edges",
        md,
        sa.Column("edge_id", sa.String(64), primary_key=True),
        sa.Column("case_id", sa.String(128), sa.ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False),
        sa.Column("source_node_id", sa.String(64), nullable=False),
        sa.Column("target_node_id", sa.String(64), nullable=False),
        sa.Column("relation", sa.String(64), nullable=False),
        sa.Column("confidence", sa.Float, nullable=False, default=0.0),
        sa.Column("metadata_json", sa.Text, nullable=False),
        sa.Column("created_at", sa.Text, nullable=False),
    )

    evidence_hash_log = sa.Table(
        "evidence_hash_log",
        md,
        sa.Column("hash_pk", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("case_id", sa.String(128), sa.ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False),
        sa.Column("rel_path", sa.Text, nullable=False),
        sa.Column("sha256", sa.String(128), nullable=False),
        sa.Column("size_bytes", sa.Integer, nullable=False),
        sa.Column("logged_at", sa.Text, nullable=False),
    )

    audit_log = sa.Table(
        "audit_log",
        md,
        sa.Column("audit_pk", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("case_id", sa.String(128), nullable=True),
        sa.Column("action", sa.String(128), nullable=False),
        sa.Column("actor", sa.String(128), nullable=False),
        sa.Column("details_json", sa.Text, nullable=False),
        sa.Column("created_at", sa.Text, nullable=False),
    )

    schema_migrations = sa.Table(
        "schema_migrations",
        md,
        sa.Column("version", sa.Integer, primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("applied_at", sa.Text, nullable=False),
    )

    analysis_jobs = sa.Table(
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

    return {
        "cases": cases,
        "artifacts": artifacts,
        "findings": findings,
        "timeline": timeline,
        "case_iocs": case_iocs,
        "ioc_enrichment_cache": ioc_enrichment_cache,
        "analyst_notes": analyst_notes,
        "workspace_views": workspace_views,
        "notebook_entries": notebook_entries,
        "agent_sessions": agent_sessions,
        "agent_steps": agent_steps,
        "agent_recommendations": agent_recommendations,
        "graph_nodes": graph_nodes,
        "graph_edges": graph_edges,
        "evidence_hash_log": evidence_hash_log,
        "audit_log": audit_log,
        "schema_migrations": schema_migrations,
        "analysis_jobs": analysis_jobs,
    }
