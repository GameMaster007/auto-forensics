from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


def _normalize_text(value: Any) -> str:
    return str(value or "").strip()


def _short_text(value: str, limit: int = 180) -> str:
    clean = " ".join(value.split())
    if len(clean) <= limit:
        return clean
    return clean[: limit - 1].rstrip() + "…"


def risk_level(score: float) -> str:
    if score >= 75:
        return "critical"
    if score >= 55:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def build_artifact_previews(
    artifacts: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    timeline: list[dict[str, Any]],
    iocs: list[dict[str, Any]],
    report_payload: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    report_payload = report_payload or {}
    binaries = report_payload.get("binary_features", [])
    binary_by_path: dict[str, dict[str, Any]] = {}
    for item in binaries:
        path = _normalize_text(item.get("path"))
        if path:
            binary_by_path[path.replace("\\", "/")] = item

    previews: list[dict[str, Any]] = []
    for artifact in artifacts:
        rel_path = _normalize_text(artifact.get("rel_path")).replace("\\", "/")
        metadata = dict(artifact.get("metadata") or {})
        finding_titles: list[str] = []
        event_hits = 0
        ioc_hits: list[str] = []
        risk_score = 0.0

        for finding in findings:
            evidence = " ".join(str(item) for item in finding.get("evidence", []))
            if rel_path and rel_path.lower() in evidence.lower():
                finding_titles.append(_normalize_text(finding.get("title")))
                risk_score = max(
                    risk_score,
                    float(finding.get("confidence", 0) or 0) * 100.0,
                )

        for event in timeline:
            blob = " ".join(
                [
                    _normalize_text(event.get("source")),
                    _normalize_text(event.get("description")),
                    json.dumps(event.get("related") or {}, sort_keys=True),
                ]
            )
            if rel_path and rel_path.lower() in blob.lower():
                event_hits += 1
                risk_score = max(risk_score, float(event.get("risk_score", 0) or 0))

        for ioc in iocs:
            sources = " ".join(str(item) for item in ioc.get("sources", []))
            if rel_path and rel_path.lower() in sources.lower():
                ioc_hits.append(_normalize_text(ioc.get("value")))

        binary = binary_by_path.get(rel_path)
        if binary:
            risk_score = max(
                risk_score,
                float(binary.get("suspicious_score", 0) or 0) * 20.0,
            )

        preview_summary = ""
        if finding_titles:
            preview_summary = _short_text("; ".join(finding_titles), limit=160)
        elif binary:
            preview_summary = _short_text(
                "; ".join(str(item) for item in binary.get("rationale", []))
                or "Binary analyzed with no narrative rationale.",
                limit=160,
            )
        elif event_hits:
            preview_summary = f"Referenced by {event_hits} timeline event(s)."
        else:
            preview_summary = "No derived alerts yet. Artifact is available for review."

        previews.append(
            {
                "rel_path": rel_path,
                "artifact_type": _normalize_text(artifact.get("artifact_type")),
                "size_bytes": int(artifact.get("size_bytes", 0) or 0),
                "sha256": _normalize_text(artifact.get("sha256")),
                "source_path": _normalize_text(metadata.get("source_path")) or None,
                "display_name": Path(rel_path).name or rel_path,
                "risk_score": round(risk_score, 2),
                "risk_level": risk_level(risk_score),
                "summary": preview_summary,
                "matched_findings": [item for item in finding_titles if item],
                "matched_timeline_events": event_hits,
                "ioc_hits": [item for item in ioc_hits if item],
                "available_outputs": {
                    "raw_artifact": True,
                    "report_json": bool(report_payload),
                    "report_html": bool(report_payload),
                },
                "metadata": metadata,
            }
        )

    previews.sort(
        key=lambda item: (
            float(item.get("risk_score", 0) or 0),
            -int(item.get("size_bytes", 0) or 0),
            str(item.get("rel_path", "")),
        ),
        reverse=True,
    )
    return previews


def build_case_threads(
    findings: list[dict[str, Any]],
    timeline: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for finding in findings:
        tactic = _normalize_text(finding.get("tactic")).lower() or "general"
        thread = grouped.setdefault(
            tactic,
            {
                "thread_id": f"thread-{tactic}",
                "title": tactic.replace("-", " ").title(),
                "severity": "low",
                "confidence": 0.0,
                "finding_ids": [],
                "timeline_events": 0,
                "event_types": set(),
            },
        )
        thread["finding_ids"].append(_normalize_text(finding.get("finding_id")))
        thread["confidence"] = max(
            float(thread["confidence"]),
            float(finding.get("confidence", 0) or 0),
        )
        sev = _normalize_text(finding.get("severity")).lower()
        if sev in {"critical", "high", "medium", "low"}:
            order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            if order.get(sev, 0) > order.get(thread["severity"], 0):
                thread["severity"] = sev

    for event in timeline:
        tags = [str(item).lower() for item in event.get("tags", [])]
        related = json.dumps(event.get("related") or {}).lower()
        linked_tactic = next((tag for tag in tags if tag in grouped), None)
        if not linked_tactic:
            for tactic in grouped:
                if tactic in related or tactic in _normalize_text(event.get("event_type")).lower():
                    linked_tactic = tactic
                    break
        if not linked_tactic:
            continue
        thread = grouped[linked_tactic]
        thread["timeline_events"] += 1
        thread["event_types"].add(_normalize_text(event.get("event_type")))

    output: list[dict[str, Any]] = []
    for thread in grouped.values():
        output.append(
            {
                "thread_id": thread["thread_id"],
                "title": thread["title"],
                "severity": thread["severity"],
                "confidence": round(float(thread["confidence"]), 2),
                "evidence_count": len(thread["finding_ids"])
                + int(thread["timeline_events"]),
                "finding_ids": [item for item in thread["finding_ids"] if item],
                "timeline_events": int(thread["timeline_events"]),
                "event_types": sorted(item for item in thread["event_types"] if item),
            }
        )
    output.sort(
        key=lambda item: (
            {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(
                str(item.get("severity")).lower(),
                0,
            ),
            float(item.get("confidence", 0) or 0),
            int(item.get("evidence_count", 0) or 0),
        ),
        reverse=True,
    )
    return output


def build_case_graph(
    case_id: str,
    artifacts: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    timeline: list[dict[str, Any]],
    iocs: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, Any]] = {}

    def add_node(node_type: str, label: str, score: float = 0.0) -> str:
        raw = f"{node_type}:{label.strip().lower()}"
        node_id = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]
        existing = nodes.get(node_id)
        payload = {
            "node_id": node_id,
            "case_id": case_id,
            "node_type": node_type,
            "label": label,
            "score": round(score, 2),
            "metadata": {},
        }
        if existing is None:
            nodes[node_id] = payload
        else:
            existing["score"] = round(max(float(existing.get("score", 0)), score), 2)
        return node_id

    def add_edge(
        source_id: str,
        target_id: str,
        relation: str,
        confidence: float = 0.0,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        raw = f"{source_id}:{relation}:{target_id}"
        edge_id = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]
        edges[edge_id] = {
            "edge_id": edge_id,
            "case_id": case_id,
            "source_node_id": source_id,
            "target_node_id": target_id,
            "relation": relation,
            "confidence": round(confidence, 2),
            "metadata": metadata or {},
        }

    artifact_nodes: dict[str, str] = {}
    for artifact in artifacts:
        rel_path = _normalize_text(artifact.get("rel_path"))
        if not rel_path:
            continue
        artifact_nodes[rel_path] = add_node(
            "artifact",
            rel_path,
            score=float(artifact.get("size_bytes", 0) or 0) / 1_000_000.0,
        )

    for ioc in iocs:
        value = _normalize_text(ioc.get("value"))
        ioc_type = _normalize_text(ioc.get("ioc_type")) or "ioc"
        if not value:
            continue
        node_type = {
            "ip": "ip",
            "domain": "domain",
            "url": "url",
            "sha256": "hash",
            "md5": "hash",
        }.get(ioc_type, "ioc")
        node_id = add_node(node_type, value, score=0.6)
        for source in ioc.get("sources", []):
            source_text = _normalize_text(source)
            for rel_path, artifact_id in artifact_nodes.items():
                if rel_path.lower() in source_text.lower():
                    add_edge(artifact_id, node_id, "observed_in", 0.8)

    finding_nodes: list[str] = []
    for finding in findings:
        title = _normalize_text(finding.get("title"))
        if not title:
            continue
        severity = _normalize_text(finding.get("severity")).lower()
        score = {"critical": 1.0, "high": 0.8, "medium": 0.55}.get(severity, 0.3)
        finding_id = add_node("finding", title, score=score)
        finding_nodes.append(finding_id)
        evidence = " ".join(str(item) for item in finding.get("evidence", []))
        for rel_path, artifact_id in artifact_nodes.items():
            if rel_path.lower() in evidence.lower():
                add_edge(artifact_id, finding_id, "related_to", score)

    for event in timeline:
        event_type = _normalize_text(event.get("event_type"))
        if not event_type:
            continue
        event_id = add_node(
            "event",
            event_type,
            score=float(event.get("risk_score", 0) or 0) / 100.0,
        )
        source_blob = " ".join(
            [
                _normalize_text(event.get("source")),
                _normalize_text(event.get("description")),
                json.dumps(event.get("related") or {}, sort_keys=True),
            ]
        ).lower()
        for rel_path, artifact_id in artifact_nodes.items():
            if rel_path.lower() in source_blob:
                add_edge(artifact_id, event_id, "extracted_from", 0.7)

    return list(nodes.values()), list(edges.values())


def build_agent_recommendations(
    case_id: str,
    overview: dict[str, Any],
    notebook_entries: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    findings = overview.get("findings", [])
    iocs = overview.get("iocs", [])
    enrichments = overview.get("ioc_enrichments", [])
    threads = overview.get("threads", [])
    recommendations: list[dict[str, Any]] = []

    if findings:
        top = findings[0]
        recommendations.append(
            {
                "case_id": case_id,
                "priority": 3,
                "title": "Validate the highest-risk finding",
                "reason": _short_text(
                    _normalize_text(top.get("title"))
                    or "A high-risk finding needs analyst validation."
                ),
                "linked_entities": {
                    "finding_ids": [_normalize_text(top.get("finding_id"))],
                },
                "suggested_action": {"action": "generate_verdict"},
                "status": "pending",
                "confidence": float(top.get("confidence", 0) or 0),
                "evidence_count": len(top.get("evidence", [])),
            }
        )

    if iocs and not enrichments:
        recommendations.append(
            {
                "case_id": case_id,
                "priority": 2,
                "title": "Run IOC enrichment",
                "reason": "Indicators were extracted but have not been enriched yet.",
                "linked_entities": {
                    "ioc_ids": [_normalize_text(item.get("ioc_id")) for item in iocs[:10]],
                },
                "suggested_action": {"action": "start_enrichment"},
                "status": "pending",
                "confidence": 0.8,
                "evidence_count": len(iocs),
            }
        )

    if not notebook_entries and findings:
        recommendations.append(
            {
                "case_id": case_id,
                "priority": 1,
                "title": "Capture a working hypothesis",
                "reason": "No notebook hypothesis exists yet for this case.",
                "linked_entities": {
                    "thread_ids": [_normalize_text(item.get("thread_id")) for item in threads[:5]],
                },
                "suggested_action": {"action": "generate_verdict"},
                "status": "pending",
                "confidence": 0.6,
                "evidence_count": len(threads),
            }
        )

    if not recommendations:
        recommendations.append(
            {
                "case_id": case_id,
                "priority": 1,
                "title": "Re-run analysis with refreshed workspace data",
                "reason": "Case state is sparse; another analysis pass may surface more context.",
                "linked_entities": {},
                "suggested_action": {"action": "rerun_analysis"},
                "status": "pending",
                "confidence": 0.45,
                "evidence_count": 0,
            }
        )
    return recommendations


def build_case_brief_markdown(overview: dict[str, Any]) -> str:
    case = overview.get("case", {})
    summary = overview.get("summary", {})
    findings = overview.get("findings", [])
    threads = overview.get("threads", [])
    notebook_entries = overview.get("notebook_entries", [])
    agent_sessions = overview.get("agent_sessions", [])

    lines = [
        f"# Analyst Brief: {case.get('case_id', 'unknown-case')}",
        "",
        f"- Status: {case.get('status', 'unknown')}",
        f"- Findings: {len(findings)}",
        f"- IOCs: {len(overview.get('iocs', []))}",
        f"- Timeline events: {len(overview.get('timeline', []))}",
        f"- Risk score: {summary.get('risk_score') or summary.get('total_risk_score') or 'n/a'}",
        "",
        "## Investigation Threads",
    ]
    if not threads:
        lines.append("- No investigation threads were generated.")
    else:
        for thread in threads[:10]:
            lines.append(
                f"- [{str(thread.get('severity', 'low')).upper()}] "
                f"{thread.get('title', 'Untitled thread')} "
                f"(confidence={thread.get('confidence', 0)}, "
                f"evidence={thread.get('evidence_count', 0)})"
            )

    lines.append("")
    lines.append("## Notebook Highlights")
    highlights = notebook_entries[:5]
    if not highlights:
        lines.append("- No notebook entries yet.")
    else:
        for entry in highlights:
            lines.append(
                f"- [{entry.get('kind', 'note')}] "
                f"{entry.get('title', 'Untitled')}: "
                f"{_short_text(_normalize_text(entry.get('body')), limit=140)}"
            )

    if agent_sessions:
        latest = agent_sessions[0]
        lines.append("")
        lines.append("## Agent Summary")
        lines.append(
            f"- Latest session status: {latest.get('status', 'unknown')}"
        )
        if latest.get("summary"):
            lines.append(f"- {latest['summary']}")
    return "\n".join(lines)
