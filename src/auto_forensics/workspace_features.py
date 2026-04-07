from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _risk_level(score: float) -> str:
    if score >= 70:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def _safe_lower(value: Any) -> str:
    return str(value or "").lower()


def _match_blob(parts: list[Any]) -> str:
    return " ".join(str(part or "") for part in parts).lower()


def build_artifact_previews(
    case: dict[str, Any],
    artifacts: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    timeline: list[dict[str, Any]],
    iocs: list[dict[str, Any]],
    report_payload: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    report_payload = report_payload or {}
    binary_by_path: dict[str, dict[str, Any]] = {}
    for binary in report_payload.get("binary_features", []):
        path = str(binary.get("path") or "")
        if path:
            binary_by_path[path.replace("\\", "/").lower()] = dict(binary)

    previews: list[dict[str, Any]] = []
    for artifact in artifacts:
        rel_path = str(artifact.get("rel_path") or "")
        rel_path_norm = rel_path.replace("\\", "/").lower()
        metadata = dict(artifact.get("metadata") or {})
        display_name = Path(rel_path).name or rel_path

        matched_findings: list[str] = []
        max_score = 0.0
        for finding in findings:
            evidence = finding.get("evidence") or []
            evidence_blob = _match_blob(list(evidence))
            title = str(finding.get("title") or "")
            if rel_path_norm and rel_path_norm in evidence_blob:
                matched_findings.append(title)
                max_score = max(max_score, float(finding.get("confidence", 0.0) or 0.0) * 100.0)

        matched_timeline: list[dict[str, Any]] = []
        for event in timeline:
            related_blob = _match_blob(
                [
                    event.get("source"),
                    event.get("description"),
                    json.dumps(event.get("related") or {}, sort_keys=True),
                ]
            )
            if rel_path_norm and rel_path_norm in related_blob:
                matched_timeline.append(event)
                max_score = max(max_score, float(event.get("risk_score", 0.0) or 0.0))

        ioc_hits: list[str] = []
        for ioc in iocs:
            sources = [str(item) for item in (ioc.get("sources") or [])]
            if any(rel_path_norm and rel_path_norm in _safe_lower(item) for item in sources):
                ioc_hits.append(str(ioc.get("value") or ""))

        binary = binary_by_path.get(rel_path_norm)
        if binary:
            max_score = max(max_score, min(float(binary.get("suspicious_score", 0.0) or 0.0) * 20.0, 100.0))

        summary_parts: list[str] = []
        if matched_findings:
            summary_parts.append(f"{len(matched_findings)} finding(s)")
        if matched_timeline:
            summary_parts.append(f"{len(matched_timeline)} timeline event(s)")
        if ioc_hits:
            summary_parts.append(f"{len(ioc_hits)} IOC hit(s)")
        if binary and binary.get("rationale"):
            rationale = list(binary.get("rationale") or [])
            summary_parts.append("; ".join(str(item) for item in rationale[:2]))

        previews.append(
            {
                "rel_path": rel_path,
                "artifact_type": artifact.get("artifact_type"),
                "size_bytes": int(artifact.get("size_bytes", 0) or 0),
                "sha256": artifact.get("sha256"),
                "source_path": metadata.get("source_path"),
                "display_name": display_name,
                "risk_score": round(max_score, 2),
                "risk_level": _risk_level(max_score),
                "summary": ", ".join(summary_parts) if summary_parts else "No correlated risk signals yet.",
                "matched_findings": matched_findings,
                "matched_timeline_events": len(matched_timeline),
                "ioc_hits": ioc_hits,
                "available_outputs": {
                    "raw_artifact": True,
                    "report_json": bool(report_payload),
                    "report_html": bool(report_payload),
                },
                "metadata": metadata,
            }
        )
    previews.sort(key=lambda item: (-float(item.get("risk_score", 0.0) or 0.0), str(item.get("rel_path") or "")))
    return previews


def filter_artifact_previews(
    previews: list[dict[str, Any]],
    page: int = 1,
    page_size: int = 50,
    artifact_type: str | None = None,
    source: str | None = None,
    sort: str = "risk",
    search: str | None = None,
) -> dict[str, Any]:
    items = list(previews)
    if artifact_type:
        item_type = artifact_type.strip().lower()
        items = [item for item in items if _safe_lower(item.get("artifact_type")) == item_type]
    if source:
        source_blob = source.strip().lower()
        items = [
            item for item in items if source_blob in _safe_lower(item.get("source_path"))
        ]
    if search:
        needle = search.strip().lower()
        items = [
            item
            for item in items
            if needle in _match_blob(
                [
                    item.get("rel_path"),
                    item.get("display_name"),
                    item.get("summary"),
                    item.get("artifact_type"),
                    json.dumps(item.get("metadata") or {}, sort_keys=True),
                ]
            )
        ]

    sort_mode = (sort or "risk").strip().lower()
    if sort_mode == "name":
        items.sort(key=lambda item: str(item.get("display_name") or "").lower())
    elif sort_mode == "size":
        items.sort(key=lambda item: (-int(item.get("size_bytes", 0) or 0), str(item.get("rel_path") or "")))
    else:
        items.sort(key=lambda item: (-float(item.get("risk_score", 0.0) or 0.0), str(item.get("rel_path") or "")))

    page = max(1, int(page))
    page_size = max(1, min(200, int(page_size)))
    total = len(items)
    start = (page - 1) * page_size
    end = start + page_size
    return {
        "page": page,
        "page_size": page_size,
        "total": total,
        "items": items[start:end],
    }


def build_case_graph(
    artifacts: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    timeline: list[dict[str, Any]],
    iocs: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, Any]] = {}

    def add_node(node_id: str, node_type: str, label: str, score: float = 0.0, metadata: dict[str, Any] | None = None) -> None:
        existing = nodes.get(node_id)
        payload = {
            "node_id": node_id,
            "node_type": node_type,
            "label": label,
            "score": round(score, 2),
            "metadata": metadata or {},
        }
        if existing is None:
            nodes[node_id] = payload
            return
        existing["score"] = max(float(existing.get("score", 0.0) or 0.0), payload["score"])
        if metadata:
            existing_meta = dict(existing.get("metadata") or {})
            existing_meta.update(metadata)
            existing["metadata"] = existing_meta

    def add_edge(from_node: str, to_node: str, relation: str, confidence: float = 0.5, metadata: dict[str, Any] | None = None) -> None:
        edge_id = f"{from_node}|{relation}|{to_node}"
        current = edges.get(edge_id)
        payload = {
            "edge_id": edge_id,
            "from_node": from_node,
            "to_node": to_node,
            "relation": relation,
            "confidence": round(confidence, 2),
            "metadata": metadata or {},
        }
        if current is None:
            edges[edge_id] = payload
            return
        current["confidence"] = max(float(current.get("confidence", 0.0) or 0.0), payload["confidence"])

    artifact_ids: dict[str, str] = {}
    for artifact in artifacts:
        rel_path = str(artifact.get("rel_path") or "")
        node_id = f"artifact:{rel_path}"
        artifact_ids[rel_path.replace('\\', '/').lower()] = node_id
        add_node(
            node_id,
            "artifact",
            Path(rel_path).name or rel_path,
            metadata={
                "rel_path": rel_path,
                "artifact_type": artifact.get("artifact_type"),
                "sha256": artifact.get("sha256"),
            },
        )

    for ioc in iocs:
        ioc_type = str(ioc.get("ioc_type") or "ioc").lower()
        value = str(ioc.get("value") or "")
        node_type = ioc_type if ioc_type in {"ip", "domain", "url", "sha256", "md5"} else "ioc"
        node_id = f"{node_type}:{value}"
        add_node(node_id, node_type, value, metadata={"ioc_type": ioc_type})
        for source in ioc.get("sources") or []:
            source_text = str(source or "").replace("\\", "/").lower()
            for rel_path, artifact_node in artifact_ids.items():
                if rel_path and rel_path in source_text:
                    add_edge(artifact_node, node_id, "observed_in", 0.8)

    for event in timeline:
        source = str(event.get("source") or "")
        description = str(event.get("description") or "")
        risk = float(event.get("risk_score", 0.0) or 0.0)
        related_blob = _match_blob([source, description, json.dumps(event.get("related") or {}, sort_keys=True)])
        event_id = (
            f"event:{event.get('timestamp') or event.get('created_at') or source}:{event.get('event_type') or 'event'}"
        )
        add_node(
            event_id,
            "event",
            str(event.get("event_type") or "event"),
            score=risk,
            metadata={"source": source, "description": description},
        )
        for rel_path, artifact_node in artifact_ids.items():
            if rel_path and rel_path in related_blob:
                add_edge(artifact_node, event_id, "extracted_from", min(max(risk / 100.0, 0.4), 1.0))
        for token in description.split():
            clean = token.strip(" ,;:()[]{}<>\"'").lower()
            if clean.count(".") == 3 and all(part.isdigit() for part in clean.split(".") if part):
                node_id = f"ip:{clean}"
                add_node(node_id, "ip", clean)
                add_edge(event_id, node_id, "contacted", min(max(risk / 100.0, 0.3), 1.0))
            elif "." in clean and clean.startswith("http"):
                node_id = f"url:{clean}"
                add_node(node_id, "url", clean)
                add_edge(event_id, node_id, "contacted", min(max(risk / 100.0, 0.3), 1.0))
            elif "." in clean and len(clean) > 4 and "/" not in clean and clean.count(".") >= 1:
                node_id = f"domain:{clean}"
                add_node(node_id, "domain", clean)
                add_edge(event_id, node_id, "contacted", min(max(risk / 100.0, 0.3), 1.0))

    for finding in findings:
        title = str(finding.get("title") or "finding")
        finding_id = str(finding.get("finding_id") or title)
        node_id = f"finding:{finding_id}"
        confidence = float(finding.get("confidence", 0.0) or 0.0) * 100.0
        add_node(
            node_id,
            "finding",
            title,
            score=confidence,
            metadata={
                "severity": finding.get("severity"),
                "tactic": finding.get("tactic"),
            },
        )
        evidence_blob = _match_blob(list(finding.get("evidence") or []))
        for rel_path, artifact_node in artifact_ids.items():
            if rel_path and rel_path in evidence_blob:
                add_edge(artifact_node, node_id, "related_to", min(max(confidence / 100.0, 0.4), 1.0))

    return list(nodes.values()), list(edges.values())


def cluster_case_activity(
    findings: list[dict[str, Any]],
    timeline: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    clusters: dict[str, dict[str, Any]] = {}
    for finding in findings:
        key = str(finding.get("tactic") or "uncategorized").strip().lower() or "uncategorized"
        cluster = clusters.setdefault(
            key,
            {
                "cluster_id": key,
                "title": str(finding.get("tactic") or "Uncategorized activity").title(),
                "finding_ids": [],
                "event_ids": [],
                "evidence_count": 0,
                "confidence": 0.0,
            },
        )
        cluster["finding_ids"].append(str(finding.get("finding_id") or ""))
        cluster["evidence_count"] += len(finding.get("evidence") or [])
        cluster["confidence"] = max(cluster["confidence"], float(finding.get("confidence", 0.0) or 0.0))

    for index, event in enumerate(timeline):
        matched = False
        event_blob = _match_blob([event.get("event_type"), event.get("description"), event.get("source")])
        for key, cluster in clusters.items():
            if key != "uncategorized" and key.replace("-", " ") in event_blob:
                cluster["event_ids"].append(f"event-{index}")
                cluster["confidence"] = max(cluster["confidence"], min(float(event.get("risk_score", 0.0) or 0.0) / 100.0, 1.0))
                matched = True
        if not matched and timeline:
            fallback = clusters.setdefault(
                "timeline",
                {
                    "cluster_id": "timeline",
                    "title": "Timeline anomalies",
                    "finding_ids": [],
                    "event_ids": [],
                    "evidence_count": 0,
                    "confidence": 0.0,
                },
            )
            fallback["event_ids"].append(f"event-{index}")
            fallback["confidence"] = max(fallback["confidence"], min(float(event.get("risk_score", 0.0) or 0.0) / 100.0, 1.0))

    output = list(clusters.values())
    output.sort(
        key=lambda item: (
            -float(item.get("confidence", 0.0) or 0.0),
            -(len(item.get("finding_ids") or []) + len(item.get("event_ids") or [])),
            str(item.get("title") or ""),
        )
    )
    return output


def build_case_brief(
    case_id: str,
    overview: dict[str, Any],
    notebook_entries: list[dict[str, Any]],
    agent_session: dict[str, Any] | None,
) -> str:
    summary = overview.get("summary") or {}
    findings = overview.get("findings") or []
    iocs = overview.get("iocs") or []
    timeline = overview.get("timeline") or []
    lines = [
        f"# Analyst Brief: {case_id}",
        "",
        f"- Findings: {len(findings)}",
        f"- IOCs: {len(iocs)}",
        f"- Timeline events: {len(timeline)}",
    ]
    if summary:
        risk_score = summary.get("risk_score") or summary.get("total_risk_score")
        if risk_score is not None:
            lines.append(f"- Risk score: {risk_score}")
    lines.append("")
    lines.append("## Highlights")
    top_findings = summary.get("top_findings") or []
    if top_findings:
        for item in top_findings[:5]:
            lines.append(f"- {item.get('title', 'Finding')} ({item.get('severity', 'unknown')})")
    elif findings:
        for item in findings[:5]:
            lines.append(f"- {item.get('title', 'Finding')} ({item.get('severity', 'unknown')})")
    else:
        lines.append("- No findings recorded.")

    verdicts = [entry for entry in notebook_entries if str(entry.get("kind") or "") == "verdict"]
    hypotheses = [entry for entry in notebook_entries if str(entry.get("kind") or "") == "hypothesis"]
    if hypotheses:
        lines.extend(["", "## Hypotheses"])
        for entry in hypotheses[:5]:
            lines.append(f"- {entry.get('title') or 'Hypothesis'}: {entry.get('body') or ''}")
    if verdicts:
        lines.extend(["", "## Verdict"])
        lines.append(verdicts[-1].get("body") or "")
    elif agent_session and agent_session.get("summary"):
        lines.extend(["", "## Agent Summary", str(agent_session.get("summary") or "")])
    return "\n".join(lines) + "\n"
