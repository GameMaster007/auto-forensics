from __future__ import annotations

from datetime import datetime, timezone

from .models import ArtifactEvent, BinaryFeature, TimelineEvent

PROCESS_EVENT_TYPES = {"process_creation", "process_start"}
NETWORK_EVENT_TYPES = {"dns_query", "http_request", "tls_client_hello", "c2_beacon_suspected"}
NETWORK_PROCESS_CORRELATION_WINDOW_SECONDS = 120


def parse_iso(ts: str | None) -> datetime | None:
    if not ts:
        return None
    clean = ts.strip()
    if clean.endswith("Z"):
        clean = clean[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(clean)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def event_from_artifact(item: ArtifactEvent) -> TimelineEvent:
    description = item.description
    if item.metadata:
        important = []
        for key in ("host", "user", "process", "path", "parent_process"):
            if key in item.metadata and item.metadata[key]:
                important.append(f"{key}={item.metadata[key]}")
        if important:
            description = f"{description} ({', '.join(important)})"
    return TimelineEvent(
        timestamp=item.timestamp,
        source=item.source,
        event_type=item.event_type,
        description=description,
        risk_score=0.0,
        tags=["artifact"],
        related={"artifact_id": item.artifact_id},
    )


def event_from_binary(binary: BinaryFeature) -> TimelineEvent:
    return TimelineEvent(
        timestamp=None,
        source="binary_analysis",
        event_type="binary_analyzed",
        description=f"Analyzed {binary.path} (score={binary.suspicious_score})",
        risk_score=min(10.0, 1.0 + binary.suspicious_score),
        tags=["binary", "analysis"],
        related={"sha256": binary.sha256, "md5": binary.md5},
    )


def normalize_timeline(
    artifacts: list[ArtifactEvent],
    binaries: list[BinaryFeature],
    generated_hints: list[TimelineEvent],
) -> list[TimelineEvent]:
    events: list[TimelineEvent] = []
    events.extend(event_from_artifact(a) for a in artifacts)
    events.extend(event_from_binary(b) for b in binaries)
    events.extend(generated_hints)

    def sort_key(item: TimelineEvent) -> tuple[int, datetime]:
        dt = parse_iso(item.timestamp)
        if dt is None:
            return (1, datetime.max.replace(tzinfo=timezone.utc))
        return (0, dt)

    ordered = sorted(events, key=sort_key)
    process_events: list[tuple[datetime, TimelineEvent]] = []
    for item in ordered:
        if item.event_type not in PROCESS_EVENT_TYPES:
            continue
        dt = parse_iso(item.timestamp)
        if dt is not None:
            process_events.append((dt, item))

    for item in ordered:
        if item.event_type not in NETWORK_EVENT_TYPES:
            continue
        dt = parse_iso(item.timestamp)
        if dt is None:
            continue
        nearest: TimelineEvent | None = None
        nearest_delta = NETWORK_PROCESS_CORRELATION_WINDOW_SECONDS + 1
        for process_ts, process_event in process_events:
            delta = abs((dt - process_ts).total_seconds())
            if delta < nearest_delta:
                nearest = process_event
                nearest_delta = delta
        if nearest and nearest_delta <= NETWORK_PROCESS_CORRELATION_WINDOW_SECONDS:
            item.tags = sorted(set(item.tags + ["network", "correlated_process"]))
            item.related = {
                **item.related,
                "correlated_process_event_type": nearest.event_type,
                "correlated_process_source": nearest.source,
                "correlated_process_description": nearest.description,
                "correlation_time_delta_seconds": round(nearest_delta, 2),
            }
        elif "network" not in item.tags:
            item.tags = sorted(set(item.tags + ["network"]))
    return ordered
