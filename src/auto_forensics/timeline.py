from __future__ import annotations

import ipaddress
from bisect import bisect_right
from dataclasses import asdict, replace
from datetime import datetime, timezone
from typing import Any

from .citations import citation_from_event
from .models import ArtifactEvent, BinaryFeature, TimelineEvent

PROCESS_EVENT_TYPES = {"process_creation", "process_start"}
NETWORK_EVENT_TYPES = {"dns_query", "http_request", "tls_client_hello", "c2_beacon_suspected"}
NETWORK_PROCESS_CORRELATION_WINDOW_SECONDS = 120


def parse_iso(ts: object) -> datetime | None:
    if not isinstance(ts, str) or not ts or len(ts) > 256:
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
    related: dict[str, Any] = {"artifact_id": item.artifact_id}
    metadata = item.metadata
    citation = citation_from_event(item)
    if citation is not None:
        related["citation"] = asdict(citation)
    raw_logsource = metadata.get("logsource")
    logsource = {
        key: value.casefold() for key, value in raw_logsource.items()
        if key in {"category", "product", "service"} and isinstance(value, str)
    } if isinstance(raw_logsource, dict) else {}
    for key in ("category", "product", "service"):
        if isinstance(metadata.get(key), str):
            logsource.setdefault(key, metadata[key].casefold())
    if item.event_type in PROCESS_EVENT_TYPES:
        logsource.setdefault("category", "process_creation")
    if str(metadata.get("source_file", "")).lower().endswith(".evtx"):
        logsource.setdefault("product", "windows")
        channel = metadata.get("channel")
        if isinstance(channel, str):
            if channel.lower() == "security":
                logsource.setdefault("service", "security")
            elif "sysmon" in channel.lower():
                logsource.setdefault("service", "sysmon")
    if logsource:
        related["logsource"] = logsource
    for key in ("source_host", "computer", "hostname", "host"):
        # The HTTP Host header names a destination, not the source host.
        if key == "host" and metadata.get("src_ip"):
            continue
        if isinstance(metadata.get(key), str) and metadata[key].strip():
            related["source_host"] = metadata[key].strip()
            break
    for key in ("source_ip", "src_ip", "local_ip", "ip_address"):
        if isinstance(metadata.get(key), str) and metadata[key].strip():
            related["source_ip"] = metadata[key].strip()
            break
    for key in ("NewProcessId", "process_id", "pid", "ProcessId"):
        raw = metadata.get(key)
        if isinstance(raw, str) and len(raw) <= 32:
            try:
                raw = int(raw, 16 if raw.lower().startswith("0x") else 10)
            except ValueError:
                continue
        if type(raw) is int and raw >= 0:
            related["process_id"] = raw
            break
    timestamp = item.timestamp if isinstance(item.timestamp, str) else None
    if item.timestamp is not None and timestamp is None:
        related["unparsed_timestamp"] = item.timestamp
    return TimelineEvent(
        timestamp=timestamp,
        source=item.source,
        event_type=item.event_type,
        description=description,
        risk_score=0.0,
        tags=["artifact"],
        related=related,
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
    artifact_events = [event_from_artifact(a) for a in artifacts]
    events.extend(artifact_events)
    events.extend(event_from_binary(b) for b in binaries)
    # Provenance keys belong to the parser/framework. A generated hint
    # cannot turn itself into a cited observation by copying those keys.
    events.extend(replace(
        hint, tags=[tag for tag in hint.tags if tag != "artifact"],
        related={key: value for key, value in hint.related.items() if key not in {"citation", "artifact_id", "logsource"}},
    ) for hint in generated_hints)

    def sort_key(item: TimelineEvent) -> tuple[int, datetime]:
        dt = parse_iso(item.timestamp)
        if dt is None:
            return (1, datetime.max.replace(tzinfo=timezone.utc))
        return (0, dt)

    ordered = sorted(events, key=sort_key)
    process_events: dict[tuple[str, str, int | None], list[tuple[datetime, str, TimelineEvent]]] = {}
    for item in artifact_events:
        if item.event_type not in PROCESS_EVENT_TYPES:
            continue
        dt = parse_iso(item.timestamp)
        if dt is not None:
            for kind, value in sorted(_source_identities(item)):
                entry = (dt, str(item.related["artifact_id"]), item)
                process_events.setdefault((kind, value, None), []).append(entry)
                if "process_id" in item.related:
                    process_events.setdefault((kind, value, item.related["process_id"]), []).append(entry)
    for candidates in process_events.values():
        candidates.sort(key=lambda candidate: candidate[:2])
    process_times = {key: [candidate[0] for candidate in candidates] for key, candidates in process_events.items()}

    for item in ordered:
        if item.event_type not in NETWORK_EVENT_TYPES:
            continue
        dt = parse_iso(item.timestamp)
        if dt is None:
            continue
        nearest: TimelineEvent | None = None
        nearest_delta: float = NETWORK_PROCESS_CORRELATION_WINDOW_SECONDS + 1
        for kind, value in sorted(_source_identities(item)):
            key = (kind, value, item.related.get("process_id"))
            candidates = process_events.get(key, [])
            preceding = bisect_right(process_times.get(key, []), dt) - 1
            if preceding < 0:
                continue
            process_ts, _, process_event = candidates[preceding]
            delta = (dt - process_ts).total_seconds()
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
                "correlated_process_artifact_id": nearest.related["artifact_id"],
                "correlation_basis": "same-source-process-and-time" if "process_id" in item.related else "same-source-time-proximity",
            }
        elif "network" not in item.tags:
            item.tags = sorted(set(item.tags + ["network"]))
    return ordered


def _source_identities(event: TimelineEvent) -> set[tuple[str, str]]:
    identities = set()
    for key in ("source_host", "source_ip"):
        raw = event.related.get(key)
        if not isinstance(raw, str) or not raw.strip():
            continue
        value = raw.strip().casefold().rstrip(".")
        try:
            identities.add(("ip", str(ipaddress.ip_address(value))))
        except ValueError:
            if key == "source_host":
                identities.add(("host", value))
    return identities
