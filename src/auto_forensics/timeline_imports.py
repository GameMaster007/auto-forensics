"""Read Plaso, Hayabusa, and Chainsaw exports as cited timeline rows.

These parsers do not run those programs. They read the files an analyst
already exported. Field text is stored as evidence. It is not copied
into a recommendation, and the model only sees it inside the evidence
fence.
"""

from __future__ import annotations

import csv
import json
import re
from typing import Any

from .citations import citation_from_event
from .ids import stable_id
from .models import ArtifactEvent, Finding

_PLASO_L2T = {
    "date",
    "time",
    "timezone",
    "macb",
    "source",
    "sourcetype",
    "type",
    "user",
    "host",
    "short",
    "desc",
}
_HAYABUSA_CSV = {"timestamp", "eventid", "ruletitle"}
_PLASO_DYNAMIC = {"timestamp_desc", "message"}
_CHAINSAW_KINDS = {"individual", "aggregate", "cached"}
_CHAINSAW_SOURCES = {"sigma", "chainsaw"}
_LEVELS = {
    "critical": "critical",
    "crit": "critical",
    "high": "high",
    "med": "medium",
    "medium": "medium",
    "low": "low",
    "info": "low",
    "informational": "low",
}
_TACTICS = {
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
}
_TECHNIQUE = re.compile(r"t\d{4}(?:\.\d{3})?", re.IGNORECASE)
_FINDING_LIMIT = 500
_RECOMMENDATIONS = {
    "hayabusa": "Open the cited Hayabusa row and confirm the rule before acting on it.",
    "chainsaw": "Open the cited Chainsaw row and confirm the rule before acting on it.",
    "plaso": "Open the cited Plaso row and confirm the tagged event before acting on it.",
}


def events_from_csv(
    reader: csv.DictReader,
    source_file: str,
    digest: str,
) -> list[ArtifactEvent] | None:
    """Return rows when the header is Plaso or Hayabusa. Otherwise None."""
    kind = _csv_kind(reader.fieldnames)
    if kind is None:
        return None
    events: list[ArtifactEvent] = []
    for row in reader:
        fields = _csv_fields(row)
        line_number = reader.line_num
        if kind == "hayabusa":
            event = _hayabusa_event(fields, source_file, digest, line_number)
        else:
            event = _plaso_event(fields, source_file, digest, line_number)
        if event is not None:
            events.append(event)
    return events


def events_from_json_lines(text: str, source_file: str, digest: str) -> list[ArtifactEvent]:
    """One JSON object per line. The row is that line's number in the file."""
    import json

    events: list[ArtifactEvent] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            item = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict):
            continue
        event = event_from_record(item, source_file, digest, line_number)
        if event is not None:
            events.append(event)
    return events


def event_from_record(
    record: dict[str, Any],
    source_file: str,
    digest: str,
    row: int,
) -> ArtifactEvent | None:
    """Build one cited event when ``record`` is a known tool export."""
    kind = _record_kind(record)
    if kind == "hayabusa":
        return _hayabusa_event(_json_fields(record), source_file, digest, row, record)
    if kind == "chainsaw":
        return _chainsaw_event(record, source_file, digest, row)
    if kind == "plaso":
        return _plaso_event(_json_fields(record), source_file, digest, row)
    return None


def findings_from_imported_timelines(
    events: list[ArtifactEvent],
    limit: int = _FINDING_LIMIT,
) -> list[Finding]:
    """Draft detector findings for detection rows and tagged Plaso rows.

    Hayabusa and Chainsaw files are detection output, so each rule name
    becomes a claim. A Plaso row becomes a claim only when that export
    already carries a tag. The claim text is the field value, which is
    what the verifier looks for in the cited row.
    """
    findings: list[Finding] = []
    for event in events:
        tool = str(event.metadata.get("importer") or "")
        if tool == "hayabusa":
            claim = str(event.metadata.get("rule_title") or "").strip()
            drafted = [_draft(event, "Hayabusa", claim, str(event.metadata.get("level") or ""))] if claim else []
        elif tool == "chainsaw":
            drafted = [
                _draft(event, "Chainsaw", name, str(event.metadata.get("level") or ""))
                for name in _names(event.metadata.get("detection_names"))
            ]
        elif tool == "plaso" and str(event.metadata.get("tag") or "").strip():
            claim = event.description.strip()
            drafted = [_draft(event, "Plaso", claim, "")] if claim else []
        else:
            drafted = []
        for finding in drafted:
            findings.append(finding)
            if len(findings) >= limit:
                return findings
    return findings


def _csv_kind(fieldnames: Any) -> str | None:
    headers = _header_names(fieldnames)
    if _HAYABUSA_CSV.issubset(headers):
        return "hayabusa"
    if _PLASO_L2T.issubset(headers) or _PLASO_DYNAMIC.issubset(headers):
        return "plaso"
    return None


def _header_names(fieldnames: Any) -> set[str]:
    names: set[str] = set()
    for name in fieldnames or []:
        if not isinstance(name, str):
            continue
        names.add(name.replace("\ufeff", "").strip().lower())
    return names


def _csv_fields(row: dict[Any, Any]) -> dict[str, str]:
    fields: dict[str, str] = {}
    for key, value in row.items():
        if not isinstance(key, str):
            continue
        fields[key.replace("\ufeff", "").strip().lower()] = "" if value is None else str(value).strip()
    return fields


def _json_fields(record: dict[str, Any]) -> dict[str, Any]:
    return {str(key).replace("\ufeff", "").strip().lower(): value for key, value in record.items()}


def _record_kind(record: dict[str, Any]) -> str | None:
    fields = _json_fields(record)
    if fields.get("ruletitle") not in (None, "") and fields.get("eventid") is not None and (
        fields.get("timestamp") is not None or fields.get("channel") is not None
    ):
        return "hayabusa"
    if _is_chainsaw(record, fields):
        return "chainsaw"
    timestamp_desc = fields.get("timestamp_desc")
    if isinstance(timestamp_desc, str) and timestamp_desc.strip() and (
        isinstance(fields.get("message"), str) or isinstance(fields.get("parser"), str)
    ):
        return "plaso"
    return None


def _is_chainsaw(record: dict[str, Any], fields: dict[str, Any]) -> bool:
    detections = record.get("detections")
    if isinstance(detections, list) and any(_detection_name(item) for item in detections):
        return any(key in fields for key in ("document", "event", "path", "timestamp", "kind"))
    name = fields.get("name")
    timestamp = fields.get("timestamp")
    if not (isinstance(name, str) and name.strip() and isinstance(timestamp, str) and timestamp.strip()):
        return False
    kind = fields.get("kind")
    if isinstance(kind, str) and kind.strip().lower() in _CHAINSAW_KINDS:
        return True
    source = fields.get("source")
    authors = fields.get("authors")
    return isinstance(source, str) and source.strip().lower() in _CHAINSAW_SOURCES and isinstance(authors, list)


def _hayabusa_event(
    fields: dict[str, Any],
    source_file: str,
    digest: str,
    row: int,
    raw: dict[str, Any] | None = None,
) -> ArtifactEvent | None:
    del raw
    title = _text(fields.get("ruletitle"))
    if not title:
        return None
    return _event(
        tool="hayabusa",
        source_file=source_file,
        digest=digest,
        row=row,
        timestamp=_text(fields.get("timestamp")) or None,
        event_type="hayabusa_rule",
        description=title,
        extra={
            "rule_title": title,
            "level": _text(fields.get("level")),
            "windows_event_id": _text(fields.get("eventid")),
            "tactic": _tactic(fields.get("mitretactics")),
            "technique_id": _technique(fields.get("mitretags") or fields.get("tags")),
            "detection_names": [title],
            "details": _details_text(fields.get("details")),
        },
    )


def _plaso_event(
    fields: dict[str, Any],
    source_file: str,
    digest: str,
    row: int,
) -> ArtifactEvent | None:
    message = _text(fields.get("desc") or fields.get("message") or fields.get("short"))
    if not message:
        return None
    timestamp = _text(fields.get("datetime") or fields.get("timestamp"))
    if not timestamp:
        timestamp = _join_clock(fields.get("date"), fields.get("time"), fields.get("timezone"))
    event_type = _text(fields.get("timestamp_desc") or fields.get("type")) or "plaso_event"
    return _event(
        tool="plaso",
        source_file=source_file,
        digest=digest,
        row=row,
        timestamp=timestamp or None,
        event_type=event_type,
        description=message,
        extra={
            "tag": _plaso_tag(fields),
            "level": "",
            "rule_title": "",
            "detection_names": [],
            "details": _details_text(fields.get("filename") or fields.get("display_name")),
        },
    )


def _chainsaw_event(
    record: dict[str, Any],
    source_file: str,
    digest: str,
    row: int,
) -> ArtifactEvent | None:
    fields = _json_fields(record)
    names = _chainsaw_names(record, fields)
    if not names:
        return None
    level = _text(fields.get("level"))
    if not level:
        detections = record.get("detections")
        if isinstance(detections, list):
            for item in detections:
                if isinstance(item, dict) and _text(item.get("level")):
                    level = _text(item.get("level"))
                    break
    tags = fields.get("tags")
    return _event(
        tool="chainsaw",
        source_file=source_file,
        digest=digest,
        row=row,
        timestamp=_text(fields.get("timestamp")) or None,
        event_type="chainsaw_detection",
        description=names[0],
        extra={
            "rule_title": names[0],
            "level": level,
            "detection_names": names,
            "tactic": _tactic(tags),
            "technique_id": _technique(tags),
            "details": _details_text(record.get("document") or record.get("data")),
        },
    )


def _event(
    *,
    tool: str,
    source_file: str,
    digest: str,
    row: int,
    timestamp: str | None,
    event_type: str,
    description: str,
    extra: dict[str, Any],
) -> ArtifactEvent:
    metadata: dict[str, Any] = {"importer": tool, **extra}
    metadata["source_file"] = source_file
    metadata["source_sha256"] = digest
    metadata["row"] = row
    return ArtifactEvent(
        artifact_id=stable_id("evt", tool, digest, row, description),
        timestamp=timestamp,
        event_type=event_type,
        description=description,
        source=source_file,
        metadata=metadata,
    )


def _draft(event: ArtifactEvent, label: str, claim: str, level: str) -> Finding:
    tool = str(event.metadata.get("importer") or "")
    pointer = citation_from_event(event)
    return Finding(
        finding_id=stable_id("imp", tool, event.artifact_id, claim),
        title=f"{label}: {claim}",
        severity=_severity(level),
        confidence=0.6,
        tactic=str(event.metadata.get("tactic") or "unknown"),
        evidence=[claim],
        recommendation=_RECOMMENDATIONS[tool],
        technique_id=str(event.metadata.get("technique_id") or ""),
        citations=[pointer] if pointer is not None else [],
        origin="detector",
        review_status="unverified",
    )


def _chainsaw_names(record: dict[str, Any], fields: dict[str, Any]) -> list[str]:
    detections = record.get("detections")
    if isinstance(detections, list):
        names = [name for item in detections if (name := _detection_name(item))]
        if names:
            return names
    name = _text(fields.get("name"))
    return [name] if name else []


def _detection_name(item: Any) -> str:
    if not isinstance(item, dict):
        return ""
    return _text(item.get("name") or item.get("title"))


def _names(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [text for item in value if (text := _text(item))]


def _plaso_tag(fields: dict[str, Any]) -> str:
    tag = _tag_text(fields.get("tag"))
    if tag and tag != "-":
        return tag
    notes = _text(fields.get("notes"))
    if notes.lower().startswith("tag:"):
        return notes.split(":", 1)[1].strip()
    return ""


def _tag_text(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, list):
        return ", ".join(text for item in value if (text := _text(item)))
    return ""


def _details_text(value: Any) -> str:
    """Keep a short copy of the tool's own detail field.

    The copy is evidence. It is not a recommendation, and the prompt
    fence is what the model is allowed to see.
    """
    if isinstance(value, str):
        text = value.strip()
    elif isinstance(value, (dict, list)):
        text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    else:
        return ""
    return text[:2000]


def _text(value: Any) -> str:
    if value is None or isinstance(value, (dict, list)):
        return ""
    return str(value).strip()


def _join_clock(date: Any, time: Any, zone: Any) -> str:
    day = _text(date)
    clock = _text(time)
    if not day or not clock:
        return ""
    zone_text = _text(zone)
    return f"{day}T{clock}{zone_text}" if zone_text else f"{day}T{clock}"


def _severity(level: str) -> str:
    return _LEVELS.get(level.strip().lower(), "medium")


def _tactic(value: Any) -> str:
    if isinstance(value, list):
        candidates = [_text(item).lower().replace(" ", "-") for item in value]
    else:
        candidates = [_text(value).lower().replace(" ", "-")]
    for candidate in candidates:
        if candidate in _TACTICS:
            return candidate
    return "unknown"


def _technique(value: Any) -> str:
    if isinstance(value, list):
        text = " ".join(str(item) for item in value)
    else:
        text = str(value or "")
    match = _TECHNIQUE.search(text)
    if match is None:
        return ""
    return match.group(0).upper()
