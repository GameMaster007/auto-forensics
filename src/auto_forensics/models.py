"""Shared records for a triage run.

Findings are drafts. A draft is allowed into a report only when it
carries at least one citation that points at an ingested artifact.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from .security import validate_json_nesting

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(slots=True)
class ArtifactEvent:
    artifact_id: str
    timestamp: str | None
    event_type: str
    description: str
    source: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class BinaryStringMatch:
    keyword: str
    offset: int
    encoding: str


@dataclass(slots=True)
class BinaryFeature:
    path: str
    size_bytes: int
    sha256: str
    md5: str
    entropy: float
    string_hits: list[str] = field(default_factory=list)
    import_hints: list[str] = field(default_factory=list)
    suspicious_score: float = 0.0
    rationale: list[str] = field(default_factory=list)
    string_matches: list[BinaryStringMatch] = field(default_factory=list)
    string_match_count: int = 0
    string_matches_truncated: bool = False
    strings_scanned_bytes: int = 0


@dataclass(slots=True)
class Citation:
    """Pointer from a finding back to one ingested artifact.

    ``row`` is a 1-based record or line number. ``offset`` is a byte
    offset. A citation is complete when it names the artifact, the
    source file, and a SHA-256, and gives at least one of row or offset.
    """

    artifact_id: str
    source_file: str
    sha256: str
    row: int | None = None
    offset: int | None = None

    def is_complete(self) -> bool:
        """Return True when an analyst could open this pointer."""
        if not all(isinstance(value, str) and value.strip() for value in (
            self.artifact_id, self.source_file, self.sha256
        )):
            return False
        if self.row is None and self.offset is None:
            return False
        if self.row is not None and (type(self.row) is not int or self.row < 1):
            return False
        if self.offset is not None and (type(self.offset) is not int or self.offset < 0):
            return False
        return _SHA256_RE.fullmatch(self.sha256.lower()) is not None


@dataclass(slots=True)
class Finding:
    """One drafted claim about a case.

    ``origin`` is ``llm``, ``heuristic``, or ``detector``.
    ``worker`` is the name of the worker that submitted the finding.
    Today that is always ``pipeline``. A later orchestrator can submit
    findings from more than one worker into the same case store.
    ``review_status`` is ``unverified`` until an analyst accepts or
    rejects the draft. ``analyst_verified`` is true only after an
    accept. A reject clears it and sets ``verification`` to
    ``not verified``. ``machine_verification`` keeps the verifier
    label in that case.
    ``verification`` is otherwise the verifier label kept on a
    finding that stays in the report: ``supported``, ``score-based``,
    or ``needs review``. Score-based is a mock or heuristic draft
    with no claim sentence and a matching file hash. A live model
    draft with no claim sentence is needs review. Findings the
    verifier rejected are left out of the report.
    """

    finding_id: str
    title: str
    severity: str
    confidence: float
    tactic: str
    evidence: list[str] = field(default_factory=list)
    recommendation: str = ""
    technique_id: str = ""
    sub_technique: str = ""
    ioc_refs: list[str] = field(default_factory=list)
    confidence_low: float | None = None
    confidence_high: float | None = None
    citations: list[Citation] = field(default_factory=list)
    origin: str = "detector"
    review_status: str = "unverified"
    worker: str = "pipeline"
    verification: str = ""
    analyst_verified: bool = False
    review_actor: str = ""
    review_at: str = ""
    review_note: str = ""
    machine_verification: str = ""


@dataclass(slots=True)
class IOC:
    ioc_id: str
    ioc_type: str
    value: str
    first_seen: str | None = None
    last_seen: str | None = None
    sources: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class IOCEnrichment:
    enrichment_id: str
    ioc_id: str
    provider: str
    verdict: str
    confidence: float
    details: dict[str, Any] = field(default_factory=dict)
    fetched_at: str = field(default_factory=utc_now_iso)


@dataclass(slots=True)
class TimelineEvent:
    timestamp: str | None
    source: str
    event_type: str
    description: str
    risk_score: float = 0.0
    tags: list[str] = field(default_factory=list)
    related: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class CaseReport:
    case_id: str
    generated_at: str
    binary_features: list[BinaryFeature]
    findings: list[Finding]
    timeline: list[TimelineEvent]
    summary: dict[str, Any]
    iocs: list[IOC] = field(default_factory=list)
    enrichments: list[IOCEnrichment] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-ready copy of the report, including citations."""
        return {
            "case_id": self.case_id,
            "generated_at": self.generated_at,
            "binary_features": [asdict(item) for item in self.binary_features],
            "findings": [asdict(item) for item in self.findings],
            "timeline": [asdict(item) for item in self.timeline],
            "summary": self.summary,
            "iocs": [asdict(item) for item in self.iocs],
            "ioc_enrichments": [asdict(item) for item in self.enrichments],
        }


def citations_as_json(citations: list[Citation]) -> str:
    """Serialize citations for the findings table."""
    return json.dumps([asdict(item) for item in citations])


FINDING_DETAIL_FIELDS = (
    "technique_id", "sub_technique", "ioc_refs", "confidence_low", "confidence_high",
    "verification", "analyst_verified", "review_actor", "review_at", "review_note", "machine_verification",
)


def finding_details_as_json(finding: Finding) -> str:
    return json.dumps({name: getattr(finding, name) for name in FINDING_DETAIL_FIELDS}, allow_nan=False)


_INVALID_JSON = object()


def _stored_json(raw: Any) -> Any:
    try:
        if isinstance(raw, str) and len(raw.encode("utf-8")) > 64 * 1024 * 1024:
            return _INVALID_JSON
        parsed = json.loads(raw) if isinstance(raw, str) else raw
        validate_json_nesting(parsed)
    except (ValueError, RecursionError):
        return _INVALID_JSON
    return parsed


def decode_json_object(raw: Any) -> dict[str, Any]:
    parsed = _stored_json(raw)
    return dict(parsed) if isinstance(parsed, dict) else {}


def _json_error(item: dict[str, Any], field: str) -> None:
    errors = item.get("_json_errors")
    if not isinstance(errors, list) or not all(isinstance(error, str) for error in errors):
        errors = item["_json_errors"] = []
    if field not in errors:
        errors.append(field)


def decode_row_json(item: dict[str, Any], source: str, target: str, expected: type, *, nullable: bool = False) -> None:
    """Keep a safe display value and a diagnostic for invalid stored data."""
    parsed = _stored_json(item.pop(source, None))
    if isinstance(parsed, expected) or (nullable and parsed is None):
        item[target] = parsed
    else:
        item[target] = None if nullable else expected()
        _json_error(item, source)


def decode_finding_row(row: dict[str, Any]) -> dict[str, Any]:
    """Convert a findings-table row into the dict returned by the API.

    Corrupt JSON gets a display default and a diagnostic, so one bad row
    cannot hide the rest of the case or pass an integrity check by coercion.
    """
    item = dict(row)
    item.setdefault("evidence_json", "[]")
    decode_row_json(item, "evidence_json", "evidence", list)
    if "citations_json" in item:
        decode_row_json(item, "citations_json", "citations", list)
    else:
        item["citations"] = []
    item["origin"] = str(item.get("origin") or "detector")
    item["review_status"] = str(item.get("review_status") or "unverified")
    item["worker"] = str(item.get("worker") or "pipeline")
    item.setdefault("details_json", "{}")
    decode_row_json(item, "details_json", "_details", dict)
    details = item.pop("_details")
    for name in FINDING_DETAIL_FIELDS:
        value = details.get(name)
        if name in {"confidence_low", "confidence_high"}:
            item[name] = value if isinstance(value, (int, float)) and not isinstance(value, bool) and 0 <= value <= 1 and math.isfinite(value) else None
            valid = value is None or item[name] is not None
        elif name == "ioc_refs":
            item[name] = [reference for reference in value if isinstance(reference, str)] if isinstance(value, list) else []
            valid = isinstance(value, list) and len(item[name]) == len(value)
        elif name == "analyst_verified":
            item[name] = value is True and item["review_status"] == "accepted"
            valid = isinstance(value, bool) and (not value or item["review_status"] == "accepted")
        else:
            item[name] = value if isinstance(value, str) else ""
            valid = isinstance(value, str)
        if name in details and not valid:
            _json_error(item, "details_json." + name)
    return item


def decode_json_list(raw: Any) -> list[Any]:
    parsed = _stored_json(raw)
    return parsed if isinstance(parsed, list) else []
