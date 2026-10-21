"""Shared records for a triage run.

Findings are drafts. A draft is allowed into a report only when it
carries at least one citation that points at an ingested artifact.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

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
        located = self.row is not None or self.offset is not None
        digest = self.sha256.lower()
        return bool(self.artifact_id and self.source_file and _SHA256_RE.fullmatch(digest) and located)


@dataclass(slots=True)
class Finding:
    """One drafted claim about a case.

    ``origin`` is ``llm``, ``heuristic``, or ``detector``.
    ``worker`` is the name of the worker that submitted the finding.
    Today that is always ``pipeline``. A later orchestrator can submit
    findings from more than one worker into the same case store.
    ``review_status`` is ``unverified`` until an analyst accepts or
    rejects the draft. This version stores the status and does not
    yet provide the review command.
    ``verification`` is the verifier verdict for this finding:
    ``supported`` when the cited row contained the claim, otherwise
    empty because rejected findings are left out of the report.
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


def decode_finding_row(row: dict[str, Any]) -> dict[str, Any]:
    """Convert a findings-table row into the dict returned by the API.

    Corrupt JSON becomes an empty list rather than an exception, so one
    bad row cannot hide the rest of the case.
    """
    item = dict(row)
    item["evidence"] = _decode_json_list(item.pop("evidence_json", "[]"))
    if "citations_json" in item:
        item["citations"] = _decode_json_list(item.pop("citations_json"))
    else:
        item["citations"] = []
    item["origin"] = str(item.get("origin") or "detector")
    item["review_status"] = str(item.get("review_status") or "unverified")
    item["worker"] = str(item.get("worker") or "pipeline")
    return item


def _decode_json_list(raw: Any) -> list[Any]:
    if isinstance(raw, list):
        return raw
    if not isinstance(raw, str):
        return []
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return []
    return parsed if isinstance(parsed, list) else []
