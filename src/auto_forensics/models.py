from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


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
class Finding:
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
class WorkspaceView:
    view_id: str
    case_id: str
    name: str
    section: str
    filters: dict[str, Any] = field(default_factory=dict)
    sort: dict[str, Any] = field(default_factory=dict)
    layout: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)


@dataclass(slots=True)
class NotebookEntry:
    entry_id: str
    case_id: str
    kind: str
    title: str
    body: str
    links: dict[str, list[str]] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)


@dataclass(slots=True)
class AgentStep:
    step_id: str
    session_id: str
    step_index: int
    title: str
    rationale: str
    linked_entities: dict[str, list[str]] = field(default_factory=dict)
    proposed_action: dict[str, Any] = field(default_factory=dict)
    approval_state: str = "not_required"
    result: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)


@dataclass(slots=True)
class AgentRecommendation:
    recommendation_id: str
    session_id: str
    case_id: str
    priority: int
    title: str
    reason: str
    linked_entities: dict[str, list[str]] = field(default_factory=dict)
    suggested_action: dict[str, Any] = field(default_factory=dict)
    status: str = "pending"
    confidence: float = 0.0
    evidence_count: int = 0
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)


@dataclass(slots=True)
class AgentSession:
    session_id: str
    case_id: str
    goal: str
    status: str
    model_config: dict[str, Any] = field(default_factory=dict)
    summary: str = ""
    error: str | None = None
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)
    completed_at: str | None = None


@dataclass(slots=True)
class GraphNode:
    node_id: str
    case_id: str
    node_type: str
    label: str
    score: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now_iso)


@dataclass(slots=True)
class GraphEdge:
    edge_id: str
    case_id: str
    source_node_id: str
    target_node_id: str
    relation: str
    confidence: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now_iso)


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
