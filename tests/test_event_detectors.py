from __future__ import annotations

from auto_forensics.event_detectors import findings_from_artifact_events
from auto_forensics.models import ArtifactEvent


def test_findings_from_artifact_events_uses_event_id_mapping():
    artifacts = [
        ArtifactEvent(
            artifact_id="a1",
            timestamp="2026-02-17T13:00:00Z",
            event_type="service_install",
            description="Service install detected",
            source="security.evtx",
            metadata={
                "event_id": 7045,
                "attack_tactic": "persistence",
                "attack_technique_id": "T1543.003",
            },
        )
    ]

    findings = findings_from_artifact_events(artifacts)

    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].technique_id == "T1543.003"


def _event(row: int, event_id: int, source: str = "security.evtx") -> ArtifactEvent:
    return ArtifactEvent(artifact_id=f"a{row}", timestamp="2026-02-17T13:00:00Z", event_type="process_creation",
                         description="New process created", source=source,
                         metadata={"event_id": event_id, "source_file": source, "source_sha256": "a" * 64, "row": row})


def test_one_finding_per_event_id_per_file():
    events = [_event(i, 4688) for i in range(1, 501)] + [_event(1, 4688, "other.evtx"), _event(2, 7045)]
    findings = findings_from_artifact_events(events)
    by_id = {(f.title, f.citations[0].source_file): f for f in findings}
    assert len(findings) == 3
    assert "499 more event(s)" in by_id[("Process creation (Windows event 4688)", "security.evtx")].recommendation


def test_telemetry_ids_are_low_context_not_alerts():
    severities = {"Event " + f.title.split("Windows event ")[1].rstrip(")"): f.severity for f in findings_from_artifact_events(
        [_event(1, 4688), _event(2, 4104), _event(3, 4103), _event(4, 1102)])}
    assert severities == {"Event 4688": "low", "Event 4104": "low", "Event 4103": "low", "Event 1102": "critical"}
