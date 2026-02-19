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
