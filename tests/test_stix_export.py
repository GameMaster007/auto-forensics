from __future__ import annotations

from auto_forensics.models import CaseReport, Finding
from auto_forensics.stix_export import build_stix_bundle


def test_build_stix_bundle_contains_bundle_and_objects():
    report = CaseReport(
        case_id="case-1",
        generated_at="2026-02-18T00:00:00Z",
        binary_features=[],
        findings=[
            Finding(
                finding_id="f1",
                title="test finding",
                severity="high",
                confidence=0.8,
                tactic="execution",
            )
        ],
        timeline=[],
        summary={},
    )

    bundle = build_stix_bundle(report)

    assert bundle["type"] == "bundle"
    assert isinstance(bundle["objects"], list)
    assert any(item.get("type") == "incident" for item in bundle["objects"])
    assert any(item.get("type") == "indicator" for item in bundle["objects"])
