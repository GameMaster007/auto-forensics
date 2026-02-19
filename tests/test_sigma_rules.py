from __future__ import annotations

from pathlib import Path

from auto_forensics.models import TimelineEvent
from auto_forensics.sigma_rules import evaluate_sigma_rules


def test_evaluate_sigma_rules_returns_empty_when_directory_missing(tmp_path: Path):
    timeline = [
        TimelineEvent(
            timestamp="2026-02-17T13:12:00Z",
            source="security.evtx",
            event_type="process_creation",
            description="cmd.exe /c whoami",
            risk_score=4.0,
            tags=["artifact"],
            related={},
        )
    ]

    findings = evaluate_sigma_rules(timeline, tmp_path / "missing")

    assert findings == []
