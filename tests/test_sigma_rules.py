from __future__ import annotations

from pathlib import Path

import pytest

from auto_forensics.models import TimelineEvent
from auto_forensics.pipeline import PipelineConfig, run_case
from auto_forensics.replay import replay_manifest
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


def _event(description: str, row: int = 1, *, cited: bool = True, product: str = "windows") -> TimelineEvent:
    related = {"logsource": {"product": product, "category": "process_creation"}}
    if cited:
        related["citation"] = {"artifact_id": f"event-{row}", "source_file": "events.json", "sha256": "a" * 64, "row": row}
    return TimelineEvent(None, "fixture", "process_creation", description, related=related)


def test_keyword_any_all_logsource_and_citation_requirements(tmp_path: Path):
    yaml = pytest.importorskip("yaml")
    rule = {"title": "Synthetic keyword rule", "logsource": {"product": "windows"},
            "detection": {"keywords": ["powershell", "encoded"], "condition": "keywords"}}
    rules = tmp_path / "rules"
    rules.mkdir()
    path = rules / "keywords.yml"
    path.write_text(yaml.safe_dump(rule))
    timeline = [_event("powershell only", 1), _event("encoded only", 2), _event("powershell encoded", 3),
                _event("powershell", 4, cited=False), _event("powershell", 5, product="linux")]
    diagnostics = {}
    findings = evaluate_sigma_rules(timeline, rules, diagnostics=diagnostics)
    assert len(findings) == 3 and len({finding.finding_id for finding in findings}) == 3
    assert {finding.citations[0].row for finding in findings} == {1, 2, 3}
    assert findings[0].evidence[-1] == "powershell" and "encoded" not in findings[0].evidence
    assert diagnostics["evaluated_rules"] == 1 and diagnostics["skipped_rules"] == 0
    rule["detection"]["keywords"] = {"|all": ["powershell", "encoded"]}
    path.write_text(yaml.safe_dump(rule))
    findings = evaluate_sigma_rules(timeline, rules)
    assert len(findings) == 1 and findings[0].citations[0].row == 3


@pytest.mark.parametrize("detection", [
    {"keywords": ["powershell"], "filter": ["allowed"], "condition": "keywords and not filter"},
    {"selection": {"CommandLine|contains": ["powershell"]}, "condition": "selection"},
    {"keywords": ["power*shell"], "condition": "keywords"},
    {"keywords": [True], "condition": "keywords"},
    {"keywords": ["powershell"], "condition": ["keywords"]},
])
def test_unsupported_conditions_are_reported_instead_of_flattened_to_false_matches(tmp_path: Path, detection):
    yaml = pytest.importorskip("yaml")
    path = tmp_path / "unsupported.yml"
    path.write_text(yaml.safe_dump({"title": "Unsupported", "detection": detection}))
    diagnostics = {}
    assert evaluate_sigma_rules([_event("powershell")], tmp_path, diagnostics=diagnostics) == []
    assert diagnostics["skipped_rules"] == 1
    assert diagnostics["skipped"] == [{"rule": "unsupported.yml", "reason": "unsupported_semantics"}]


def test_cited_sigma_rows_survive_full_pipeline_and_replay(tmp_path: Path):
    yaml = pytest.importorskip("yaml")
    source = tmp_path / "evidence"
    source.mkdir()
    (source / "events.csv").write_text("timestamp,event_type,description,product\n2026-11-07T00:00:00Z,process_start,powershell,windows\n2026-11-07T00:00:01Z,process_start,encoded,windows\n")
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "keywords.yml").write_text(yaml.safe_dump({"title": "Synthetic PowerShell keywords", "tags": ["attack.t1059.001"],
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {"selection": ["powershell", "encoded"], "condition": "selection"}}))
    output = tmp_path / "output"
    report = run_case(PipelineConfig("sigma-cited", source, output, enable_llama=False, sigma_rules_dir=rules))
    findings = [finding for finding in report.findings if finding.finding_id.startswith("sigma-")]
    assert len(findings) == 2
    assert {finding.citations[0].row for finding in findings} == {2, 3}
    assert all(finding.verification == "supported" for finding in findings)
    assert report.summary["sigma_rules"]["evaluated_rules"] == 1
    assert replay_manifest(output / "run_manifest.json")["match"] is True
