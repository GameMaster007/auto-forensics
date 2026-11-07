"""Untrusted evidence stays data and every citation identifies a real row."""

from __future__ import annotations

import hashlib
import json
import re
from html.parser import HTMLParser
from pathlib import Path

import pytest

from auto_forensics.artifacts import load_csv_artifacts
from auto_forensics.citations import catalog_from_citations, citation_from_event
from auto_forensics.models import CaseReport, Citation, Finding
from auto_forensics.pipeline import _to_html
from auto_forensics.security import stays_in_tree
from auto_forensics.verifier import locate_source, read_cited_text, verify_findings


@pytest.mark.parametrize("row,offset", [
    (None, None), (0, None), (-1, None), (True, None), (1.5, None),
    ("1", None), (None, -1), (None, False), (None, "0"), (1, -1),
])
def test_invalid_citation_locations_are_not_catalogued(row: object, offset: object):
    citation = Citation("event", "events.json", "a" * 64, row=row, offset=offset)
    assert citation.is_complete() is False
    assert catalog_from_citations([citation]) == {}


def test_invalid_citation_cannot_verify_a_detector_label(tmp_path: Path):
    path = tmp_path / "sample.bin"
    path.write_bytes(b"sample")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    citation = Citation("event", path.name, digest, offset=-1)
    finding = Finding("finding", "Label", "low", 0.5, "detection", citations=[citation])
    kept, verdicts = verify_findings([finding], tmp_path)
    assert kept == []
    assert verdicts[0].verdict == "rejected"


def test_file_and_directory_symlinks_are_excluded_even_inside_tree(tmp_path: Path):
    root = tmp_path / "evidence"
    actual = root / "real"
    actual.mkdir(parents=True)
    target = actual / "events.json"
    target.write_text('{"description": "real data"}', encoding="utf-8")
    (root / "alias").symlink_to(actual, target_is_directory=True)
    (root / "link.json").symlink_to(target)
    assert stays_in_tree(target, root)
    assert not stays_in_tree(root / "alias" / "events.json", root)
    assert not stays_in_tree(root / "link.json", root)
    assert locate_source(root, "alias/events.json") is None
    assert locate_source(root, "link.json") is None
    assert locate_source(root, "missing/events.json") is None
    assert locate_source(root, "events.json") == target


def test_multiline_csv_preserves_fields_and_physical_citation_rows(tmp_path: Path):
    path = tmp_path / "events.csv"
    path.write_text(
        '\ufefftimestamp,event_type,description,source\n'
        '2026-01-01T00:00:00Z,process_start,"first line\nsecond line",sysmon\n'
        '2026-01-01T00:00:01Z,process_start,"next record",sysmon\n',
        encoding="utf-8",
    )
    events = load_csv_artifacts(path)
    assert [event.description for event in events] == ["first line\nsecond line", "next record"]
    assert [event.metadata["row"] for event in events] == [3, 4]
    findings = []
    for index, event in enumerate(events):
        citation = citation_from_event(event)
        assert citation is not None
        findings.append(Finding(
            f"f{index}", "CSV row", "low", 0.5, "detection",
            evidence=[event.description], citations=[citation],
        ))
    kept, verdicts = verify_findings(findings, tmp_path)
    assert len(kept) == 2
    assert {item.verdict for item in verdicts} == {"supported"}
    header = Citation("header", path.name, findings[0].citations[0].sha256, row=1)
    assert read_cited_text(tmp_path, header)[0] is None


def test_nested_artifact_provenance_cannot_be_shadowed_by_a_root_basename(tmp_path: Path):
    from auto_forensics.integrity import verify_run
    from auto_forensics.pipeline import PipelineConfig, run_case

    evidence = tmp_path / "evidence"
    (evidence / "host").mkdir(parents=True)
    nested = evidence / "host/events.json"
    nested.write_text(json.dumps([{
        "artifact_id": "event-4104", "event_type": "powershell_script", "source": "windows",
        "description": "PowerShell script block logged", "event_id": 4104,
    }]))
    (evidence / "events.json").write_text("[]")
    digest = hashlib.sha256(nested.read_bytes()).hexdigest()
    assert locate_source(evidence, "events.json", digest) == nested
    output = tmp_path / "output"
    report = run_case(PipelineConfig("shadow-case", evidence, output, llm_provider="off"))
    assert len(report.findings) == 1
    assert report.findings[0].citations[0].source_file == "host/events.json"
    assert report.findings[0].verification == "supported"
    assert verify_run(output / "run_manifest.json")["match"] is True


class _Tags(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)


def test_html_evidence_cannot_close_the_script_or_inject_elements():
    attack = '</script><img src=x onerror="alert(1)"><script>/* & */'
    report = CaseReport(
        case_id=attack, generated_at="2026-01-01T00:00:00Z", binary_features=[],
        findings=[Finding("finding", attack, 'low" onclick="alert(2)', 0.5, attack)],
        timeline=[], summary={},
    )
    html = _to_html(report)
    tags = _Tags()
    tags.feed(html)
    assert tags.tags.count("script") == 1
    assert "img" not in tags.tags
    embedded = re.search(r"const report = (.*?);\n    function esc", html, re.DOTALL)
    assert embedded is not None
    assert "</script" not in embedded[1].lower()
    assert json.loads(embedded[1]) == report.to_dict()
    assert '&quot;' in html and '&#39;' in html
