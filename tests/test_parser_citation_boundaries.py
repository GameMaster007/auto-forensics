"""Focused parser/citation regressions; run with the chosen source on PYTHONPATH."""
from __future__ import annotations

import csv
import hashlib
import io
import json
from pathlib import Path

import pytest

from auto_forensics.artifacts import load_csv_artifacts, load_json_artifacts, load_txt_artifacts
from auto_forensics.citations import citation_from_event
from auto_forensics.integrity import verify_run
from auto_forensics.models import Citation, Finding
from auto_forensics.pipeline import PipelineConfig, run_case
from auto_forensics.timeline_imports import events_from_json_lines, findings_from_imported_timelines
from auto_forensics.verifier import read_cited_text, verify_findings


@pytest.mark.parametrize("separator", ["\u2028", "\u2029", "\u0085"], ids=["line-separator", "paragraph-separator", "nel"])
@pytest.mark.parametrize("newline", ["\n", "\r\n"], ids=["lf", "crlf"])
def test_csv_unicode_field_cannot_supply_another_records_claim(tmp_path: Path, separator: str, newline: str):
    claim = "Credentials were stolen"
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator=newline)
    writer.writerow(["description", "source", "event_type"])
    writer.writerow(["prefix," + separator + claim, "fixture", "event"])
    writer.writerow(["Ordinary unrelated second record", "fixture", "event"])
    path = tmp_path / "rows.csv"
    path.write_bytes(buffer.getvalue().encode("utf-8"))
    events = load_csv_artifacts(path)
    assert [event.metadata["row"] for event in events] == [2, 3]
    first = citation_from_event(events[0])
    second = citation_from_event(events[1])
    assert first is not None and second is not None
    assert claim in read_cited_text(tmp_path, first)[0]
    cited, error = read_cited_text(tmp_path, second)
    assert not error and cited is not None
    assert claim not in cited
    unsupported = Finding("wrong-row", "Fixture", "high", 0.8, "credential-access", evidence=[claim], citations=[second])
    kept, verdicts = verify_findings([unsupported], tmp_path)
    assert kept == [] and verdicts[0].verdict == "rejected"


@pytest.mark.parametrize("prefix", [b"\xff" * 100, b"\xe2\x82", b"\xed\xa0\x80", "\u00e9".encode()], ids=["invalid-bytes", "truncated-utf8", "invalid-surrogate", "valid-utf8"])
@pytest.mark.parametrize("newline", [b"\n", b"\r\n"], ids=["lf", "crlf"])
def test_text_offsets_count_original_bytes_not_replacement_characters(tmp_path: Path, prefix: bytes, newline: bytes):
    path = tmp_path / "sysmon.log"
    marker = b"2026-01-01T00:00:00Z|process_start|fixture event"
    data = prefix + newline + marker + newline
    path.write_bytes(data)
    events = load_txt_artifacts(path)
    assert len(events) == 2
    pointer = citation_from_event(events[1])
    assert pointer is not None and pointer.row == 2
    assert pointer.offset == data.index(marker)
    assert data[pointer.offset:].startswith(marker)
    assert events[0].description == prefix.decode("utf-8", errors="replace")


def test_invalid_utf8_text_cannot_publish_an_immediately_unverifiable_run(tmp_path: Path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "sysmon.log").write_bytes(b"\xff" * 100 + b"\n2026-01-01T00:00:00Z|process_start|fixture event\n")
    output = tmp_path / "output"
    report = run_case(PipelineConfig("offset-case", evidence, output, enable_llama=False))
    assert len(report.findings) == 1
    assert report.findings[0].citations[0].offset == 101
    assert verify_run(output / "run_manifest.json")["match"] is True


def _hayabusa(title: str) -> dict:
    return {"Timestamp": "2026-01-01T00:00:00Z", "Channel": "Sysmon", "EventID": 1, "Level": "high", "RuleTitle": title}


@pytest.mark.parametrize("newline", ["\n", "\r\n"], ids=["lf", "crlf"])
@pytest.mark.parametrize("blank_lines", [1, 2])
def test_single_jsonl_object_retains_its_physical_line(tmp_path: Path, newline: str, blank_lines: int):
    path = tmp_path / "hayabusa.jsonl"
    path.write_bytes((newline * blank_lines + json.dumps(_hayabusa("Actual detection")) + newline).encode())
    events = load_json_artifacts(path)
    assert len(events) == 1 and events[0].metadata["row"] == blank_lines + 1
    findings = findings_from_imported_timelines(events)
    kept, verdicts = verify_findings(findings, tmp_path)
    assert len(kept) == 1 and verdicts[0].verdict == "supported"


@pytest.mark.parametrize("newline", ["\n", "\r\n"], ids=["lf", "crlf"])
@pytest.mark.parametrize("suffix", [".jsonl", ".json"], ids=["jsonl", "json-ndjson-fallback"])
def test_json_lines_unicode_inside_field_is_not_a_physical_line_break(tmp_path: Path, newline: str, suffix: str):
    path = tmp_path / ("hayabusa" + suffix)
    rows = [_hayabusa("First\u2028rule"), _hayabusa("Second rule")]
    path.write_bytes((newline.join(json.dumps(row, ensure_ascii=False) for row in rows) + newline).encode())
    events = load_json_artifacts(path)
    assert [event.description for event in events] == [row["RuleTitle"] for row in rows]
    assert [event.metadata["row"] for event in events] == [1, 2]
    kept, verdicts = verify_findings(findings_from_imported_timelines(events), tmp_path)
    assert len(kept) == 2 and {verdict.verdict for verdict in verdicts} == {"supported"}
    direct = events_from_json_lines(path.read_text(), path.name, events[0].metadata["source_sha256"])
    assert [event.metadata["row"] for event in direct] == [1, 2]
    assert [event.description for event in direct] == [row["RuleTitle"] for row in rows]


def test_generic_single_object_jsonl_stays_supported(tmp_path: Path):
    path = tmp_path / "generic.jsonl"
    path.write_text('\n{"event_type":"fixture","description":"Generic fixture","source":"fixture"}\n')
    events = load_json_artifacts(path)
    assert len(events) == 1 and events[0].description == "Generic fixture"
    assert events[0].metadata["row"] == 2


def test_generic_object_jsonl_uses_physical_rows(tmp_path: Path):
    path = tmp_path / "generic.jsonl"
    rows = [{"event_type": "fixture", "description": "First fixture"}, {"event_type": "fixture", "description": "Second fixture"}]
    path.write_text("\n" + "\n\n".join(json.dumps(row) for row in rows) + "\n")
    events = load_json_artifacts(path)
    assert [event.description for event in events] == [row["description"] for row in rows]
    assert [event.metadata["row"] for event in events] == [2, 4]


@pytest.mark.parametrize("following_object", [False, True])
def test_jsonl_array_values_do_not_become_fictitious_record_lines(tmp_path: Path, following_object: bool):
    path = tmp_path / "hayabusa.jsonl"
    text = json.dumps([_hayabusa("Array item one"), _hayabusa("Array item two")]) + "\n"
    if following_object:
        text += json.dumps(_hayabusa("Actual object record")) + "\n"
    path.write_text(text)
    events = load_json_artifacts(path)
    assert [event.description for event in events] == (["Actual object record"] if following_object else [])
    assert [event.metadata["row"] for event in events] == ([2] if following_object else [])
    if events:
        kept, verdicts = verify_findings(findings_from_imported_timelines(events), tmp_path)
        assert len(kept) == 1 and verdicts[0].verdict == "supported"


def test_json_array_record_indices_stay_unchanged(tmp_path: Path):
    path = tmp_path / "hayabusa.json"
    path.write_text(json.dumps([_hayabusa("First rule"), _hayabusa("Second rule")], indent=2))
    events = load_json_artifacts(path)
    assert [event.metadata["row"] for event in events] == [1, 2]
    kept, verdicts = verify_findings(findings_from_imported_timelines(events), tmp_path)
    assert len(kept) == 2 and {verdict.verdict for verdict in verdicts} == {"supported"}


def test_mixed_json_array_keeps_established_dictionary_record_ordinals(tmp_path: Path):
    path = tmp_path / "mixed.json"
    rows = [None, _hayabusa("First rule"), _hayabusa("Second rule")]
    path.write_text(json.dumps(rows, indent=2))
    events = load_json_artifacts(path)
    assert [event.metadata["row"] for event in events] == [1, 2]
    kept, verdicts = verify_findings(findings_from_imported_timelines(events), tmp_path)
    assert len(kept) == 2 and {verdict.verdict for verdict in verdicts} == {"supported"}


def test_logical_json_row_outside_record_count_never_falls_back_to_pretty_lines(tmp_path: Path):
    path = tmp_path / "events.json"
    claim = "First detection"
    path.write_text(json.dumps([{"description": claim}, {"description": "Second detection"}], indent=2))
    physical_row = next(index for index, line in enumerate(path.read_text().splitlines(), start=1) if claim in line)
    assert physical_row > 2
    pointer = Citation("outside-logical-records", path.name, hashlib.sha256(path.read_bytes()).hexdigest(), row=physical_row)
    assert read_cited_text(tmp_path, pointer)[0] is None
    finding = Finding("outside-json-records", "Fixture", "low", 0.5, "fixture", evidence=[claim], citations=[pointer])
    kept, verdicts = verify_findings([finding], tmp_path)
    assert kept == [] and verdicts[0].verdict == "rejected"


def test_json_object_record_index_does_not_change_for_leading_blanks(tmp_path: Path):
    path = tmp_path / "object.json"
    path.write_text("\n\n" + json.dumps(_hayabusa("Actual JSON object")) + "\n")
    events = load_json_artifacts(path)
    assert len(events) == 1 and events[0].metadata["row"] == 1
    kept, verdicts = verify_findings(findings_from_imported_timelines(events), tmp_path)
    assert len(kept) == 1 and verdicts[0].verdict == "supported"
