"""Malformed Unicode cannot turn finite JSON into an encoding-time failure."""
from __future__ import annotations

import json

import pytest

from auto_forensics.integrity import verify_run
from auto_forensics.pipeline import PipelineConfig, run_case
from auto_forensics.security import SecurityError, validate_json_nesting


@pytest.mark.parametrize("point", [0xD800, 0xDBFF, 0xDC00, 0xDFFF])
@pytest.mark.parametrize("location", ["value", "key"])
def test_json_surrogates_are_refused_at_the_shared_boundary(point, location):
    text = "prefix" + chr(point) + "suffix"
    data = {text: "value"} if location == "key" else {"records": [{"description": text}]}
    with pytest.raises(SecurityError, match="Unicode surrogates"):
        validate_json_nesting(data)


def test_valid_unicode_and_a_decoded_surrogate_pair_remain_supported():
    text = json.loads('"\\ud83d\\ude03"')
    validate_json_nesting({"日本語": [text, "é", "\u2028", "\ufffd"]})
    assert text == "😃"


@pytest.mark.parametrize("suffix", [".json", ".jsonl"])
@pytest.mark.parametrize("location", ["value", "key"])
def test_invalid_json_unicode_cannot_crash_or_publish_an_unreadable_run(tmp_path, suffix, location):
    source = tmp_path / "evidence"
    source.mkdir()
    row = {"Timestamp": "2026-11-07T00:00:00Z", "Channel": "Sysmon", "EventID": 1, "Level": "high", "RuleTitle": "Detection"}
    if location == "value":
        row["RuleTitle"] += chr(0xD800)
    else:
        row[chr(0xDFFF)] = "extra"
    (source / ("hayabusa" + suffix)).write_text(json.dumps(row))
    output = tmp_path / "output"
    report = run_case(PipelineConfig("unicode-case", source, output, enable_llama=False))
    assert report.findings == []
    assert verify_run(output / "run_manifest.json")["match"] is True
    for name in ("case_report.json", "case_report.md", "case_report.html"):
        assert (output / name).read_text(encoding="utf-8")
