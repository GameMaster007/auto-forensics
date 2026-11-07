from __future__ import annotations

from pathlib import Path

import pytest

from auto_forensics.yara_detector import scan_paths_with_yara


def test_scan_paths_with_yara_returns_empty_when_rules_dir_missing(tmp_path: Path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ test")

    findings, hints = scan_paths_with_yara([sample], rules_dir=tmp_path / "missing-rules")

    assert findings == []
    assert hints == []


def test_scan_paths_with_yara_returns_empty_when_no_rules_exist(tmp_path: Path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ test")

    findings, hints = scan_paths_with_yara([sample], rules_dir=rules_dir)

    assert findings == []
    assert hints == []


def test_identical_nested_yara_matches_keep_distinct_sources_and_replay_after_relocation(tmp_path):
    import shutil

    from auto_forensics.integrity import verify_run
    from auto_forensics.pipeline import PipelineConfig, run_case
    from auto_forensics.replay import replay_manifest

    pytest.importorskip("yara")
    source = tmp_path / "evidence"
    for host in ("host1", "host2"):
        (source / host).mkdir(parents=True)
        (source / host / "sample.bin").write_bytes(b"MZ synthetic yara marker")
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "synthetic.yar").write_text('rule synthetic { strings: $marker = "synthetic yara marker" condition: $marker }')
    output = tmp_path / "output"
    report = run_case(PipelineConfig(case_id="nested-yara", input_dir=source, output_dir=output, rules_dir=rules, enable_llama=False))
    matches = [finding for finding in report.findings if finding.title == "YARA match: synthetic"]
    assert len(matches) == 2
    assert len({finding.finding_id for finding in matches}) == 2
    assert {finding.citations[0].source_file for finding in matches} == {"host1/sample.bin", "host2/sample.bin"}
    assert len({finding.citations[0].sha256 for finding in matches}) == 1
    assert verify_run(output / "run_manifest.json")["match"] is True
    relocated = tmp_path / "relocated"
    shutil.copytree(source, relocated)
    result = replay_manifest(output / "run_manifest.json", tmp_path / "replay", input_dir=relocated)
    assert result["match"] is True
