from __future__ import annotations

from pathlib import Path

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
