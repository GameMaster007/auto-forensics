"""Tests for new CLI commands and service methods added in the CLI expansion."""
from __future__ import annotations

import json
import os
import textwrap
from pathlib import Path

from auto_forensics.config import AppConfig
from auto_forensics.service import AutoForensicsService
from auto_forensics.security import SecurityError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_cfg(tmp_path: Path) -> AppConfig:
    data_dir = tmp_path / "af_data"
    data_dir.mkdir()
    cases_dir = data_dir / "cases"
    cases_dir.mkdir()
    db_path = data_dir / "app.db"
    from auto_forensics.security import SecurityPolicy

    return AppConfig(
        data_dir=data_dir,
        cases_dir=cases_dir,
        db_path=db_path,
        host="127.0.0.1",
        port=0,
        production=False,
        api_key_hash=None,
        allowed_origins=[],
        trusted_hosts=["127.0.0.1"],
        allowed_ingest_roots=[tmp_path],
        rate_limit_per_minute=999,
        llama_endpoint="http://localhost:11434",
        llama_model="llama3.1:8b",
        security_policy=SecurityPolicy(),
    )


def _write_sample_file(tmp_path: Path, name: str = "sample.txt", content: bytes = b"Hello World") -> Path:
    p = tmp_path / name
    p.write_bytes(content)
    return p


def _write_minimal_source(source: Path) -> None:
    source.mkdir(parents=True, exist_ok=True)
    (source / "events.json").write_text(
        json.dumps([
            {"timestamp": "2026-01-15T10:00:00Z", "event_type": "test_event", "description": "Test event 1"},
            {"timestamp": "2026-01-15T12:00:00Z", "event_type": "logon", "description": "User logon detected"},
        ]),
        encoding="utf-8",
    )
    # A small "binary" to trigger analysis
    (source / "test.bin").write_bytes(b"\x00" * 100 + b"powershell cmd.exe http://evil.com" + b"\x00" * 100)


# ---------------------------------------------------------------------------
# scan_file tests
# ---------------------------------------------------------------------------


def test_scan_file_returns_hashes(tmp_path: Path) -> None:
    cfg = _make_cfg(tmp_path)
    svc = AutoForensicsService(cfg)
    sample = _write_sample_file(tmp_path, content=b"test file content for hashing")
    result = svc.scan_file(sample)

    assert "sha256" in result
    assert "md5" in result
    assert len(result["sha256"]) == 64
    assert "entropy" in result
    assert "suspicious_score" in result
    assert result["size_bytes"] == len(b"test file content for hashing")
    assert "yara_hits" in result


def test_scan_file_detects_suspicious_strings(tmp_path: Path) -> None:
    cfg = _make_cfg(tmp_path)
    svc = AutoForensicsService(cfg)
    # Create a file with suspicious keywords
    evil = tmp_path / "evil.bin"
    evil.write_bytes(b"\x00" * 50 + b"powershell -enc AAAA cmd.exe /c malware http://bad.evil" + b"\x00" * 50)
    result = svc.scan_file(evil)
    assert result["suspicious_score"] > 0
    assert len(result["string_hits"]) > 0


def test_scan_file_rejects_nonexistent(tmp_path: Path) -> None:
    cfg = _make_cfg(tmp_path)
    svc = AutoForensicsService(cfg)
    import pytest
    with pytest.raises(SecurityError):
        svc.scan_file(tmp_path / "nonexistent.txt")


# ---------------------------------------------------------------------------
# scan_directory tests
# ---------------------------------------------------------------------------


def test_scan_directory_scans_all_files(tmp_path: Path) -> None:
    cfg = _make_cfg(tmp_path)
    svc = AutoForensicsService(cfg)
    scan_dir = tmp_path / "scan_target"
    scan_dir.mkdir()
    (scan_dir / "a.txt").write_bytes(b"file A content")
    (scan_dir / "b.bin").write_bytes(b"file B content powershell cmd.exe")
    sub = scan_dir / "sub"
    sub.mkdir()
    (sub / "c.txt").write_bytes(b"nested file C")

    result = svc.scan_directory(scan_dir, recursive=True)
    assert result["total_files"] == 3
    assert result["total_bytes"] > 0
    assert result["directory"] == str(scan_dir.resolve())
    # The most suspicious file should be first (sorted by score desc)
    assert len(result["files"]) == 3


def test_scan_directory_nonrecursive(tmp_path: Path) -> None:
    cfg = _make_cfg(tmp_path)
    svc = AutoForensicsService(cfg)
    scan_dir = tmp_path / "flat_scan"
    scan_dir.mkdir()
    (scan_dir / "a.txt").write_bytes(b"file A")
    sub = scan_dir / "sub"
    sub.mkdir()
    (sub / "b.txt").write_bytes(b"file B")

    result = svc.scan_directory(scan_dir, recursive=False)
    assert result["total_files"] == 1  # only top-level


# ---------------------------------------------------------------------------
# generate_conclusions tests
# ---------------------------------------------------------------------------


def test_generate_conclusions_empty_case(tmp_path: Path) -> None:
    cfg = _make_cfg(tmp_path)
    svc = AutoForensicsService(cfg)
    svc.create_case("test-conclusions-empty")

    result = svc.generate_conclusions("test-conclusions-empty")
    assert result["case_id"] == "test-conclusions-empty"
    assert result["total_findings"] == 0
    assert result["risk_verdict"] == "LOW"
    assert len(result["conclusions"]) > 0
    assert any("benign" in c.lower() or "no findings" in c.lower() for c in result["conclusions"])


def test_generate_conclusions_with_analysis(tmp_path: Path) -> None:
    cfg = _make_cfg(tmp_path)
    svc = AutoForensicsService(cfg)
    svc.create_case("test-conclusions-full")
    source = tmp_path / "evidence_src"
    _write_minimal_source(source)
    svc.ingest_case("test-conclusions-full", source)
    svc.analyze_case("test-conclusions-full", enable_llama=False)

    result = svc.generate_conclusions("test-conclusions-full")
    assert result["case_id"] == "test-conclusions-full"
    # After analysis, we should have a proper verdict and conclusions
    assert "risk_verdict" in result
    assert isinstance(result["conclusions"], list)
    assert len(result["conclusions"]) >= 1
    assert "details" in result


# ---------------------------------------------------------------------------
# filter_timeline tests
# ---------------------------------------------------------------------------


def test_filter_timeline_basic(tmp_path: Path) -> None:
    cfg = _make_cfg(tmp_path)
    svc = AutoForensicsService(cfg)
    svc.create_case("test-timeline-filter")
    source = tmp_path / "evidence_filter"
    _write_minimal_source(source)
    svc.ingest_case("test-timeline-filter", source)
    svc.analyze_case("test-timeline-filter", enable_llama=False)

    # Get all events
    result = svc.filter_timeline("test-timeline-filter")
    assert result["case_id"] == "test-timeline-filter"
    assert result["total_events"] >= 0
    assert result["matched_events"] == result["total_events"]

    # Filter by keyword that likely doesn't match
    result_kw = svc.filter_timeline("test-timeline-filter", keyword="xyznonexistent")
    assert result_kw["matched_events"] == 0


def test_filter_timeline_risk_threshold(tmp_path: Path) -> None:
    cfg = _make_cfg(tmp_path)
    svc = AutoForensicsService(cfg)
    svc.create_case("test-timeline-risk")
    source = tmp_path / "evidence_risk"
    _write_minimal_source(source)
    svc.ingest_case("test-timeline-risk", source)
    svc.analyze_case("test-timeline-risk", enable_llama=False)

    # Filter with a very high threshold — should return 0 or fewer events
    result = svc.filter_timeline("test-timeline-risk", min_risk=999)
    assert result["matched_events"] == 0


# ---------------------------------------------------------------------------
# CLI parser tests
# ---------------------------------------------------------------------------


def test_build_parser_has_new_commands() -> None:
    from auto_forensics.cli import build_parser
    parser = build_parser()
    # Extract subcommand names
    for action in parser._subparsers._actions:
        if hasattr(action, "_name_parser_map"):
            commands = set(action._name_parser_map.keys())
            break
    else:
        commands = set()

    expected = {
        "scan", "scan-dir", "conclusions", "timeline-filter",
        "iocs", "audit", "hash", "config", "version", "start",
    }
    for cmd in expected:
        assert cmd in commands, f"Missing subcommand: {cmd}"


def test_hash_command_parser() -> None:
    from auto_forensics.cli import build_parser
    parser = build_parser()
    args = parser.parse_args(["hash", "--path", "test.txt", "--algo", "all"])
    assert args.command == "hash"
    assert args.algo == "all"
    assert args.path == Path("test.txt")


def test_scan_command_parser() -> None:
    from auto_forensics.cli import build_parser
    parser = build_parser()
    args = parser.parse_args(["scan", "--path", "sample.exe", "--json"])
    assert args.command == "scan"
    assert args.json is True


def test_conclusions_command_parser() -> None:
    from auto_forensics.cli import build_parser
    parser = build_parser()
    args = parser.parse_args(["conclusions", "--case-id", "case-001", "--json"])
    assert args.command == "conclusions"
    assert args.case_id == "case-001"


def test_timeline_filter_command_parser() -> None:
    from auto_forensics.cli import build_parser
    parser = build_parser()
    args = parser.parse_args([
        "timeline-filter", "--case-id", "case-001",
        "--after", "2026-01-01", "--min-risk", "50",
        "--keyword", "malware",
    ])
    assert args.command == "timeline-filter"
    assert args.after == "2026-01-01"
    assert args.min_risk == 50.0
    assert args.keyword == "malware"


def test_iocs_command_parser() -> None:
    from auto_forensics.cli import build_parser
    parser = build_parser()
    args = parser.parse_args(["iocs", "--case-id", "case-001", "--type", "ip", "--export", "csv"])
    assert args.command == "iocs"
    assert args.type == "ip"
    assert args.export == "csv"
