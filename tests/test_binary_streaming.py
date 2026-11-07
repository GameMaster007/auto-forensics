"""Located binary strings survive chunk boundaries, limits, review, and replay."""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace

import pytest

from auto_forensics.binary_analysis import MAX_STRING_MATCHES, _scan_binary, analyze_binary, shannon_entropy
from auto_forensics.citations import citation_for_binary
from auto_forensics.cli import main
from auto_forensics.integrity import verify_run
from auto_forensics.pipeline import PipelineConfig, run_case
from auto_forensics.replay import replay_manifest
from auto_forensics.reviews import record_review
from auto_forensics.security import SecurityError


@pytest.mark.parametrize("chunk_size", [1, 2, 5, 17, 64, 1024])
def test_hashes_entropy_and_exact_ascii_utf16_offsets_are_chunk_independent(tmp_path: Path, chunk_size: int):
    path = tmp_path / "synthetic.bin"
    payload = b"\x00\xffMZ\x00PoWeRsHeLl\x00" + "VirtualAlloc".encode("utf-16le") + b"\x00\x00wmic\x00"
    path.write_bytes(payload)
    sha, md5, entropy, size, matches, count = _scan_binary(path, chunk_size)
    assert sha == hashlib.sha256(payload).hexdigest()
    assert md5 == hashlib.md5(payload, usedforsecurity=False).hexdigest()
    assert entropy == shannon_entropy(payload) and size == len(payload)
    assert [(item.keyword, item.offset, item.encoding) for item in matches] == [
        ("powershell", payload.index(b"PoWeRsHeLl"), "ascii"),
        ("virtualalloc", payload.index("VirtualAlloc".encode("utf-16le")), "utf-16le"),
        ("wmic", payload.index(b"wmic"), "ascii"),
    ]
    assert count == 3


def test_bounded_locations_keep_new_keywords_after_thousands_of_earlier_strings(tmp_path: Path):
    payload = (b"benign-looking-string\x00" * 5000) + (b"powershell\x00" * 5000) + b"cmd.exe\x00" + "WMIC".encode("utf-16le")
    path = tmp_path / "many-strings.bin"
    path.write_bytes(payload)
    feature = analyze_binary(path)
    assert feature.string_hits == ["cmd.exe", "powershell", "wmic"]
    assert feature.string_match_count == 5002 and feature.string_matches_truncated is True
    assert len(feature.string_matches) <= MAX_STRING_MATCHES
    assert feature.strings_scanned_bytes == len(payload)
    assert citation_for_binary(feature).offset == payload.index(b"cmd.exe")


def test_utf16_keyword_beyond_old_32mb_prefix_is_cited_reviewed_and_replayed(tmp_path: Path):
    source = tmp_path / "evidence"
    source.mkdir()
    path = source / "late-string.bin"
    offset = 33 * 1024 * 1024 + 7
    with path.open("wb") as handle:
        handle.write(b"MZ")
        handle.seek(offset)
        handle.write("PowerShell".encode("utf-16le") + b"\x00\x00")
    output = tmp_path / "output"
    report = run_case(PipelineConfig("large-string-case", source, output, llm_provider="mock"))
    feature = report.binary_features[0]
    assert feature.string_hits == ["powershell"]
    assert feature.string_matches[0].offset == offset
    finding = next(item for item in report.findings if item.origin == "llm")
    assert finding.citations[0].offset == offset and finding.verification == "supported"
    before = asdict(feature)
    record_review(output, finding_id=finding.finding_id, decision="accept", actor="Synthetic Analyst")
    assert json.loads((output / "case_report.json").read_text())["binary_features"][0] == before
    assert verify_run(output / "run_manifest.json")["match"] is True
    assert replay_manifest(output / "run_manifest.json")["match"] is True


def test_empty_binary_has_defined_hashes_and_no_string_matches(tmp_path: Path):
    path = tmp_path / "empty.bin"
    path.write_bytes(b"")
    feature = analyze_binary(path)
    assert feature.size_bytes == 0 and feature.entropy == 0 and feature.string_match_count == 0
    assert feature.sha256 == hashlib.sha256(b"").hexdigest()


def test_binary_changes_during_import_inspection_are_refused(tmp_path: Path, monkeypatch):
    path = tmp_path / "changing.bin"
    path.write_bytes(b"MZ synthetic")
    def change(source):
        source.write_bytes(b"changed synthetic bytes")
        return []
    monkeypatch.setattr("auto_forensics.binary_analysis._extract_pe_import_hints", change)
    with pytest.raises(SecurityError, match="changed during analysis"):
        analyze_binary(path)


def test_pe_mapping_is_closed_when_import_parsing_fails(tmp_path: Path, monkeypatch):
    from auto_forensics.binary_analysis import _extract_pe_import_hints

    closed = []
    class BrokenPE:
        def parse_data_directories(self, **kwargs):
            raise ValueError("Synthetic damaged import table")
        def close(self):
            closed.append(True)
    monkeypatch.setitem(sys.modules, "pefile", SimpleNamespace(PE=lambda *args, **kwargs: BrokenPE(), DIRECTORY_ENTRY={"IMAGE_DIRECTORY_ENTRY_IMPORT": 1}))
    assert _extract_pe_import_hints(tmp_path / "fixture.exe") == []
    assert closed == [True]


def test_inspect_binary_cli_is_offline_and_does_not_create_a_case(tmp_path: Path, monkeypatch, capsys):
    path = tmp_path / "synthetic.bin"
    path.write_bytes(b"MZ powershell")
    before = path.read_bytes()
    monkeypatch.setattr("auto_forensics.cli.AutoForensicsService", lambda config: pytest.fail("Inspection must not create a case"))
    monkeypatch.setattr(sys, "argv", ["auto-forensics", "inspect-binary", str(path)])
    main()
    payload = json.loads(capsys.readouterr().out)
    assert payload["string_matches"] == [{"keyword": "powershell", "offset": 3, "encoding": "ascii"}]
    assert path.read_bytes() == before


def test_nested_binaries_with_matching_names_and_content_retain_their_own_citations(tmp_path: Path):
    source = tmp_path / "evidence"
    for folder, content in (("host-a", b"MZ powershell"), ("host-b", b"MZ powershell"), ("host-c", b"MZ VirtualAlloc")):
        (source / folder).mkdir(parents=True)
        (source / folder / "payload.bin").write_bytes(content)
    report = run_case(PipelineConfig("nested-binaries", source, tmp_path / "output", llm_provider="mock"))
    findings = [finding for finding in report.findings if finding.origin == "llm"]
    assert len(findings) == 3
    assert {finding.citations[0].source_file for finding in findings} == {f"host-{letter}/payload.bin" for letter in "abc"}
    assert len({finding.finding_id for finding in findings}) == 3
    assert {feature.path for feature in report.binary_features} == {f"host-{letter}/payload.bin" for letter in "abc"}
