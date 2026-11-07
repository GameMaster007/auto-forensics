"""Ingestion is additive and never silently replaces existing evidence."""

from __future__ import annotations

from pathlib import Path

import pytest

from auto_forensics.case_manager import CaseManager
from auto_forensics.security import SecurityError, SecurityPolicy


def test_repeated_ingestion_keeps_all_evidence_and_conflicts_do_not_partially_copy(tmp_path: Path):
    manager = CaseManager(tmp_path / "cases", SecurityPolicy())
    evidence, _output = manager.init_case_dirs("ingest-case")
    first = tmp_path / "first"
    first.mkdir()
    (first / "one.txt").write_text("original")
    assert len(manager.ingest_directory("ingest-case", first)) == 1
    second = tmp_path / "second"
    second.mkdir()
    (second / "two.jsonl").write_text("{}")
    entries = manager.ingest_directory("ingest-case", second)
    assert [entry.rel_path for entry in entries] == ["one.txt", "two.jsonl"]
    (second / "one.txt").write_text("overwrite attempt")
    (second / "added.txt").write_text("must not be copied")
    with pytest.raises(SecurityError, match="overwrite"):
        manager.ingest_directory("ingest-case", second)
    assert (evidence / "one.txt").read_text() == "original"
    assert not (evidence / "added.txt").exists()


def test_destination_symlinks_are_rejected_before_any_copy(tmp_path: Path):
    manager = CaseManager(tmp_path / "cases", SecurityPolicy())
    evidence, _output = manager.init_case_dirs("ingest-case")
    outside = tmp_path / "outside.txt"
    outside.write_text("untouched")
    (evidence / "one.txt").symlink_to(outside)
    source = tmp_path / "source"
    source.mkdir()
    (source / "one.txt").write_text("replace")
    with pytest.raises(SecurityError, match="symlink|escapes"):
        manager.ingest_directory("ingest-case", source)
    assert outside.read_text() == "untouched"


def test_ingestion_stages_every_file_before_publication(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    import auto_forensics.case_manager as module

    manager = CaseManager(tmp_path / "cases", SecurityPolicy())
    evidence, _output = manager.init_case_dirs("ingest-case")
    source = tmp_path / "source"
    source.mkdir()
    (source / "a.txt").write_text("first")
    (source / "b.txt").write_text("second")
    copy = module.shutil.copy2

    def corrupt(source_path: Path, destination: Path):
        result = copy(source_path, destination)
        if source_path.name == "b.txt":
            destination.write_text("corrupted")
        return result

    monkeypatch.setattr(module.shutil, "copy2", corrupt)
    with pytest.raises(SecurityError, match="changed during ingestion"):
        manager.ingest_directory("ingest-case", source)
    assert list(evidence.iterdir()) == []


def test_case_paths_and_recursive_ingest_sources_are_confined(tmp_path: Path):
    manager = CaseManager(tmp_path / "cases", SecurityPolicy())
    manager.init_case_dirs("ingest-case")
    with pytest.raises(SecurityError):
        manager.case_root("../escape")
    with pytest.raises(SecurityError, match="overlap"):
        manager.ingest_directory("ingest-case", tmp_path)


def test_skipped_source_entries_are_reported_with_reasons(tmp_path: Path):
    import os

    manager = CaseManager(tmp_path / "cases", SecurityPolicy(max_file_size_bytes=32))
    manager.init_case_dirs("ingest-case")
    source = tmp_path / "source"
    source.mkdir()
    (source / "kept.txt").write_text("kept")
    (source / "too-large.bin").write_bytes(b"x" * 33)
    (source / "unsupported.xyz").write_bytes(b"excluded")
    (source / "link.txt").symlink_to(source / "kept.txt")
    os.mkfifo(source / "pipe.log")
    intake = manager.ingest_directory_detailed("ingest-case", source)
    assert [entry.rel_path for entry in intake.entries] == ["kept.txt"]
    assert intake.skipped_counts == {"file_size_limit": 1, "unsupported_artifact": 1, "symlink": 1, "special_or_missing_file": 1}
    assert len(intake.skipped_entries) == 4 and intake.skipped_entries_truncated is False


def test_skipped_entry_details_have_an_explicit_bounded_sample(tmp_path: Path):
    manager = CaseManager(tmp_path / "cases", SecurityPolicy())
    manager.init_case_dirs("ingest-case")
    source = tmp_path / "source"
    source.mkdir()
    for index in range(1001):
        (source / f"{index}.unsupported").touch()
    intake = manager.ingest_directory_detailed("ingest-case", source)
    assert intake.entries == [] and intake.skipped_counts == {"unsupported_artifact": 1001}
    assert len(intake.skipped_entries) == 1000 and intake.skipped_entries_truncated is True


def test_special_entries_in_managed_evidence_refuse_additive_ingest(tmp_path: Path):
    import os

    manager = CaseManager(tmp_path / "cases", SecurityPolicy())
    evidence, _output = manager.init_case_dirs("ingest-case")
    os.mkfifo(evidence / "pipe.log")
    source = tmp_path / "source"
    source.mkdir()
    (source / "new.txt").write_text("not copied")
    with pytest.raises(SecurityError, match="special"):
        manager.ingest_directory("ingest-case", source)
    assert not (evidence / "new.txt").exists()
