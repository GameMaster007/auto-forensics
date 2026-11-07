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
