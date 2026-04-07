"""Tests for the watcher module."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest


def test_derive_case_id_basic():
    from auto_forensics.watcher import derive_case_id

    assert derive_case_id("M57-Jean") == "M57-Jean"


def test_derive_case_id_starting_with_digit():
    from auto_forensics.watcher import derive_case_id

    # digit-leading is fine for case IDs (first char must be alnum)
    result = derive_case_id("2024-incident")
    assert result[0].isalnum()
    assert "2024" in result or result.startswith("af-")


def test_derive_case_id_path_traversal_chars_sanitized():
    from auto_forensics.watcher import derive_case_id

    result = derive_case_id("../../evil/path")
    # Should not contain slashes or dots from path separators
    assert "/" not in result
    assert "\\" not in result
    assert ".." not in result
    # Result must be a valid non-empty string starting with alnum
    assert result and result[0].isalnum()


def test_derive_case_id_strips_special_chars():
    from auto_forensics.watcher import derive_case_id

    result = derive_case_id("case name with spaces & symbols!")
    assert " " not in result
    assert "&" not in result
    assert "!" not in result


def test_processed_registry_roundtrip(tmp_path):
    from auto_forensics.watcher import ProcessedRegistry

    reg = ProcessedRegistry(tmp_path)
    assert not reg.is_processed("disk.e01")

    reg.mark_processed("disk.e01", "case-001", "success", details={"artifacts": 5})
    assert reg.is_processed("disk.e01")
    entries = reg.all_entries()
    assert "disk.e01" in entries
    assert entries["disk.e01"]["case_id"] == "case-001"
    assert entries["disk.e01"]["status"] == "success"


def test_processed_registry_persists_across_instances(tmp_path):
    from auto_forensics.watcher import ProcessedRegistry

    reg1 = ProcessedRegistry(tmp_path)
    reg1.mark_processed("image.vhd", "case-002", "success")

    reg2 = ProcessedRegistry(tmp_path)
    assert reg2.is_processed("image.vhd")
    assert reg2.all_entries()["image.vhd"]["case_id"] == "case-002"


def test_drop_watcher_processes_new_directory(tmp_path):
    """DropWatcher should call process_drop_item for a new subdirectory."""
    from auto_forensics.watcher import DropWatcher

    drop_dir = tmp_path / "drop"
    drop_dir.mkdir()
    evidence = drop_dir / "evidence-folder"
    evidence.mkdir()

    mock_service = MagicMock()
    mock_service.process_drop_item.return_value = {
        "case_id": "evidence-folder",
        "artifacts": 3,
        "findings": 1,
    }

    watcher = DropWatcher(mock_service, drop_dir, interval=5)
    watcher._scan_once()

    mock_service.process_drop_item.assert_called_once()
    call_args = mock_service.process_drop_item.call_args
    assert call_args[0][0] == evidence  # item_path


def test_drop_watcher_skips_already_processed(tmp_path):
    """DropWatcher must not reprocess items already in the registry."""
    from auto_forensics.watcher import DropWatcher, ProcessedRegistry

    drop_dir = tmp_path / "drop"
    drop_dir.mkdir()
    folder = drop_dir / "old-case"
    folder.mkdir()

    # Pre-populate registry
    reg = ProcessedRegistry(drop_dir)
    reg.mark_processed("old-case", "old-case", "success")

    mock_service = MagicMock()
    watcher = DropWatcher(mock_service, drop_dir, interval=5)
    watcher._scan_once()

    mock_service.process_drop_item.assert_not_called()


def test_process_drop_item_creates_case_in_db(tmp_path):
    """Integration test: process_drop_item creates a case and ingests artifacts."""
    import os

    os.environ.setdefault("AUTO_FORENSICS_HOME", str(tmp_path))

    from auto_forensics.config import AppConfig
    from auto_forensics.service import AutoForensicsService

    config = AppConfig.from_env()
    config.data_dir = tmp_path
    config.cases_dir = tmp_path / "cases"
    config.db_path = tmp_path / "app.db"
    config.cases_dir.mkdir(parents=True, exist_ok=True)

    svc = AutoForensicsService(config)

    # Create a small evidence directory
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "events.json").write_text(
        '[{"event_type": "test", "description": "hello", "source": "test.json"}]',
        encoding="utf-8",
    )

    result = svc.process_drop_item(evidence, "test-drop-001", enable_llm=False, auto_extract=False)

    assert result["case_id"] == "test-drop-001"
    assert result["artifacts"] >= 1
    case = svc.db.get_case("test-drop-001")
    assert case is not None
    assert case["status"] in ("complete", "ready", "failed")
