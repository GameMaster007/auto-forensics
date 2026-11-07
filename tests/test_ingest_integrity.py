"""Ingestion is additive and never silently replaces existing evidence."""

from __future__ import annotations

import errno
from pathlib import Path

import pytest

from auto_forensics.case_manager import CaseManager
from auto_forensics.security import SecurityError, SecurityPolicy


@pytest.mark.parametrize("error", [errno.EPERM, errno.EOPNOTSUPP, errno.EXDEV, errno.ENOSYS])
def test_ingestion_without_hard_links_keeps_content_and_source_times(tmp_path, monkeypatch, error):
    import os

    import auto_forensics.case_manager as module

    manager = CaseManager(tmp_path / "cases", SecurityPolicy())
    evidence, _ = manager.init_case_dirs("portable-case")
    source = tmp_path / "source"
    source.mkdir()
    original = source / "artifact.txt"
    original.write_bytes(b"synthetic portable evidence\n" * 100)
    os.utime(original, ns=(1_700_000_000_000_000_000, 1_700_000_001_000_000_000))
    stamp = original.stat().st_mtime_ns
    monkeypatch.setattr(module.os, "link", lambda *a, **k: (_ for _ in ()).throw(OSError(error, "hard links unavailable")))
    intake = manager.ingest_directory_detailed("portable-case", source)
    assert (evidence / "artifact.txt").read_bytes() == original.read_bytes()
    assert (evidence / "artifact.txt").stat().st_mtime_ns == stamp
    assert intake.entries[0].sha256 == module.sha256_file(original)
    assert intake.published_paths == [evidence / "artifact.txt"]
    manager.rollback_ingest("portable-case", intake)
    assert list(evidence.iterdir()) == []


def _unsupported_links(monkeypatch):
    import auto_forensics.case_manager as module

    def unavailable(*args, **kwargs):
        raise OSError(errno.EOPNOTSUPP, "hard links unavailable")

    monkeypatch.setattr(module.os, "link", unavailable)
    return module


@pytest.mark.parametrize("winerror,allowed", [(1, True), (50, True), (5, False), (87, False)])
def test_windows_unsupported_link_codes_do_not_mask_other_failures(tmp_path, monkeypatch, winerror, allowed):
    module = _unsupported_links(monkeypatch)
    manager = CaseManager(tmp_path / "cases", SecurityPolicy())
    evidence, _ = manager.init_case_dirs("portable-case")
    source = tmp_path / "source"
    source.mkdir()
    (source / "artifact.txt").write_text("synthetic portable evidence")

    def failed_link(*args, **kwargs):
        failure = OSError(errno.EINVAL, "Windows link failure")
        failure.winerror = winerror
        raise failure

    monkeypatch.setattr(module.os, "link", failed_link)
    if allowed:
        manager.ingest_directory("portable-case", source)
        assert (evidence / "artifact.txt").read_text() == "synthetic portable evidence"
    else:
        with pytest.raises(OSError, match="Windows link failure"):
            manager.ingest_directory("portable-case", source)
        assert list(evidence.iterdir()) == []


def test_exclusive_copy_never_replaces_a_competing_destination(tmp_path, monkeypatch):
    module = _unsupported_links(monkeypatch)
    manager = CaseManager(tmp_path / "cases", SecurityPolicy())
    evidence, _ = manager.init_case_dirs("portable-case")
    source = tmp_path / "source"
    source.mkdir()
    (source / "artifact.txt").write_text("incoming evidence")

    def raced_link(staged, destination):
        destination.write_text("concurrent evidence")
        raise OSError(errno.EOPNOTSUPP, "hard links unavailable")

    monkeypatch.setattr(module.os, "link", raced_link)
    with pytest.raises(FileExistsError):
        manager.ingest_directory("portable-case", source)
    assert (evidence / "artifact.txt").read_text() == "concurrent evidence"


def test_exclusive_copy_failure_rolls_back_only_unchanged_partial_bytes(tmp_path, monkeypatch):
    module = _unsupported_links(monkeypatch)
    manager = CaseManager(tmp_path / "cases", SecurityPolicy())
    evidence, _ = manager.init_case_dirs("portable-case")
    source = tmp_path / "source"
    (source / "nested").mkdir(parents=True)
    (source / "nested/a.txt").write_text("first complete file")
    (source / "nested/b.txt").write_text("second partial file")
    write = module.os.write
    calls = 0

    def fail_after_partial(descriptor, data):
        nonlocal calls
        calls += 1
        if calls == 3:
            raise OSError(errno.ENOSPC, "injected full filesystem")
        return write(descriptor, data[:7] if calls == 2 else data)

    monkeypatch.setattr(module.os, "write", fail_after_partial)
    with pytest.raises(OSError, match="full filesystem"):
        manager.ingest_directory("portable-case", source)
    assert calls == 3
    assert list(evidence.iterdir()) == []


def test_exclusive_copy_failure_preserves_a_replaced_destination(tmp_path, monkeypatch):
    module = _unsupported_links(monkeypatch)
    manager = CaseManager(tmp_path / "cases", SecurityPolicy())
    evidence, _ = manager.init_case_dirs("portable-case")
    source = tmp_path / "source"
    source.mkdir()
    (source / "artifact.txt").write_text("incoming evidence")
    destination = evidence / "artifact.txt"
    write = module.os.write

    def replace_after_write(descriptor, data):
        write(descriptor, data[:3])
        destination.unlink()
        destination.write_text("concurrent replacement")
        raise OSError(errno.ENOSPC, "injected full filesystem")

    monkeypatch.setattr(module.os, "write", replace_after_write)
    with pytest.raises(SecurityError, match="preserved for recovery"):
        manager.ingest_directory("portable-case", source)
    assert destination.read_text() == "concurrent replacement"


def test_unsupported_link_api_and_short_writes_are_supported(tmp_path, monkeypatch):
    module = _unsupported_links(monkeypatch)
    manager = CaseManager(tmp_path / "cases", SecurityPolicy())
    evidence, _ = manager.init_case_dirs("portable-case")
    source = tmp_path / "source"
    source.mkdir()
    (source / "artifact.txt").write_text("portable evidence" * 30)

    def unavailable(*args, **kwargs):
        raise NotImplementedError("link API unavailable")

    write = module.os.write
    monkeypatch.setattr(module.os, "link", unavailable)
    monkeypatch.setattr(module.os, "write", lambda fd, data: write(fd, data[:7]))
    manager.ingest_directory("portable-case", source)
    assert (evidence / "artifact.txt").read_bytes() == (source / "artifact.txt").read_bytes()


def test_managed_exclusive_copy_rolls_back_if_custody_transaction_fails(tmp_path, monkeypatch):
    from test_archive_integrity import _service

    _unsupported_links(monkeypatch)
    service = _service(tmp_path)
    service.create_case("portable-case")
    source = tmp_path / "source"
    source.mkdir()
    (source / "artifact.txt").write_text("portable evidence")

    def failed_transaction(*args, **kwargs):
        raise RuntimeError("injected custody transaction failure")

    monkeypatch.setattr(service.db, "ingest_case_records", failed_transaction)
    with pytest.raises(RuntimeError, match="custody transaction"):
        service.ingest_case("portable-case", source)
    assert list(Path(service.require_case("portable-case")["evidence_dir"]).iterdir()) == []
    assert service.db.get_artifacts("portable-case") == []
    assert service.db.get_evidence_hash_log("portable-case") == []


def test_failed_exclusive_copy_does_not_remove_modified_same_inode(tmp_path, monkeypatch):
    module = _unsupported_links(monkeypatch)
    manager = CaseManager(tmp_path / "cases", SecurityPolicy())
    evidence, _ = manager.init_case_dirs("portable-case")
    source = tmp_path / "source"
    source.mkdir()
    (source / "artifact.txt").write_text("incoming evidence")
    destination = evidence / "artifact.txt"
    write = module.os.write

    def changed_before_failure(descriptor, data):
        write(descriptor, data[:3])
        destination.write_text("changed same inode")
        raise OSError(errno.ENOSPC, "injected full filesystem")

    monkeypatch.setattr(module.os, "write", changed_before_failure)
    with pytest.raises(SecurityError, match="preserved for recovery"):
        manager.ingest_directory("portable-case", source)
    assert destination.read_text() == "changed same inode"


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


def test_publication_failure_removes_only_owned_empty_directories(tmp_path: Path, monkeypatch):
    import auto_forensics.case_manager as module

    manager = CaseManager(tmp_path / "cases", SecurityPolicy())
    evidence, _ = manager.init_case_dirs("ingest-case")
    source = tmp_path / "source"
    (source / "folder.txt").mkdir(parents=True)
    (source / "folder.txt/inside.txt").write_text("synthetic evidence")
    with monkeypatch.context() as patch:
        patch.setattr(module.os, "link", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("injected publication failure")))
        with pytest.raises(OSError, match="injected publication failure"):
            manager.ingest_directory("ingest-case", source)
    assert not (evidence / "folder.txt").exists()
    replacement = tmp_path / "replacement"
    replacement.mkdir()
    (replacement / "folder.txt").write_text("valid later file")
    manager.ingest_directory("ingest-case", replacement)
    assert (evidence / "folder.txt").read_text() == "valid later file"
