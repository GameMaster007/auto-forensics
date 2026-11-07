"""An invalid archive must not publish a partial case or escape its root."""

from __future__ import annotations

import hashlib
import json
import stat
import zipfile
from pathlib import Path

import pytest

from auto_forensics.config import AppConfig
from auto_forensics.file_ops import directory_lock
from auto_forensics.security import SecurityError, SecurityPolicy
from auto_forensics.service import AutoForensicsService


def _service(root: Path, *, policy: SecurityPolicy | None = None, key: str | None = None) -> AutoForensicsService:
    data = root / "data"
    return AutoForensicsService(AppConfig(
        data_dir=data, cases_dir=data / "cases", db_path=data / "app.db", host="127.0.0.1", port=8765,
        production=False, api_key_hash=key, allowed_origins=[], trusted_hosts=["127.0.0.1"],
        allowed_ingest_roots=[root], rate_limit_per_minute=240, llama_endpoint="http://localhost:11434",
        llama_model="test", security_policy=policy or SecurityPolicy(),
    ))


def _row(name: str, data: bytes) -> dict:
    return {"rel_path": name, "size_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def _archive(service: AutoForensicsService, path: Path, rows: list, contents: list[tuple[str | zipfile.ZipInfo, bytes]]) -> Path:
    manifest = {"case_id": "archive-case", "files": rows}
    manifest["signature"] = service._archive_signature(manifest)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        for name, data in contents:
            archive.writestr(name, data)
    return path


@pytest.mark.parametrize("name", ["../escape.txt", "/absolute.txt", "C:/escape.txt", "a/../escape.txt", "a\\escape.txt", "."])
def test_even_a_correctly_digested_manifest_cannot_escape_case_storage(tmp_path: Path, name: str):
    service = _service(tmp_path)
    path = _archive(service, tmp_path / "bad.zip", [_row(name, b"bad")], [("evidence/safe.txt", b"bad")])
    with pytest.raises(SecurityError):
        service.import_case_archive(path)
    assert service.db.get_case("archive-case") is None
    assert not (service.config.cases_dir / "archive-case").exists()


@pytest.mark.parametrize("kind", ["zip-traversal", "symlink", "duplicate", "unlisted", "missing", "hash", "size", "non-record"])
def test_bad_archives_leave_no_partial_case(tmp_path: Path, kind: str):
    service = _service(tmp_path)
    rows = [_row("evidence/a.txt", b"first"), _row("evidence/b.txt", b"second")]
    contents: list[tuple[str | zipfile.ZipInfo, bytes]] = [("evidence/a.txt", b"first"), ("evidence/b.txt", b"second")]
    if kind == "zip-traversal":
        contents.append(("../../outside.txt", b"escape"))
    elif kind == "symlink":
        link = zipfile.ZipInfo("evidence/link.txt")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        contents.append((link, b"../../outside.txt"))
    elif kind == "duplicate":
        contents.append(("evidence/a.txt", b"first"))
    elif kind == "unlisted":
        contents.append(("output/extra.txt", b"unlisted"))
    elif kind == "missing":
        contents.pop()
    elif kind == "hash":
        rows[1]["sha256"] = "0" * 64
    elif kind == "size":
        rows[1]["size_bytes"] += 1
    else:
        rows.append("not a record")
    if kind == "duplicate":
        with pytest.warns(UserWarning, match="Duplicate name"):
            path = _archive(service, tmp_path / "bad.zip", rows, contents)
    else:
        path = _archive(service, tmp_path / "bad.zip", rows, contents)
    with pytest.raises(SecurityError):
        service.import_case_archive(path)
    assert service.db.get_case("archive-case") is None
    assert not (service.config.cases_dir / "archive-case").exists()
    assert not (tmp_path / "outside.txt").exists()
    assert not list(service.config.cases_dir.glob(".af-import-*"))


def test_compressed_members_are_bounded_before_extracting(tmp_path: Path):
    service = _service(tmp_path, policy=SecurityPolicy(max_file_size_bytes=1024, max_archive_size_bytes=10_000))
    data = b"A" * 2000
    path = _archive(service, tmp_path / "bomb.zip", [_row("evidence/a.bin", data)], [("evidence/a.bin", data)])
    with pytest.raises(SecurityError, match="file size limit"):
        service.import_case_archive(path)
    assert not (service.config.cases_dir / "archive-case").exists()


def test_export_roundtrip_restores_custody_index_and_declares_checksum_mode(tmp_path: Path):
    service = _service(tmp_path)
    service.create_case("source-case")
    source = tmp_path / "source"
    source.mkdir()
    (source / "events.jsonl").write_text('{"RuleTitle":"Synthetic", "EventID":1, "Timestamp":"2026-01-01T00:00:00Z"}\n')
    service.ingest_case("source-case", source)
    path = tmp_path / "case.zip"
    service.export_case_archive("source-case", path)
    with zipfile.ZipFile(path) as archive:
        manifest = json.loads(archive.read("manifest.json"))
    assert manifest["archive_version"] == 2
    assert manifest["integrity_algorithm"] == "sha256"
    service.import_case_archive(path, case_id_override="imported-case")
    artifacts = service.db.get_artifacts("imported-case")
    assert len(artifacts) == 1
    assert artifacts[0]["rel_path"] == "events.jsonl"
    assert service.db.get_evidence_hash_log("imported-case")


def test_keyed_archives_require_the_matching_key(tmp_path: Path):
    service = _service(tmp_path / "one", key="a" * 64)
    service.create_case("source-case")
    source = tmp_path / "one" / "source"
    source.mkdir()
    (source / "note.txt").write_text("synthetic evidence")
    service.ingest_case("source-case", source)
    path = tmp_path / "keyed.zip"
    service.export_case_archive("source-case", path)
    with zipfile.ZipFile(path) as archive:
        assert json.loads(archive.read("manifest.json"))["integrity_algorithm"] == "hmac-sha256"
    wrong = _service(tmp_path / "two", key="b" * 64)
    with pytest.raises(SecurityError, match="verification failed"):
        wrong.import_case_archive(path)
    service.import_case_archive(path, case_id_override="keyed-copy")


def test_export_rejects_symlinks_and_a_destination_inside_the_case(tmp_path: Path):
    service = _service(tmp_path)
    case = service.create_case("source-case")
    root = Path(case["evidence_dir"])
    with pytest.raises(SecurityError, match="outside the case"):
        service.export_case_archive("source-case", root / "self.zip")
    target = tmp_path / "outside.txt"
    target.write_text("private fixture")
    (root / "link.txt").symlink_to(target)
    path = tmp_path / "existing.zip"
    path.write_bytes(b"existing archive remains intact")
    with pytest.raises(SecurityError, match="symlinks"):
        service.export_case_archive("source-case", path)
    assert path.read_bytes() == b"existing archive remains intact"


def test_export_cannot_replace_failed_custody_with_a_new_archive_baseline(tmp_path: Path, monkeypatch):
    service = _service(tmp_path)
    case = service.create_case("source-case")
    source = tmp_path / "source"
    source.mkdir()
    (source / "note.txt").write_bytes(b"original evidence")
    service.ingest_case("source-case", source)
    original = service.db.get_evidence_hash_log("source-case")
    (Path(case["evidence_dir"]) / "note.txt").write_bytes(b"tampered evidence")
    # A separate read could observe original bytes while the actual ZIP
    # inventory sees tampering. The inventory itself must match custody.
    monkeypatch.setattr("auto_forensics.service.custody_changes", lambda *args: {"added": [], "missing": [], "modified": []})
    destination = tmp_path / "existing.zip"
    destination.write_bytes(b"preserved destination")
    with pytest.raises(SecurityError, match="custody index"):
        service.export_case_archive("source-case", destination)
    assert destination.read_bytes() == b"preserved destination"
    assert service.db.get_evidence_hash_log("source-case") == original
    assert not list(tmp_path.glob(".af-export-*"))


def test_imported_uppercase_hashes_allow_additive_ingest(tmp_path: Path):
    service = _service(tmp_path)
    row = _row("evidence/note.txt", b"original evidence")
    row["sha256"] = row["sha256"].upper()
    archive = _archive(service, tmp_path / "upper.zip", [row], [(row["rel_path"], b"original evidence")])
    service.import_case_archive(archive)
    assert service.db.get_artifacts("archive-case")[0]["sha256"] == row["sha256"].lower()
    source = tmp_path / "additional"
    source.mkdir()
    (source / "extra.txt").write_text("additional evidence")
    assert service.ingest_case("archive-case", source)["ingested_files"] == 1
    assert service.check_case_integrity("archive-case")["match"] is True


def test_import_applies_evidence_depth_limit_before_publishing(tmp_path: Path):
    service = _service(tmp_path)
    name = "evidence/" + "d/" * 20 + "note.txt"
    archive = _archive(service, tmp_path / "deep.zip", [_row(name, b"data")], [(name, b"data")])
    with pytest.raises(SecurityError, match="maximum directory depth"):
        service.import_case_archive(archive)
    assert service.db.get_case("archive-case") is None
    assert not (service.config.cases_dir / "archive-case").exists()


@pytest.mark.parametrize("limit", [1, 10_000])
def test_import_applies_evidence_count_limit_before_publishing(tmp_path: Path, limit: int):
    service = _service(tmp_path, policy=SecurityPolicy(max_total_files=limit))
    contents = [(f"evidence/{index}.txt", b"x") for index in range(limit + 1)]
    archive = _archive(service, tmp_path / "many.zip", [_row(name, data) for name, data in contents], contents)
    with pytest.raises(SecurityError, match="manifest file limit"):
        service.import_case_archive(archive)
    assert service.db.get_case("archive-case") is None
    assert not (service.config.cases_dir / "archive-case").exists()


@pytest.mark.parametrize("name", [
    "evidence/CON.txt", "evidence/NUL/note.txt", "evidence/COM¹.txt", "evidence/LPT³.txt", "evidence/CONIN$.txt",
    "evidence/note.txt:stream", "evidence/note?.txt",
    "evidence/trailing. /note.txt", "evidence/trailing./note.txt", "evidence/control\x01.txt",
    ".AF-output.lock", "Evidence/note.txt", "Output/note.txt", "output/Case_Report.json",
    "output/case_report.md/payload.txt", "output/analyst_reviews.jsonl/payload.txt",
])
def test_nonportable_or_reserved_archive_components_are_rejected(tmp_path: Path, name: str):
    service = _service(tmp_path)
    archive = _archive(service, tmp_path / "path.zip", [_row(name, b"data")], [(name, b"data")])
    with pytest.raises(SecurityError):
        service.import_case_archive(archive)
    assert service.db.get_case("archive-case") is None
    assert not (service.config.cases_dir / "archive-case").exists()


def test_implicit_parent_directory_case_aliases_are_rejected(tmp_path: Path):
    service = _service(tmp_path)
    contents = [("evidence/Foo/a.txt", b"one"), ("evidence/foo/b.txt", b"two")]
    archive = _archive(service, tmp_path / "alias.zip", [_row(name, data) for name, data in contents], contents)
    with pytest.raises(SecurityError, match="case-aliased path components"):
        service.import_case_archive(archive)
    assert service.db.get_case("archive-case") is None


def test_raw_nul_zip_names_cannot_be_silently_truncated(tmp_path: Path):
    service = _service(tmp_path)
    raw_name = "evidence/note.txtXhidden"
    archive = _archive(service, tmp_path / "nul.zip", [_row("evidence/note.txt", b"data")], [(raw_name, b"data")])
    archive.write_bytes(archive.read_bytes().replace(raw_name.encode(), raw_name.replace("X", "\x00").encode()))
    with pytest.raises(SecurityError, match="NUL"):
        service.import_case_archive(archive)
    assert service.db.get_case("archive-case") is None


@pytest.mark.parametrize("name", ["case_report.html", "case_report.md", "case_report.pdf", "analyst_reviews.jsonl"])
def test_unrecorded_report_formats_and_review_logs_cannot_pass_case_integrity(tmp_path: Path, name: str):
    service = _service(tmp_path)
    relative = "output/" + name
    archive = _archive(service, tmp_path / "orphan.zip", [_row(relative, b"orphan")], [(relative, b"orphan")])
    service.import_case_archive(archive)
    result = service.check_case_integrity("archive-case")
    assert result["match"] is False
    assert any("without its run manifest" in error for error in result["errors"])


def test_export_accounts_for_manifest_and_preserves_destination_on_size_failure(tmp_path: Path):
    service = _service(tmp_path, policy=SecurityPolicy(max_archive_size_bytes=1000))
    service.create_case("source-case")
    source = tmp_path / "source"
    source.mkdir()
    (source / "note.txt").write_bytes(b"A" * 850)
    service.ingest_case("source-case", source)
    destination = tmp_path / "existing.zip"
    destination.write_bytes(b"preserved destination")
    with pytest.raises(SecurityError, match="expanded archive size"):
        service.export_case_archive("source-case", destination)
    assert destination.read_bytes() == b"preserved destination"


@pytest.mark.parametrize("payload", [b"", b"A" * 850], ids=["compressed-boundary", "expanded-boundary"])
def test_exported_archive_roundtrips_at_exact_size_boundary(tmp_path: Path, monkeypatch, payload: bytes):
    service = _service(tmp_path)
    service.create_case("source-case")
    if payload:
        source = tmp_path / "source"
        source.mkdir()
        (source / "note.txt").write_bytes(payload)
        service.ingest_case("source-case", source)
    now = "2026-11-07T03:00:00.123456Z"
    monkeypatch.setattr("auto_forensics.service.utc_now_iso", lambda: now)
    destination = tmp_path / "boundary.zip"
    service.export_case_archive("source-case", destination)
    with zipfile.ZipFile(destination) as archive:
        expanded = sum(item.file_size for item in archive.infolist())
        assert json.loads(archive.read("manifest.json"))["exported_at"] == now
    compressed = destination.stat().st_size
    assert (compressed > expanded) is not bool(payload)
    required = max(compressed, expanded)
    service.config.security_policy.max_archive_size_bytes = required
    service.export_case_archive("source-case", destination)
    service.import_case_archive(destination, case_id_override="boundary-copy")
    assert service.check_case_integrity("boundary-copy")["match"] is True
    before = destination.read_bytes()
    service.config.security_policy.max_archive_size_bytes = required - 1
    with pytest.raises(SecurityError, match="size limit"):
        service.export_case_archive("source-case", destination)
    assert destination.read_bytes() == before
    assert not list(tmp_path.glob(".af-export-*"))


def test_incremental_ingest_keeps_the_full_index_and_original_provenance(tmp_path: Path):
    service = _service(tmp_path)
    case = service.create_case("source-case")
    first = tmp_path / "first"
    first.mkdir()
    (first / "one.txt").write_text("original evidence")
    assert service.ingest_case("source-case", first)["ingested_files"] == 1
    original = service.db.get_artifacts("source-case")[0]
    second = tmp_path / "second"
    second.mkdir()
    (second / "two.txt").write_text("additional evidence")
    result = service.ingest_case("source-case", second)
    assert result["ingested_files"] == 1
    assert result["total_evidence_files"] == 2
    rows = {row["rel_path"]: row for row in service.db.get_artifacts("source-case")}
    assert rows["one.txt"] == original
    assert set(rows) == {"one.txt", "two.txt"}
    with directory_lock(Path(case["evidence_dir"]).parent):
        with pytest.raises(SecurityError, match="busy"):
            service.ingest_case("source-case", second)
    (Path(case["evidence_dir"]) / "one.txt").write_text("tampered")
    with pytest.raises(SecurityError, match="custody hash"):
        service.ingest_case("source-case", second)


def test_api_archive_paths_honor_read_and_write_boundaries(tmp_path: Path):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from auto_forensics.api import create_app

    service = _service(tmp_path)
    service.create_case("source-case")
    with TestClient(create_app(service.config), base_url="http://127.0.0.1") as client:
        outside = tmp_path / "outside.zip"
        denied = client.post("/api/cases/source-case/export", json={"destination_path": str(outside)})
        assert denied.status_code == 400
        assert not outside.exists()
        exported = client.post("/api/cases/source-case/export", json={"destination_path": "safe.zip"})
        assert exported.status_code == 200
        archive = service.config.data_dir / "exports" / "safe.zip"
        assert archive.is_file()
        imported = client.post("/api/cases/import", json={"archive_path": str(archive), "case_id_override": "api-copy"})
        assert imported.status_code == 200
        service.config.allowed_ingest_roots = [tmp_path / "allowed-only"]
        denied = client.post("/api/cases/import", json={"archive_path": str(archive), "case_id_override": "denied-copy"})
        assert denied.status_code == 400
