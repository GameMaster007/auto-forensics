"""Validate an entire archive before publishing any imported case files."""

from __future__ import annotations

import hashlib
import json
import stat
import zipfile
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Callable

from .manifest import REPORT_ARTIFACT_NAMES, valid_digest
from .security import SecurityError, SecurityPolicy, validate_json_nesting

_WINDOWS_DEVICES = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"} | {
    f"{prefix}{digit}" for prefix in ("COM", "LPT") for digit in "123456789¹²³"
}


def archive_relative_path(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise SecurityError("Archive has an invalid relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or PureWindowsPath(value).drive or ".." in path.parts or str(path) != value:
        raise SecurityError("Archive path escapes or aliases the case directory")
    if not path.parts or path.parts[0].casefold().startswith(".af-") or value.casefold() == "manifest.json":
        raise SecurityError("Archive has a reserved or empty case path")
    for component in path.parts:
        if (component.split(".")[0].rstrip(" ").upper() in _WINDOWS_DEVICES or component.endswith((".", " "))
                or any(ord(character) < 32 or character in '<>:"|?*' for character in component)):
            raise SecurityError("Archive has a nonportable path component")
    reserved_output = {*REPORT_ARTIFACT_NAMES, "run_manifest.json", "analyst_reviews.jsonl"}
    if path.parts[0].casefold() in {"evidence", "output"} and path.parts[0] not in {"evidence", "output"}:
        raise SecurityError("Archive aliases a required case directory")
    if len(path.parts) > 1 and path.parts[0] == "output" and path.parts[1].casefold() in reserved_output and path.parts[1] not in reserved_output:
        raise SecurityError("Archive aliases a reserved output file")
    if path.parts[0].casefold() == "manifest.json" or (
        len(path.parts) > 2 and path.parts[0] == "output" and path.parts[1] in reserved_output
    ):
        raise SecurityError("Archive uses a reserved file name as a directory")
    return value


def record_archive_path(name: str, spellings: dict[str, str]) -> None:
    """Reject differently spelled implicit parents on case-insensitive hosts."""
    parts = PurePosixPath(name).parts
    for end in range(1, len(parts) + 1):
        prefix = "/".join(parts[:end])
        key = prefix.casefold()
        if key in spellings and spellings[key] != prefix:
            raise SecurityError("Archive has case-aliased path components")
        spellings[key] = prefix


def extract_verified_archive(
    archive_path: Path,
    staging_root: Path,
    policy: SecurityPolicy,
    verify_signature: Callable[[dict[str, Any]], None],
) -> dict[str, Any]:
    """Extract only listed, bounded, hash-verified regular files into staging."""
    try:
        if archive_path.stat().st_size > policy.max_archive_size_bytes:
            raise SecurityError("Archive exceeds the compressed size limit")
        with zipfile.ZipFile(archive_path) as archive:
            members: dict[str, zipfile.ZipInfo] = {}
            seen: set[str] = set()
            spellings: dict[str, str] = {}
            total_bytes = 0
            if len(archive.infolist()) > min(policy.max_total_files + 32, 10_032):
                raise SecurityError("Archive exceeds the file count limit")
            for info in archive.infolist():
                if info.orig_filename != info.filename or "\x00" in info.orig_filename:
                    raise SecurityError("Archive has a truncated or NUL-containing member path")
                name = info.filename.rstrip("/") if info.is_dir() else info.filename
                if name != "manifest.json":
                    archive_relative_path(name)
                record_archive_path(name, spellings)
                key = name.casefold()
                if key in seen:
                    raise SecurityError("Archive has duplicate or case-aliased paths")
                seen.add(key)
                mode = stat.S_IFMT(info.external_attr >> 16)
                if mode not in {0, stat.S_IFREG, stat.S_IFDIR} or info.flag_bits & 1:
                    raise SecurityError("Archive has a symlink, special, or encrypted entry")
                if info.is_dir():
                    if name.startswith("output/") and name.split("/")[-1] in {*REPORT_ARTIFACT_NAMES, "run_manifest.json", "analyst_reviews.jsonl"}:
                        raise SecurityError("Archive uses a reserved file name as a directory")
                    continue
                if name in {"evidence", "output"}:
                    raise SecurityError("Archive replaces a required case directory with a file")
                if mode == stat.S_IFDIR:
                    raise SecurityError("Archive directory metadata disagrees with its path")
                limit = 4 * 1024 * 1024 if name == "manifest.json" else policy.max_file_size_bytes
                if info.file_size > limit:
                    raise SecurityError("Archive member exceeds the file size limit")
                total_bytes += info.file_size
                if total_bytes > policy.max_archive_size_bytes:
                    raise SecurityError("Archive exceeds the expanded size limit")
                members[name] = info
            if "manifest.json" not in members:
                raise SecurityError("Archive missing manifest.json")
            manifest = json.loads(archive.read(members["manifest.json"]).decode("utf-8"))
            validate_json_nesting(manifest)
            if not isinstance(manifest, dict):
                raise SecurityError("Invalid archive manifest")
            verify_signature(manifest)
            rows = manifest.get("files")
            if not isinstance(rows, list) or len(rows) > min(policy.max_total_files + 16, 10_016):
                raise SecurityError("Invalid archive file inventory")
            listed: set[str] = set()
            for row in rows:
                if not isinstance(row, dict):
                    raise SecurityError("Archive inventory contains a non-record")
                name = archive_relative_path(row.get("rel_path"))
                if name.casefold() in listed:
                    raise SecurityError("Archive inventory has duplicate paths")
                listed.add(name.casefold())
                if not valid_digest(row.get("sha256")) or type(row.get("size_bytes")) is not int or row["size_bytes"] < 0:
                    raise SecurityError("Archive inventory has an invalid hash or size")
                listed_member = members.get(name)
                if listed_member is None or listed_member.file_size != row["size_bytes"]:
                    raise SecurityError(f"Archive is missing a listed file or has a size mismatch: {name}")
            if listed != {name.casefold() for name in members if name != "manifest.json"}:
                raise SecurityError("Archive contains files absent from its manifest")
            for row in rows:
                name = row["rel_path"]
                destination = staging_root / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                digest = hashlib.sha256()
                size = 0
                with archive.open(members[name]) as source, destination.open("xb") as target:
                    while chunk := source.read(1024 * 1024):
                        size += len(chunk)
                        if size > row["size_bytes"]:
                            raise SecurityError(f"Expanded archive size mismatch: {name}")
                        digest.update(chunk)
                        target.write(chunk)
                if size != row["size_bytes"] or digest.hexdigest() != row["sha256"].lower():
                    raise SecurityError(f"File hash or size mismatch for {name}")
            return manifest
    except SecurityError:
        raise
    except (OSError, ValueError, RuntimeError, NotImplementedError, zipfile.BadZipFile) as exc:
        raise SecurityError("Archive could not be read and verified") from exc
