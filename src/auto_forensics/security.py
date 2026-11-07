from __future__ import annotations

import hashlib
import math
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

CASE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$")
_JSON_SURROGATE_PATTERN = re.compile(r"[\ud800-\udfff]")


class SecurityError(ValueError):
    pass


def validate_json_nesting(value: Any, *, max_depth: int = 128) -> None:
    """Bound JSON depth and reject nonfinite or non-JSON values iteratively."""
    stack = [iter((value,))]
    while stack:
        try:
            item = next(stack[-1])
        except StopIteration:
            stack.pop()
            continue
        if isinstance(item, (dict, list, tuple)):
            if len(stack) > max_depth:
                raise SecurityError(f"JSON nesting exceeds the maximum depth ({max_depth})")
            if isinstance(item, dict) and any(not isinstance(key, str) for key in item):
                raise SecurityError("JSON object keys must be strings")
            if isinstance(item, dict) and any(_JSON_SURROGATE_PATTERN.search(key) for key in item):
                raise SecurityError("JSON object keys contain invalid Unicode surrogates")
            stack.append(iter(item.values() if isinstance(item, dict) else item))
        elif isinstance(item, float) and not math.isfinite(item):
            raise SecurityError("JSON contains a nonfinite number")
        elif isinstance(item, str) and _JSON_SURROGATE_PATTERN.search(item):
            raise SecurityError("JSON text contains invalid Unicode surrogates")
        elif item is not None and not isinstance(item, (str, int, float, bool)):
            raise SecurityError("Value cannot be represented as JSON")


@dataclass(slots=True)
class SecurityPolicy:
    max_file_size_bytes: int = 100 * 1024 * 1024
    max_total_files: int = 200_000
    max_text_bytes: int = 4 * 1024 * 1024
    follow_symlinks: bool = False
    max_archive_size_bytes: int = 1024 * 1024 * 1024


def bounded_tree_paths(root: Path, *, max_entries: int = 50_000, max_depth: int = 20) -> Iterator[Path]:
    """Walk without following directory links or materializing an unbounded tree.

    Yield links and special entries too, so callers can explicitly skip or
    reject them. Permission/read errors propagate instead of hiding files.
    """
    root = root.resolve()
    if not root.is_dir():
        raise SecurityError(f"Evidence directory does not exist: {root}")
    if type(max_entries) is not int or max_entries < 1 or type(max_depth) is not int or max_depth < 1:
        raise SecurityError("Traversal limits must be positive integers")
    pending = [root]
    visited = 0
    while pending:
        directory = pending.pop()
        confine_without_symlinks(root, directory)
        with os.scandir(directory) as entries:
            for entry in entries:
                visited += 1
                if visited > max_entries:
                    raise SecurityError(f"Evidence exceeds the traversal entry limit ({max_entries})")
                path = Path(entry.path)
                if len(path.relative_to(root).parts) > max_depth:
                    raise SecurityError(f"Evidence exceeds the maximum directory depth ({max_depth})")
                yield path
                if entry.is_dir(follow_symlinks=False):
                    pending.append(path)


def validate_case_id(case_id: str) -> str:
    if not CASE_ID_PATTERN.fullmatch(case_id):
        raise SecurityError(
            "Invalid case_id. Use 2-64 characters: letters, numbers, dot, underscore, hyphen."
        )
    return case_id


def confine_path(root: Path, candidate: Path) -> Path:
    root_resolved = root.resolve()
    candidate_resolved = candidate.resolve()
    try:
        candidate_resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise SecurityError(f"Path escapes allowed root: {candidate}") from exc
    return candidate_resolved


def confine_without_symlinks(root: Path, candidate: Path) -> Path:
    """Confine a possibly new destination before creating or copying it."""
    resolved_root = root.resolve()
    absolute = candidate.absolute()
    try:
        relative = absolute.relative_to(resolved_root)
    except ValueError as exc:
        raise SecurityError(f"Path escapes allowed root: {candidate}") from exc
    if ".." in relative.parts:
        raise SecurityError(f"Path escapes allowed root: {candidate}")
    component = resolved_root
    for part in relative.parts:
        component /= part
        if component.is_symlink():
            raise SecurityError(f"Path uses a symlink: {candidate}")
    confine_path(resolved_root, absolute)
    return absolute


def is_supported_artifact(path: Path) -> bool:
    suffix = path.suffix.lower()
    basename = path.name.upper()
    if basename in {"SOFTWARE", "SYSTEM", "SAM", "SECURITY", "NTUSER.DAT", "USRCLASS.DAT", "$MFT"}:
        return True
    return suffix in {
        ".json",
        ".jsonl",
        ".csv",
        ".txt",
        ".log",
        ".evtx",
        ".pcap",
        ".pcapng",
        ".pf",
        ".mft",
        ".hiv",
        ".hive",
        ".raw",
        ".dmp",
        ".mem",
        ".exe",
        ".dll",
        ".sys",
        ".bin",
    }


def stays_in_tree(path: Path, root: Path) -> bool:
    """Accept regular files below the root without following any symlink.

    Check every component before resolving it, including directory links
    whose targets happen to be inside the evidence tree.
    """
    try:
        resolved_root = root.resolve()
        candidate = path.absolute()
        relative = candidate.relative_to(resolved_root)
        if ".." in relative.parts:
            return False
        component = resolved_root
        for part in relative.parts:
            component /= part
            if component.is_symlink():
                return False
        return candidate.is_file() and candidate.resolve().is_relative_to(resolved_root)
    except (OSError, ValueError, RuntimeError):
        return False


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def read_limited_text(path: Path, max_bytes: int) -> str:
    with path.open("rb") as f:
        data = f.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise SecurityError(f"File exceeds maximum text size: {path}")
    return data.decode("utf-8", errors="replace")


def capture_regular_evidence(
    path: Path, root: Path, *, destination: Path | None = None,
    max_bytes: int | None = None, start: int = 0, window_bytes: int = 0,
) -> tuple[str, bytes]:
    """Hash and capture the same source bytes in one bounded, regular-file pass.

    A binary citation retains just its window in memory. Record parsers get a
    private file snapshot. Read only the initial file length, so an appending
    writer cannot turn verification into an unbounded stream.
    """
    descriptor = None
    try:
        root = root.resolve()
        confine_without_symlinks(root, path)
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0))
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise SecurityError("Cited evidence must be a regular file")
        if max_bytes is not None and before.st_size > max_bytes:
            raise SecurityError("Cited evidence exceeds its verification size limit")
        digest = hashlib.sha256()
        window = bytearray()
        offset = 0
        remaining = before.st_size
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            output = destination.open("xb") if destination is not None else None
            try:
                while remaining:
                    chunk = source.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise SecurityError("Cited evidence changed during capture")
                    digest.update(chunk)
                    if output is not None:
                        output.write(chunk)
                    left, right = max(start, offset), min(start + window_bytes, offset + len(chunk))
                    if right > left:
                        window.extend(chunk[left - offset:right - offset])
                    offset += len(chunk)
                    remaining -= len(chunk)
                if source.read(1):
                    raise SecurityError("Cited evidence changed during capture")
            finally:
                if output is not None:
                    output.close()
        confine_without_symlinks(root, path)
        after = os.fstat(descriptor)
        current = path.stat(follow_symlinks=False)
        if (before.st_size, before.st_mtime_ns, before.st_dev, before.st_ino) != (
            after.st_size, after.st_mtime_ns, current.st_dev, current.st_ino
        ):
            raise SecurityError("Cited evidence changed during capture")
        return digest.hexdigest(), bytes(window)
    except OSError as exc:
        raise SecurityError("Cited evidence could not be captured as a regular file") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def read_regular_text(path: Path, root: Path, max_bytes: int) -> str:
    """Read one unchanged regular UTF-8 file without following symlinks."""
    root = root.absolute()
    def guard() -> None:
        if any(parent.is_symlink() for parent in (root, *root.parents)) or not stays_in_tree(path, root):
            raise SecurityError("Published report must be a regular file inside its output directory without symlinks")
    try:
        guard()
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise SecurityError("Published report must be a regular file")
            if before.st_size > max_bytes:
                raise SecurityError("Published report exceeds its text size limit")
            guard()
            current = path.stat(follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
                raise SecurityError("Published report changed before reading")
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                data = handle.read(max_bytes + 1)
            guard()
            after = os.fstat(descriptor)
            current = path.stat(follow_symlinks=False)
            if (before.st_size, before.st_mtime_ns, before.st_dev, before.st_ino) != (
                after.st_size, after.st_mtime_ns, current.st_dev, current.st_ino
            ):
                raise SecurityError("Published report changed while reading")
        finally:
            os.close(descriptor)
        if len(data) > max_bytes:
            raise SecurityError("Published report exceeds its text size limit")
        return data.decode("utf-8")
    except (OSError, UnicodeError) as exc:
        raise SecurityError("Published report could not be read as bounded regular UTF-8 text") from exc
