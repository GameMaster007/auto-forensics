from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

CASE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$")


class SecurityError(ValueError):
    pass


@dataclass(slots=True)
class SecurityPolicy:
    max_file_size_bytes: int = 100 * 1024 * 1024
    max_total_files: int = 200_000
    max_text_bytes: int = 4 * 1024 * 1024
    follow_symlinks: bool = False


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


def is_supported_artifact(path: Path) -> bool:
    suffix = path.suffix.lower()
    basename = path.name.upper()
    if basename in {"SOFTWARE", "SYSTEM", "SAM", "SECURITY", "NTUSER.DAT", "USRCLASS.DAT", "$MFT"}:
        return True
    return suffix in {
        ".json",
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
    """Return True when ``path`` is a regular file that resolves inside ``root``.

    ``rglob`` follows a directory symlink, so a file can look like it
    sits under ``root`` while its real path does not. Those files are
    outside the case and are not evidence for this run.
    """
    if not path.is_file() or path.is_symlink():
        return False
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


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
