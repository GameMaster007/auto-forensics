"""Safe extraction of evidence ZIP archives into the run folder.

The archive in the evidence folder is never changed. Its members are
copied into ``<run>/archives/<name>-<hash8>/`` after every check passes,
and each extracted file is hashed and recorded in ``archives.json``.
Findings about a member cite it as ``<archive path>!<member path>``.

Refused: absolute paths, ``..``, drive letters, control characters,
names that collide when case is ignored, symlinks and special files,
encrypted entries, more than ``MAX_MEMBERS`` files, a member over
``MAX_MEMBER_BYTES``, more than ``MAX_TOTAL_BYTES`` in total, and any
member that expands more than ``MAX_RATIO`` times (zip bombs). Nested
archives are listed but not opened.
"""

from __future__ import annotations

import hashlib
import stat
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath

from auto_forensics.security import SecurityError

MAX_MEMBERS = 10_000
MAX_MEMBER_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_RATIO = 200
MAX_DEPTH = 20
SEPARATOR = "!"


@dataclass(slots=True)
class Member:
    archive: str
    archive_sha256: str
    member: str
    extracted: str
    sha256: str
    size_bytes: int

    @property
    def cited_as(self) -> str:
        return f"{self.archive}{SEPARATOR}{self.member}"

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["cited_as"] = self.cited_as
        return data


def safe_member_name(name: str) -> str:
    if not name or "\x00" in name or "\\" in name:
        raise SecurityError("Archive member has an invalid name")
    path = PurePosixPath(name)
    if path.is_absolute() or PureWindowsPath(name).drive or ".." in path.parts:
        raise SecurityError("Archive member escapes the extraction folder")
    if len(path.parts) > MAX_DEPTH:
        raise SecurityError("Archive member is nested too deeply")
    for part in path.parts:
        if any(ord(ch) < 32 for ch in part) or part in {".", ""} or SEPARATOR in part:
            raise SecurityError("Archive member has a control character or reserved name")
    return path.as_posix()


def extract_zip(archive_path: Path, archive_rel: str, archive_sha256: str, destination: Path) -> list[Member]:
    """Check every member first, then extract. Raises SecurityError and writes nothing on refusal."""
    try:
        with zipfile.ZipFile(archive_path) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_MEMBERS:
                raise SecurityError("Archive has too many members")
            plan: list[tuple[zipfile.ZipInfo, str]] = []
            seen: set[str] = set()
            total = 0
            for info in infos:
                if info.is_dir():
                    continue
                name = safe_member_name(info.filename)
                key = name.casefold()
                if key in seen:
                    raise SecurityError("Archive has members whose names differ only by case")
                seen.add(key)
                mode = stat.S_IFMT(info.external_attr >> 16)
                if mode not in {0, stat.S_IFREG} or info.flag_bits & 0x1:
                    raise SecurityError("Archive has a symlink, special, or encrypted member")
                if info.file_size > MAX_MEMBER_BYTES:
                    raise SecurityError("Archive member is too large")
                if info.file_size > 1024 * 1024 and info.file_size > MAX_RATIO * max(info.compress_size, 1):
                    raise SecurityError("Archive member expands suspiciously (possible zip bomb)")
                total += info.file_size
                if total > MAX_TOTAL_BYTES:
                    raise SecurityError("Archive expands beyond the total size limit")
                plan.append((info, name))
            destination.mkdir(parents=True, exist_ok=False)
            members: list[Member] = []
            for info, name in plan:
                target = destination / name
                target.parent.mkdir(parents=True, exist_ok=True)
                digest = hashlib.sha256()
                written = 0
                with archive.open(info) as source, target.open("xb") as sink:
                    while chunk := source.read(1024 * 1024):
                        written += len(chunk)
                        if written > info.file_size:
                            raise SecurityError("Archive member is larger than its header says")
                        digest.update(chunk)
                        sink.write(chunk)
                members.append(Member(archive_rel, archive_sha256, name, target.relative_to(destination).as_posix(),
                                      digest.hexdigest(), written))
            return members
    except SecurityError:
        raise
    except (OSError, ValueError, RuntimeError, NotImplementedError, zipfile.BadZipFile, EOFError) as exc:
        raise SecurityError(f"Archive could not be read: {type(exc).__name__}") from exc
