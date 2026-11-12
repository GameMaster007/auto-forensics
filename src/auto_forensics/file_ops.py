"""Small filesystem operations used to publish complete local results."""

from __future__ import annotations

import os
import socket
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .security import SecurityError


@contextmanager
def directory_lock(directory: Path) -> Iterator[None]:
    """Exclude cooperating writers, including writers in another process.

    A stale lock is reported instead of being silently stolen. The lock
    is adjacent to the directory so it is not itself evidence or output.
    """
    target = directory.resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    path = target.parent / f".af-{target.name}.lock"
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise SecurityError(f"Directory is busy or has a stale lock: {directory}") from exc
    owned = os.fstat(descriptor)
    try:
        # Who holds the lock, so a tool can tell a live holder from one that died (see the review page's remove).
        host = socket.gethostname().encode("ascii", errors="replace")[:255].replace(b"\n", b"?")
        os.write(descriptor, f"pid={os.getpid()}\n".encode("ascii") + b"host=" + host + b"\n")
        yield
    finally:
        os.close(descriptor)
        try:
            current = path.lstat()
            if (current.st_dev, current.st_ino) == (owned.st_dev, owned.st_ino):
                path.unlink()
        except FileNotFoundError:
            pass


def atomic_write_text(path: Path, content: str) -> None:
    """Replace a text file without exposing a partially written version."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n", dir=path.parent, delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def publish_directory_files(staging: Path, destination: Path, *, obsolete: tuple[str, ...] = ()) -> None:
    """Replace staged files individually, publishing the manifest last.

    The caller holds the output lock. An interrupted multi-file publish
    can be detected by the prior manifest's hashes; no partial file is
    exposed as a complete new file.
    """
    files = sorted(staging.iterdir(), key=lambda path: (path.name == "run_manifest.json", path.name))
    for path in files:
        if not path.is_file() or path.is_symlink() or (destination / path.name).is_dir():
            raise SecurityError("Report publication has an invalid file destination")
    names = {path.name for path in files}
    stale = [destination / name for name in obsolete if name not in names]
    if any(path.is_dir() for path in stale):
        raise SecurityError("Report publication has an invalid obsolete file destination")
    destination.mkdir(parents=True, exist_ok=True)
    for path in files:
        if path.name == "run_manifest.json":
            for old in stale:
                old.unlink(missing_ok=True)
        os.replace(path, destination / path.name)
