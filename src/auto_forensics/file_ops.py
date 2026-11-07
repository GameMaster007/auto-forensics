"""Small filesystem operations used to publish complete local results."""

from __future__ import annotations

import os
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
        os.write(descriptor, f"pid={os.getpid()}\n".encode("ascii"))
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
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
