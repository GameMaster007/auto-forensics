from __future__ import annotations

import errno
import hashlib
import os
import shutil
import stat
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .security import (
    SecurityError,
    SecurityPolicy,
    bounded_tree_paths,
    confine_without_symlinks,
    is_supported_artifact,
    sha256_file,
    stays_in_tree,
    validate_case_id,
)


@dataclass(slots=True)
class ArtifactIndexEntry:
    rel_path: str
    artifact_type: str
    size_bytes: int
    sha256: str
    metadata: dict[str, str]


@dataclass(slots=True)
class IngestResult:
    entries: list[ArtifactIndexEntry]
    skipped_entries: list[dict[str, str]]
    skipped_counts: dict[str, int]
    skipped_entries_truncated: bool
    published_paths: list[Path] = field(default_factory=list)
    created_directories: list[tuple[Path, int, int]] = field(default_factory=list)


class CaseManager:
    def __init__(self, cases_dir: Path, policy: SecurityPolicy):
        self.cases_dir = cases_dir
        self.policy = policy
        self.cases_dir.mkdir(parents=True, exist_ok=True)

    def case_root(self, case_id: str) -> Path:
        root = self.cases_dir.resolve()
        return confine_without_symlinks(root, root / validate_case_id(case_id))

    def evidence_dir(self, case_id: str) -> Path:
        root = self.case_root(case_id)
        return confine_without_symlinks(root, root / "evidence")

    def output_dir(self, case_id: str) -> Path:
        root = self.case_root(case_id)
        return confine_without_symlinks(root, root / "output")

    def init_case_dirs(self, case_id: str) -> tuple[Path, Path]:
        evidence = self.evidence_dir(case_id)
        output = self.output_dir(case_id)
        evidence.mkdir(parents=True, exist_ok=True)
        output.mkdir(parents=True, exist_ok=True)
        return evidence, output

    def ingest_directory(self, case_id: str, source_dir: Path) -> list[ArtifactIndexEntry]:
        return self.ingest_directory_detailed(case_id, source_dir).entries

    def ingest_directory_detailed(self, case_id: str, source_dir: Path) -> IngestResult:
        source_dir = source_dir.resolve()
        if not source_dir.exists() or not source_dir.is_dir():
            raise SecurityError(f"Source directory does not exist: {source_dir}")

        evidence_dir = self.evidence_dir(case_id)
        evidence_dir.mkdir(parents=True, exist_ok=True)

        if self.cases_dir.resolve().is_relative_to(source_dir) or source_dir.is_relative_to(self.case_root(case_id)):
            raise SecurityError("Ingest source must not overlap the case storage tree")
        sources: list[tuple[Path, Path, int, str]] = []
        skipped: list[dict[str, str]] = []
        skipped_counts: dict[str, int] = {}

        def skip(path: Path, reason: str) -> None:
            skipped_counts[reason] = skipped_counts.get(reason, 0) + 1
            if len(skipped) < 1000:
                skipped.append({"path": str(path.relative_to(source_dir)), "reason": reason})

        for src in sorted(bounded_tree_paths(source_dir)):
            if src.is_symlink() and (not self.policy.follow_symlinks or src.is_dir()):
                skip(src, "symlink")
                continue
            if src.is_dir():
                continue
            if not src.is_file():
                skip(src, "special_or_missing_file")
                continue
            if not self.policy.follow_symlinks and not stays_in_tree(src, source_dir):
                skip(src, "unsafe_path")
                continue
            if not src.resolve().is_relative_to(source_dir):
                raise SecurityError("Ingest source symlink escapes the source directory")
            if not is_supported_artifact(src):
                skip(src, "unsupported_artifact")
                continue
            size_bytes = src.stat().st_size
            if size_bytes > self.policy.max_file_size_bytes:
                skip(src, "file_size_limit")
                continue

            rel_path = src.relative_to(source_dir)
            confine_without_symlinks(evidence_dir, evidence_dir / rel_path)
            sources.append((src, rel_path, size_bytes, sha256_file(src)))
            if len(sources) > min(self.policy.max_total_files, 10_000):
                raise SecurityError("Maximum file count exceeded during ingestion")

        existing: dict[str, ArtifactIndexEntry] = {}
        for path in sorted(bounded_tree_paths(evidence_dir)):
            if path.is_symlink():
                raise SecurityError("Existing case evidence contains a symlink")
            if not stays_in_tree(path, evidence_dir):
                if not path.is_dir():
                    raise SecurityError("Existing case evidence contains a special or missing file")
                continue
            relative_text = str(path.relative_to(evidence_dir))
            existing[relative_text] = ArtifactIndexEntry(
                relative_text, path.suffix.lower().lstrip("."), path.stat().st_size,
                sha256_file(path), {"source_path": str(path)},
            )
        for _src, relative, size, digest in sources:
            prior = existing.get(str(relative))
            if prior is not None and (prior.sha256 != digest or prior.size_bytes != size):
                raise SecurityError(f"Ingest would overwrite existing evidence: {relative}")
        if len(set(existing) | {str(relative) for _, relative, _, _ in sources}) > min(self.policy.max_total_files, 10_000):
            raise SecurityError("Maximum case file count exceeded during ingestion")

        added: list[Path] = []
        created_directories: list[tuple[Path, int, int]] = []
        with tempfile.TemporaryDirectory(prefix=".af-ingest-", dir=self.case_root(case_id)) as temporary:
            stage = Path(temporary)
            for src, relative, size, digest in sources:
                staged = stage / relative
                staged.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, staged)
                if staged.stat().st_size != size or sha256_file(staged) != digest:
                    raise SecurityError(f"Source changed during ingestion: {relative}")
            try:
                for src, relative, size, digest in sources:
                    key = str(relative)
                    if key in existing:
                        continue
                    destination = confine_without_symlinks(evidence_dir, evidence_dir / relative)
                    missing_parents: list[Path] = []
                    parent = destination.parent
                    while not parent.exists():
                        missing_parents.append(parent)
                        parent = parent.parent
                    for directory in reversed(missing_parents):
                        directory.mkdir()
                        identity = directory.stat()
                        created_directories.append((directory, identity.st_dev, identity.st_ino))
                    _publish_staged_evidence(stage / relative, destination, size, digest)
                    added.append(destination)
                    existing[key] = ArtifactIndexEntry(
                        key, src.suffix.lower().lstrip("."), size, digest, {"source_path": str(src)},
                    )
            except Exception:
                self.rollback_ingest(case_id, IngestResult(
                    list(existing.values()), skipped, skipped_counts, False, added, created_directories,
                ))
                raise
        return IngestResult(
            [existing[key] for key in sorted(existing)], skipped, skipped_counts,
            sum(skipped_counts.values()) > len(skipped), added, created_directories,
        )

    def rollback_ingest(self, case_id: str, intake: IngestResult) -> None:
        """Remove only unchanged files published by a confirmed failed ingest."""
        evidence = self.evidence_dir(case_id)
        expected = {item.rel_path: item for item in intake.entries}
        removable: list[Path] = []
        for path in intake.published_paths:
            confine_without_symlinks(evidence, path)
            if not path.exists():
                continue
            entry = expected[str(path.relative_to(evidence))]
            if not stays_in_tree(path, evidence) or path.stat().st_size != entry.size_bytes or sha256_file(path) != entry.sha256:
                raise SecurityError("Ingest rollback found changed new evidence; files were preserved for recovery")
            removable.append(path)
        for path in reversed(removable):
            path.unlink()
        for path, device, inode in reversed(intake.created_directories):
            try:
                current = path.lstat()
                if not path.is_symlink() and path.is_dir() and (current.st_dev, current.st_ino) == (device, inode):
                    path.rmdir()
            except FileNotFoundError:
                continue
            except OSError as exc:
                if exc.errno not in {errno.ENOTEMPTY, errno.EEXIST}:
                    raise


def _publish_staged_evidence(staged: Path, destination: Path, size: int, digest: str) -> None:
    """Publish without overwriting, including on filesystems without links.

    The hard-link path exposes a complete file atomically. The exclusive-copy
    fallback is protected from managed readers by the caller's case lock;
    its custody record is committed only after the copy has been verified.
    """
    try:
        os.link(staged, destination)
        return
    except NotImplementedError:
        pass
    except OSError as exc:
        if exc.errno not in {errno.EPERM, errno.EOPNOTSUPP, errno.ENOSYS, errno.EXDEV}:
            raise

    descriptor = os.open(
        destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600,
    )
    owned = os.fstat(descriptor)
    copied = 0
    copied_hash = hashlib.sha256()
    closed = False
    try:
        with staged.open("rb") as source:
            while chunk := source.read(min(1024 * 1024, size - copied + 1)):
                if copied + len(chunk) > size:
                    raise SecurityError("Staged evidence grew during exclusive publication")
                remaining = memoryview(chunk)
                while remaining:
                    count = os.write(descriptor, remaining)
                    if count <= 0:
                        raise OSError(errno.EIO, "Evidence copy made no progress")
                    copied_hash.update(remaining[:count])
                    copied += count
                    remaining = remaining[count:]
        os.fsync(descriptor)
        current = destination.lstat()
        if (
            not stat.S_ISREG(current.st_mode)
            or (current.st_dev, current.st_ino) != (owned.st_dev, owned.st_ino)
            or copied != size or copied_hash.hexdigest() != digest
            or current.st_size != size or sha256_file(destination) != digest
        ):
            raise SecurityError("Staged evidence changed during exclusive publication")
        shutil.copystat(staged, destination)
    except Exception as exc:
        # Windows refuses unlinking an open file, including on FAT volumes.
        os.close(descriptor)
        closed = True
        try:
            current = destination.lstat()
        except FileNotFoundError:
            raise exc
        if (
            stat.S_ISREG(current.st_mode)
            and (current.st_dev, current.st_ino) == (owned.st_dev, owned.st_ino)
            and current.st_size == copied
            and sha256_file(destination) == copied_hash.hexdigest()
        ):
            destination.unlink()
        else:
            raise SecurityError("Failed evidence copy changed; files were preserved for recovery") from exc
        raise
    finally:
        if not closed:
            os.close(descriptor)
