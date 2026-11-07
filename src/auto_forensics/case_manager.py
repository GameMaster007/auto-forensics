from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .security import (
    SecurityError,
    SecurityPolicy,
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
        source_dir = source_dir.resolve()
        if not source_dir.exists() or not source_dir.is_dir():
            raise SecurityError(f"Source directory does not exist: {source_dir}")

        evidence_dir = self.evidence_dir(case_id)
        evidence_dir.mkdir(parents=True, exist_ok=True)

        if self.cases_dir.resolve().is_relative_to(source_dir) or source_dir.is_relative_to(self.case_root(case_id)):
            raise SecurityError("Ingest source must not overlap the case storage tree")
        sources: list[tuple[Path, Path, int, str]] = []
        for src in sorted(source_dir.rglob("*")):
            if not src.is_file():
                continue
            if not self.policy.follow_symlinks and not stays_in_tree(src, source_dir):
                continue
            if not src.resolve().is_relative_to(source_dir):
                raise SecurityError("Ingest source symlink escapes the source directory")
            if not is_supported_artifact(src):
                continue
            size_bytes = src.stat().st_size
            if size_bytes > self.policy.max_file_size_bytes:
                continue

            rel_path = src.relative_to(source_dir)
            confine_without_symlinks(evidence_dir, evidence_dir / rel_path)
            sources.append((src, rel_path, size_bytes, sha256_file(src)))
            if len(sources) > min(self.policy.max_total_files, 10_000):
                raise SecurityError("Maximum file count exceeded during ingestion")

        existing: dict[str, ArtifactIndexEntry] = {}
        for path in sorted(evidence_dir.rglob("*")):
            if path.is_symlink():
                raise SecurityError("Existing case evidence contains a symlink")
            if not stays_in_tree(path, evidence_dir):
                continue
            relative = str(path.relative_to(evidence_dir))
            existing[relative] = ArtifactIndexEntry(
                relative, path.suffix.lower().lstrip("."), path.stat().st_size,
                sha256_file(path), {"source_path": str(path)},
            )
        for _src, relative, size, digest in sources:
            prior = existing.get(str(relative))
            if prior is not None and (prior.sha256 != digest or prior.size_bytes != size):
                raise SecurityError(f"Ingest would overwrite existing evidence: {relative}")
        if len(set(existing) | {str(relative) for _, relative, _, _ in sources}) > min(self.policy.max_total_files, 10_000):
            raise SecurityError("Maximum case file count exceeded during ingestion")

        added: list[Path] = []
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
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    # A hard link publishes a complete staged file and refuses
                    # to replace anything created since preflight.
                    os.link(stage / relative, destination)
                    added.append(destination)
                    existing[key] = ArtifactIndexEntry(
                        key, src.suffix.lower().lstrip("."), size, digest, {"source_path": str(src)},
                    )
            except Exception:
                for path in reversed(added):
                    path.unlink(missing_ok=True)
                raise
        return [existing[key] for key in sorted(existing)]
