from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from .security import SecurityError, SecurityPolicy, confine_path, is_supported_artifact, sha256_file


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
        return self.cases_dir / case_id

    def evidence_dir(self, case_id: str) -> Path:
        return self.case_root(case_id) / "evidence"

    def output_dir(self, case_id: str) -> Path:
        return self.case_root(case_id) / "output"

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

        file_count = 0
        entries: list[ArtifactIndexEntry] = []
        for src in sorted(source_dir.rglob("*")):
            if not src.is_file():
                continue
            if file_count >= self.policy.max_total_files:
                raise SecurityError("Maximum file count exceeded during ingestion.")
            if (not self.policy.follow_symlinks) and src.is_symlink():
                continue
            if not is_supported_artifact(src):
                continue
            size_bytes = src.stat().st_size
            if size_bytes > self.policy.max_file_size_bytes:
                continue

            rel_path = src.relative_to(source_dir)
            dst = evidence_dir / rel_path
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            confine_path(evidence_dir, dst)

            entries.append(
                ArtifactIndexEntry(
                    rel_path=str(rel_path),
                    artifact_type=src.suffix.lower().lstrip("."),
                    size_bytes=size_bytes,
                    sha256=sha256_file(dst),
                    metadata={"source_path": str(src)},
                )
            )
            file_count += 1
        return entries
