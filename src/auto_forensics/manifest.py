"""Run manifest.

The manifest is the record required to repeat a triage run: which
files went in, which tool version and prompt template were used, and
the hash of the report that came out. Replay itself (re-executing from
the manifest and comparing output) is not implemented yet. This module
only writes the record.

``model.seed`` is always null in this version. Temperature is 0 only
when a live model endpoint is called. The offline mock does not sample,
so its temperature is null as well.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .security import sha256_file
from .version import __version__


def hash_input_tree(input_dir: Path, max_files: int = 10_000) -> list[dict[str, Any]]:
    """Hash regular files under ``input_dir``.

    Symlinks are skipped. The walk stops after ``max_files`` so a huge
    or cyclic tree cannot fill the manifest.
    """
    rows: list[dict[str, Any]] = []
    root = input_dir.resolve()
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        if len(path.relative_to(root).parts) > 20:
            continue
        rows.append(
            {
                "path": str(path.relative_to(root)),
                "sha256": sha256_file(path).lower(),
                "size_bytes": path.stat().st_size,
            }
        )
        if len(rows) >= max_files:
            break
    return rows


def prompt_template_sha256(template_text: str) -> str:
    """Hash the fixed instruction text, not the evidence payload."""
    return hashlib.sha256(template_text.encode("utf-8")).hexdigest()


def build_run_manifest(
    *,
    case_id: str,
    started_at: str,
    finished_at: str,
    input_files: list[dict[str, Any]],
    provider: str,
    model_name: str,
    prompt_sent: bool,
    prompt_template_sha256_value: str,
    finding_count: int,
    dropped_uncited: int,
    report_path: Path,
    workers: list[str],
    tool_calls: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build the manifest dict. ``report_path`` must already exist."""
    live_model = provider in {"ollama", "openai_compatible"}
    return {
        "manifest_version": 1,
        "case_id": case_id,
        "tool_version": __version__,
        "started_at": started_at,
        "finished_at": finished_at,
        "input_files": input_files,
        "model": {
            "provider": provider,
            "name": model_name,
            "offline": provider in {"mock", "off"},
            "temperature": 0 if live_model else None,
            "seed": None,
            "prompt_sent": prompt_sent,
            "prompt_template_sha256": prompt_template_sha256_value,
        },
        "workers": workers,
        "tool_calls": tool_calls,
        "finding_count": finding_count,
        "dropped_uncited": dropped_uncited,
        "output": {
            "report": report_path.name,
            "sha256": sha256_file(report_path).lower(),
        },
        "limits": {
            "citation_check": "pointer-exists",
            "verifier": "not-run",
            "replay": "not-run",
            "orchestrator": "not-run",
        },
    }


def write_run_manifest(path: Path, manifest: dict[str, Any]) -> None:
    """Write the manifest as UTF-8 JSON."""
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
