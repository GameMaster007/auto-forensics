"""Run manifest.

The manifest is the record required to repeat a triage run: which
files went in, which tool version, prompt template, and seed were
used, and the canonical hash of the report that came out.

``output.sha256`` is not the raw bytes of ``case_report.json``.
``generated_at`` is removed before hashing so two runs of the same
input share a hash. Temperature is 0 only when a live model endpoint
is called. The offline mock does not sample, so its temperature is
null. ``seed`` is 0 for every provider; live calls send that seed
when the API accepts one.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .security import sha256_file, stays_in_tree
from .version import __version__


def hash_input_tree(input_dir: Path, max_files: int = 10_000) -> list[dict[str, Any]]:
    """Hash regular files under ``input_dir``.

    Symlinks are skipped. The walk stops after ``max_files`` so a huge
    or cyclic tree cannot fill the manifest.
    """
    rows: list[dict[str, Any]] = []
    root = input_dir.resolve()
    for path in sorted(root.rglob("*")):
        if not stays_in_tree(path, root):
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


def canonical_report_sha256(report: dict[str, Any]) -> str:
    """Hash the report with the clock field removed.

    ``generated_at`` is the time the file was written. It is kept in
    the file the analyst opens and omitted from this hash.
    """
    body = {key: value for key, value in report.items() if key != "generated_at"}
    payload = json.dumps(body, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def build_run_manifest(
    *,
    case_id: str,
    started_at: str,
    finished_at: str,
    input_dir: str,
    input_files: list[dict[str, Any]],
    provider: str,
    model_name: str,
    endpoint: str | None,
    seed: int,
    prompt_sent: bool,
    prompt_template_sha256_value: str,
    finding_count: int,
    dropped_uncited: int,
    dropped_unsupported: int,
    report_name: str,
    report_sha256: str,
    workers: list[str],
    tool_calls: list[dict[str, Any]],
    verifier: str,
    verification: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build the manifest dict. ``report_sha256`` is the canonical hash."""
    live_model = provider in {"ollama", "openai_compatible"}
    return {
        "manifest_version": 1,
        "case_id": case_id,
        "tool_version": __version__,
        "started_at": started_at,
        "finished_at": finished_at,
        "input_dir": input_dir,
        "input_files": input_files,
        "model": {
            "provider": provider,
            "name": model_name,
            "endpoint": endpoint if live_model else None,
            "offline": provider in {"mock", "off"},
            "temperature": 0 if live_model else None,
            "seed": seed,
            "prompt_sent": prompt_sent,
            "prompt_template_sha256": prompt_template_sha256_value,
        },
        "workers": workers,
        "tool_calls": tool_calls,
        "finding_count": finding_count,
        "dropped_uncited": dropped_uncited,
        "dropped_unsupported": dropped_unsupported,
        "verification": verification,
        "output": {
            "report": report_name,
            "sha256": report_sha256,
            "sha256_scope": "case_report.json with generated_at removed",
        },
        "limits": {
            "citation_check": "pointer-exists",
            "verifier": verifier,
            "replay": "available",
            "orchestrator": "not-run",
        },
    }


def write_run_manifest(path: Path, manifest: dict[str, Any]) -> None:
    """Write the manifest as UTF-8 JSON."""
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
