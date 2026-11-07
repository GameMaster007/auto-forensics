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
import re
from pathlib import Path
from typing import Any

from .file_ops import atomic_write_text
from .security import SecurityError, bounded_tree_paths, read_limited_text, sha256_file, stays_in_tree
from .version import __version__

_DIGEST = re.compile(r"^[0-9a-fA-F]{64}$")
MAX_REPORT_BYTES = 64 * 1024 * 1024
REPORT_ARTIFACT_NAMES = (
    "attack_navigator_layer.json", "case_report.html", "case_report.json",
    "case_report.md", "case_report.pdf", "case_stix_bundle.json",
)


def read_run_manifest(path: Path) -> dict[str, Any]:
    """Load a bounded, structurally valid manifest before executing a replay."""
    path = path.parent.resolve() / path.name
    if not stays_in_tree(path, path.parent):
        raise SecurityError("Run manifest must be a regular file without a symlink")
    try:
        manifest = json.loads(read_limited_text(path, 16 * 1024 * 1024))
    except (OSError, ValueError) as exc:
        raise SecurityError("Run manifest could not be read as bounded JSON") from exc
    if not isinstance(manifest, dict) or type(manifest.get("manifest_version")) is not int:
        raise SecurityError("Run manifest must be an object with a manifest_version")
    if manifest["manifest_version"] not in {1, 2}:
        raise SecurityError("Unsupported run manifest version")
    if not isinstance(manifest.get("case_id"), str) or not manifest["case_id"]:
        raise SecurityError("Run manifest is missing its case identifier")
    if not isinstance(manifest.get("input_dir"), str) or not manifest["input_dir"] or "\x00" in manifest["input_dir"]:
        raise SecurityError("Run manifest is missing its evidence directory")
    validate_file_inventory(manifest.get("input_files"))
    if "artifacts" in manifest:
        validate_file_inventory(manifest["artifacts"])
    if "analyst_reviews" in manifest:
        reviews = manifest["analyst_reviews"]
        if not isinstance(reviews, dict) or reviews.get("log") != "analyst_reviews.jsonl" or (
            type(reviews.get("entries")) is not int or reviews["entries"] < 0
        ):
            raise SecurityError("Run manifest has invalid analyst review metadata")
        if "sha256" in reviews and (
            not valid_digest(reviews["sha256"]) or type(reviews.get("size_bytes")) is not int or reviews["size_bytes"] < 0
        ):
            raise SecurityError("Run manifest has an invalid analyst review digest")
    output = manifest.get("output")
    if not isinstance(output, dict) or output.get("report") != "case_report.json" or not valid_digest(output.get("sha256")):
        raise SecurityError("Run manifest has an invalid report path or hash")
    model = manifest.get("model")
    if not isinstance(model, dict) or not isinstance(model.get("provider"), str) or model["provider"] not in {
        "off", "mock", "ollama", "openai_compatible"
    }:
        raise SecurityError("Run manifest has an invalid model provider")
    if type(model.get("seed")) is not int or not valid_digest(model.get("prompt_template_sha256")):
        raise SecurityError("Run manifest has an invalid seed or prompt hash")
    if model.get("endpoint") is not None and not isinstance(model["endpoint"], str):
        raise SecurityError("Run manifest has an invalid model endpoint")
    for field in ("paths", "limits"):
        if not isinstance(manifest.get(field, {}), dict):
            raise SecurityError(f"Run manifest has an invalid {field} section")
    for key, value in manifest.get("paths", {}).items():
        if key not in {"rules_dir", "sigma_rules_dir", "attack_stix_path"} or (
            value is not None and (not isinstance(value, str) or not value or "\x00" in value)
        ):
            raise SecurityError("Run manifest has an invalid analysis resource path")
    if manifest["manifest_version"] == 2 or "config" in manifest:
        config = manifest.get("config")
        if not isinstance(config, dict) or type(config.get("max_text_bytes")) is not int or config["max_text_bytes"] < 1:
            raise SecurityError("Run manifest has an invalid text byte limit")
    if manifest["manifest_version"] == 2:
        resources = manifest.get("resources")
        if not isinstance(resources, list):
            raise SecurityError("Run manifest has an invalid resource inventory")
        seen: set[tuple[str, str]] = set()
        for resource in resources:
            if not isinstance(resource, dict) or not isinstance(resource.get("kind"), str) or resource["kind"] not in {
                "rules_dir", "sigma_rules_dir", "attack_stix_path"
            }:
                raise SecurityError("Run manifest has an invalid resource kind")
            validate_file_inventory([resource])
            identity = (resource["kind"], resource["path"])
            if identity in seen:
                raise SecurityError("Run manifest has duplicate resource entries")
            seen.add(identity)
    return manifest


def hash_output_files(output_dir: Path) -> list[dict[str, Any]]:
    return [
        {"path": name, "sha256": sha256_file(output_dir / name), "size_bytes": (output_dir / name).stat().st_size}
        for name in REPORT_ARTIFACT_NAMES if stays_in_tree(output_dir / name, output_dir)
    ]


def valid_digest(value: object) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


def safe_relative_path(value: object) -> bool:
    if not isinstance(value, str) or not value or "\x00" in value:
        return False
    path = Path(value)
    return not path.is_absolute() and path.parts != () and ".." not in path.parts and str(path) == value


def validate_file_inventory(rows: object) -> None:
    if not isinstance(rows, list) or len(rows) > 10_000:
        raise SecurityError("Run manifest has an invalid file inventory")
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or not safe_relative_path(row.get("path")) or not valid_digest(row.get("sha256")):
            raise SecurityError("Run manifest has an invalid file path or hash")
        if type(row.get("size_bytes")) is not int or row["size_bytes"] < 0:
            raise SecurityError("Run manifest has an invalid file size")
        if row["path"] in seen:
            raise SecurityError("Run manifest has duplicate input paths")
        seen.add(row["path"])


def hash_input_tree(input_dir: Path, max_files: int = 10_000) -> list[dict[str, Any]]:
    """Hash regular files under ``input_dir``.

    Symlinks are skipped. Exceeding the file or depth cap is an error:
    a partial inventory must never be presented as a complete manifest.
    """
    rows: list[dict[str, Any]] = []
    root = input_dir.resolve()
    if not root.is_dir():
        raise SecurityError(f"Evidence directory does not exist: {input_dir}")
    if type(max_files) is not int or max_files < 1:
        raise SecurityError("The manifest file limit must be a positive integer")
    for path in bounded_tree_paths(root):
        if not stays_in_tree(path, root):
            continue
        if len(rows) >= max_files:
            raise SecurityError(f"Evidence exceeds the manifest file limit ({max_files})")
        before = path.stat()
        digest = sha256_file(path).lower()
        after = path.stat()
        if not stays_in_tree(path, root) or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
        ):
            raise SecurityError(f"Evidence changed while hashing: {path.relative_to(root)}")
        rows.append(
            {
                "path": str(path.relative_to(root)),
                "sha256": digest,
                "size_bytes": after.st_size,
            }
        )
    return sorted(rows, key=lambda row: row["path"])


def hash_analysis_resources(paths: dict[str, Path | None]) -> list[dict[str, Any]]:
    """Record rule and ATT&CK inputs as well as the case evidence."""
    resources: list[dict[str, Any]] = []
    for kind, path in sorted(paths.items()):
        if path is None:
            continue
        root = path.resolve()
        # AppConfig supplies a default STIX path even on a fresh offline
        # install. Absence means no resource was used; later appearance
        # or disappearance changes this inventory and prevents replay.
        if not root.exists():
            continue
        if root.is_dir() and kind != "attack_stix_path":
            rows = hash_input_tree(root)
            resources.extend({"kind": kind, **row} for row in rows)
        elif root.is_file() and kind == "attack_stix_path":
            resources.append({
                "kind": kind, "path": root.name,
                "sha256": sha256_file(root), "size_bytes": root.stat().st_size,
            })
        else:
            raise SecurityError(f"Configured analysis resource is missing or invalid: {kind}")
    return resources


def prompt_template_sha256(template_text: str) -> str:
    """Hash the fixed instruction text, not the evidence payload."""
    return hashlib.sha256(template_text.encode("utf-8")).hexdigest()


def canonical_report_sha256(report: dict[str, Any]) -> str:
    """Hash the report with the clock field removed.

    ``generated_at`` is the time the file was written. It is kept in
    the file the analyst opens and omitted from this hash.
    """
    body = {key: value for key, value in report.items() if key != "generated_at"}
    try:
        payload = json.dumps(body, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n"
    except (ValueError, TypeError) as exc:
        raise SecurityError("Report contains values that cannot be represented as finite JSON") from exc
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def serialize_report(report: dict[str, Any]) -> str:
    """Publish only finite JSON that subsequent verification can read."""
    try:
        payload = json.dumps(report, indent=2, allow_nan=False)
    except (ValueError, TypeError) as exc:
        raise SecurityError("Report contains values that cannot be represented as finite JSON") from exc
    if len(payload.encode("utf-8")) > MAX_REPORT_BYTES:
        raise SecurityError("Report exceeds the supported JSON size limit (64 MiB)")
    return payload


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
    rules_dir: str | None = None,
    sigma_rules_dir: str | None = None,
    attack_stix_path: str | None = None,
    resources: list[dict[str, Any]] | None = None,
    max_text_bytes: int = 4 * 1024 * 1024,
) -> dict[str, Any]:
    """Build the manifest dict. ``report_sha256`` is the canonical hash."""
    live_model = provider in {"ollama", "openai_compatible"}
    return {
        "manifest_version": 2,
        "case_id": case_id,
        "tool_version": __version__,
        "started_at": started_at,
        "finished_at": finished_at,
        "input_dir": input_dir,
        "input_files": input_files,
        "paths": {
            "rules_dir": rules_dir,
            "sigma_rules_dir": sigma_rules_dir,
            "attack_stix_path": attack_stix_path,
        },
        "resources": resources or [],
        "config": {"max_text_bytes": max_text_bytes},
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
    atomic_write_text(path, json.dumps(manifest, indent=2, allow_nan=False) + "\n")
