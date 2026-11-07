"""Re-run a case from ``run_manifest.json`` and compare hashes.

The command checks the input file hashes, runs the same case id,
provider, model, and seed, and compares the canonical report hash.
Clock fields are not part of that hash. A mismatch is a false result;
the caller exits non-zero.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .file_ops import directory_lock
from .integrity import check_inputs, check_resources, checked_review_snapshot
from .manifest import read_run_manifest, validate_output_resource_paths
from .pipeline import PipelineConfig
from .pipeline import run_case_locked as run_case
from .reviews import ANALYST_REVIEW_LOG, ReviewError
from .reviews import apply_review_log_locked as apply_review_log
from .security import SecurityError
from .version import __version__


def replay_manifest(manifest_path: Path, output_dir: Path | None = None, *, input_dir: Path | None = None) -> dict[str, Any]:
    """Re-execute the run described by ``manifest_path``.

    The replay writes into ``output_dir``, or into a ``replay`` directory
    next to the manifest. It does not overwrite the manifest it read.
    Analyst decisions in ``analyst_reviews.jsonl`` beside that manifest
    are applied again before the report hash is compared.
    """
    manifest_path = manifest_path.parent.resolve() / manifest_path.name
    # A source review must not change between the integrity check, copying its
    # log, and comparing the replay. Destination writers are excluded below.
    read_run_manifest(manifest_path)
    with directory_lock(manifest_path.parent):
        return _replay_manifest_locked(manifest_path, output_dir, input_dir)


def _replay_manifest_locked(manifest_path: Path, output_dir: Path | None, input_dir_override: Path | None) -> dict[str, Any]:
    manifest = read_run_manifest(manifest_path)
    tool_version_match = manifest.get("tool_version") == __version__
    version_error = "" if tool_version_match else "Replay requires the tool version recorded in the manifest; no analysis was executed"
    input_dir = input_dir_override.expanduser().resolve() if input_dir_override is not None else Path(manifest["input_dir"])
    input_match, input_changes, input_error = check_inputs(manifest, input_dir)
    input_differences = sorted(path for paths in input_changes.values() for path in paths)
    if input_error:
        input_differences.append(input_error)
    resources_match, resource_error = check_resources(manifest)
    reviews_match, review_error, review_entries, review_content = checked_review_snapshot(manifest, manifest_path.parent)

    model = manifest.get("model") if isinstance(manifest.get("model"), dict) else {}
    expected_sha = str(manifest.get("output", {}).get("sha256") or "")
    destination = output_dir or (manifest_path.parent / "replay")
    if output_dir is None:
        sequence = 2
        while destination.exists():
            destination = manifest_path.parent / f"replay-{sequence}"
            sequence += 1
    if destination.resolve() == manifest_path.parent.resolve():
        raise SecurityError("Replay output must not overwrite the original run directory")
    if destination.resolve().is_relative_to(input_dir.resolve()):
        raise SecurityError("Replay output must be outside the evidence directory")
    validate_output_resource_paths(destination, {
        kind: Path(value) if value else None for kind, value in manifest.get("paths", {}).items()
    })
    output_match = False
    prompt_match = False
    seed_match = False
    actual_sha = ""
    executed = False
    if input_match and resources_match and reviews_match and tool_version_match:
        with directory_lock(destination):
            executed = True
            report = run_case(config_from_manifest(manifest, input_dir, destination))
            del report
            try:
                if "analyst_reviews" in manifest and not apply_review_log(destination, manifest_path.parent / ANALYST_REVIEW_LOG, snapshot=(review_entries, review_content)):
                    review_error = "Review log names a finding missing from the replay"
            except ReviewError as exc:
                review_error = str(exc)
            replayed = json.loads((destination / "run_manifest.json").read_text(encoding="utf-8"))
            actual_sha = str(replayed.get("output", {}).get("sha256") or "")
            output_match = bool(actual_sha) and actual_sha == expected_sha
            prompt_match = replayed.get("model", {}).get("prompt_template_sha256") == model.get("prompt_template_sha256")
            seed_match = replayed.get("model", {}).get("seed") == model.get("seed")
    match = input_match and resources_match and output_match and prompt_match and seed_match and tool_version_match and not review_error
    return {
        "match": match,
        "input_match": input_match,
        "output_match": output_match,
        "prompt_match": prompt_match,
        "seed_match": seed_match,
        "resources_match": resources_match,
        "reviews_match": reviews_match,
        "resource_error": resource_error,
        "executed": executed,
        "expected_sha256": expected_sha,
        "actual_sha256": actual_sha,
        "input_differences": input_differences,
        "replay_output_dir": str(destination),
        "review_error": review_error,
        "tool_version_match": tool_version_match,
        "recorded_tool_version": manifest.get("tool_version"),
        "current_tool_version": __version__,
        "version_error": version_error,
        "recorded_input_dir": manifest["input_dir"],
        "checked_input_dir": str(input_dir.resolve()),
    }


def config_from_manifest(manifest: dict[str, Any], input_dir: Path, output_dir: Path) -> PipelineConfig:
    """Build the pipeline config a manifest can repeat.

    Rule and STIX paths are taken from the manifest. The API key is
    read from the environment only when the manifest endpoint is the
    endpoint already configured there. A manifest cannot redirect that
    key to another host. The key is never stored.
    """
    model = manifest.get("model") if isinstance(manifest.get("model"), dict) else {}
    paths = manifest.get("paths") if isinstance(manifest.get("paths"), dict) else {}
    provider = str(model.get("provider") or "off")
    seed = model.get("seed")
    endpoint = model.get("endpoint")
    llama_endpoint = "http://localhost:11434"
    openai_endpoint = None
    if provider == "ollama" and endpoint:
        llama_endpoint = str(endpoint)
    if provider == "openai_compatible" and endpoint:
        openai_endpoint = str(endpoint)
    configured_endpoint = os.environ.get("AUTO_FORENSICS_OPENAI_ENDPOINT")
    api_key = None
    if (
        provider == "openai_compatible"
        and openai_endpoint
        and configured_endpoint
        and openai_endpoint == configured_endpoint
    ):
        api_key = os.environ.get("AUTO_FORENSICS_OPENAI_API_KEY")
    return PipelineConfig(
        case_id=str(manifest.get("case_id") or "replay"),
        input_dir=input_dir,
        output_dir=output_dir,
        enable_llama=provider != "off",
        llama_endpoint=llama_endpoint,
        llama_model=str(model.get("name") or "llama3.1:8b"),
        rules_dir=_recorded_path(paths.get("rules_dir")),
        sigma_rules_dir=_recorded_path(paths.get("sigma_rules_dir")),
        attack_stix_path=_recorded_path(paths.get("attack_stix_path")),
        openai_compatible_endpoint=openai_endpoint,
        openai_api_key=api_key,
        llm_provider=provider,
        max_text_bytes=manifest.get("config", {}).get("max_text_bytes", 4 * 1024 * 1024),
        seed=int(seed) if isinstance(seed, int) else 0,
        expected_input_files=manifest.get("input_files"),
        verifier_judge=_judge_mode(str(manifest.get("limits", {}).get("verifier") or "")),
    )


def _recorded_path(value: object) -> Path | None:
    if not value:
        return None
    return Path(str(value))


def _judge_mode(verifier_limit: str) -> str:
    if verifier_limit == "rules+mock":
        return "mock"
    if verifier_limit == "rules+llm":
        return "llm"
    return "rules"
