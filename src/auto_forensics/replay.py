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

from .manifest import hash_input_tree
from .pipeline import PipelineConfig, run_case


def replay_manifest(manifest_path: Path, output_dir: Path | None = None) -> dict[str, Any]:
    """Re-execute the run described by ``manifest_path``.

    The replay writes into ``output_dir``, or into a ``replay`` directory
    next to the manifest. It does not overwrite the manifest it read.
    """
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    recorded_inputs = {
        str(item["path"]): str(item["sha256"]).lower()
        for item in manifest.get("input_files", [])
        if isinstance(item, dict)
    }
    input_dir_raw = manifest.get("input_dir")
    input_dir = Path(str(input_dir_raw)) if input_dir_raw else None
    input_match = False
    input_differences: list[str] = []
    if input_dir is None or not input_dir.is_dir():
        input_differences.append("input directory from the manifest is missing")
    else:
        current = {item["path"]: item["sha256"] for item in hash_input_tree(input_dir)}
        input_match = current == recorded_inputs
        for path in sorted(set(current) | set(recorded_inputs)):
            if current.get(path) != recorded_inputs.get(path):
                input_differences.append(path)

    model = manifest.get("model") if isinstance(manifest.get("model"), dict) else {}
    expected_sha = str(manifest.get("output", {}).get("sha256") or "")
    destination = output_dir or (manifest_path.parent / "replay")
    output_match = False
    prompt_match = False
    seed_match = False
    actual_sha = ""
    if input_dir is not None and input_dir.is_dir():
        report = run_case(config_from_manifest(manifest, input_dir, destination))
        del report
        replayed = json.loads((destination / "run_manifest.json").read_text(encoding="utf-8"))
        actual_sha = str(replayed.get("output", {}).get("sha256") or "")
        output_match = bool(actual_sha) and actual_sha == expected_sha
        prompt_match = replayed.get("model", {}).get("prompt_template_sha256") == model.get("prompt_template_sha256")
        seed_match = replayed.get("model", {}).get("seed") == model.get("seed")
    match = input_match and output_match and prompt_match and seed_match
    return {
        "match": match,
        "input_match": input_match,
        "output_match": output_match,
        "prompt_match": prompt_match,
        "seed_match": seed_match,
        "expected_sha256": expected_sha,
        "actual_sha256": actual_sha,
        "input_differences": input_differences,
        "replay_output_dir": str(destination),
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
        seed=int(seed) if isinstance(seed, int) else 0,
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
