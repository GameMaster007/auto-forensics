"""Read-only checks of a published run; no model or detector is executed."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .manifest import (
    MAX_REPORT_BYTES,
    canonical_report_sha256,
    hash_analysis_resources,
    hash_input_tree,
    read_run_manifest,
)
from .models import Citation
from .report_validation import validate_report_data
from .security import SecurityError, read_limited_text, sha256_file, stays_in_tree
from .version import __version__


def compare_inventory(recorded: list[dict[str, Any]], current: list[dict[str, Any]]) -> dict[str, list[str]]:
    expected = {item["path"]: (item["sha256"].lower(), item["size_bytes"]) for item in recorded}
    observed = {item["path"]: (item["sha256"].lower(), item["size_bytes"]) for item in current}
    return {
        "added": sorted(observed.keys() - expected.keys()),
        "missing": sorted(expected.keys() - observed.keys()),
        "modified": sorted(path for path in expected.keys() & observed.keys() if expected[path] != observed[path]),
    }


def check_inputs(manifest: dict[str, Any], input_dir: Path) -> tuple[bool, dict[str, list[str]], str]:
    try:
        changes = compare_inventory(manifest["input_files"], hash_input_tree(input_dir))
    except (OSError, SecurityError) as exc:
        return False, {"added": [], "missing": [], "modified": []}, str(exc)
    return not any(changes.values()), changes, ""


def check_resources(manifest: dict[str, Any]) -> tuple[bool, str]:
    if manifest["manifest_version"] < 2:
        return True, ""
    paths = {key: Path(value) if value else None for key, value in manifest.get("paths", {}).items()}
    try:
        current = hash_analysis_resources(paths)
    except (OSError, SecurityError) as exc:
        return False, str(exc)
    def index(rows: list[dict[str, Any]]) -> dict[tuple[str, str], tuple[str, int]]:
        return {(item["kind"], item["path"]): (item["sha256"].lower(), item["size_bytes"]) for item in rows}

    return index(current) == index(manifest["resources"]), ""


def verify_run(manifest_path: Path, *, input_dir: Path | None = None) -> dict[str, Any]:
    """Check evidence, resources, and the stored report without rerunning it.

    Hashes detect changes relative to the manifest. This is not a digital
    signature, and it does not decide whether a finding's words are true.
    """
    # Resolve directory aliases without following a manifest-file symlink
    # into an unrelated output directory.
    manifest_path = manifest_path.parent.resolve() / manifest_path.name
    manifest = read_run_manifest(manifest_path)
    source = input_dir if input_dir is not None else Path(manifest["input_dir"])
    input_match, changes, input_error = check_inputs(manifest, source)
    resources_match, resource_error = check_resources(manifest)
    errors = [error for error in (input_error, resource_error) if error]
    artifacts_match, artifact_changes = _check_artifacts(manifest, manifest_path.parent)
    reviews_match, review_error, review_entries, _ = checked_review_snapshot(manifest, manifest_path.parent)
    if review_error:
        errors.append(review_error)
    actual_sha = ""
    report_match = False
    citations_match = False
    report_path = manifest_path.parent / manifest["output"]["report"]
    try:
        if not stays_in_tree(report_path, manifest_path.parent):
            raise SecurityError("Published report is missing or reached through a symlink")
        report = json.loads(read_limited_text(report_path, MAX_REPORT_BYTES))
        if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
            raise SecurityError("Published report is not a case report object")
        if report.get("case_id") != manifest["case_id"]:
            raise SecurityError("Published report case identifier differs from its manifest")
        validate_report_data(report)
        if reviews_match:
            from .reviews import review_state_error

            review_error = review_state_error(report, review_entries, require_summary=manifest.get("tool_version") == __version__)
            if review_error:
                reviews_match = False
                errors.append(review_error)
        actual_sha = canonical_report_sha256(report)
        report_match = actual_sha == manifest["output"]["sha256"].lower()
        citations_match = _check_citation_files(report["findings"], manifest["input_files"])
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        errors.append(str(exc))
    warnings = []
    if manifest.get("tool_version") != __version__:
        warnings.append("This run records another or unknown tool version; verify checks archived bytes, while replay/review require the recorded version")
    if manifest["manifest_version"] < 2:
        warnings.append("Legacy manifest does not record resource hashes or the parser text limit")
    if "artifacts" not in manifest:
        warnings.append("Legacy manifest does not hash the other report formats")
    if "analyst_reviews" in manifest and "sha256" not in manifest["analyst_reviews"]:
        warnings.append("Legacy manifest does not hash the analyst review log")
    return {
        "match": input_match and resources_match and report_match and citations_match and artifacts_match and reviews_match and not errors,
        "input_match": input_match,
        "resources_match": resources_match,
        "report_match": report_match,
        "citation_files_match": citations_match,
        "artifacts_match": artifacts_match,
        "artifact_changes": artifact_changes,
        "reviews_match": reviews_match,
        "input_changes": changes,
        "expected_sha256": manifest["output"]["sha256"],
        "actual_sha256": actual_sha,
        "errors": errors,
        "warnings": warnings,
    }


def _check_artifacts(manifest: dict[str, Any], output_dir: Path) -> tuple[bool, list[str]]:
    differences = []
    for item in manifest.get("artifacts", []):
        path = output_dir / item["path"]
        try:
            if not stays_in_tree(path, output_dir) or path.stat().st_size != item["size_bytes"] or sha256_file(path) != item["sha256"].lower():
                differences.append(item["path"])
        except OSError:
            differences.append(item["path"])
    return not differences, sorted(differences)


def check_review_log(manifest: dict[str, Any], output_dir: Path) -> tuple[bool, str]:
    match, error, _, _ = checked_review_snapshot(manifest, output_dir)
    return match, error


def checked_review_snapshot(manifest: dict[str, Any], output_dir: Path) -> tuple[bool, str, list[dict[str, Any]], str]:
    from .reviews import ReviewError, read_review_snapshot

    metadata = manifest.get("analyst_reviews")
    path = output_dir / "analyst_reviews.jsonl"
    if metadata is None:
        return (False, "An unrecorded analyst review log exists", [], "") if path.exists() or path.is_symlink() else (True, "", [], "")
    try:
        if not stays_in_tree(path, output_dir):
            return False, "Analyst review log is missing or reached through a symlink", [], ""
        entries, content = read_review_snapshot(path)
        if len(entries) != metadata["entries"]:
            return False, "Analyst review count does not match the manifest", [], ""
        raw = content.encode("utf-8")
        if "sha256" in metadata and (
            len(raw) != metadata["size_bytes"] or hashlib.sha256(raw).hexdigest() != metadata["sha256"].lower()
        ):
            return False, "Analyst review log hash does not match the manifest", [], ""
    except (OSError, ReviewError) as exc:
        return False, str(exc), [], ""
    return True, "", entries, content


def _check_citation_files(findings: list[Any], inputs: list[dict[str, Any]]) -> bool:
    for finding in findings:
        if not isinstance(finding, dict) or not isinstance(finding.get("citations"), list) or not finding["citations"]:
            return False
        for raw in finding["citations"]:
            if not isinstance(raw, dict):
                return False
            citation = Citation(**raw)
            if not citation.is_complete():
                return False
            matches = [item for item in inputs if item["sha256"].lower() == citation.sha256.lower() and (
                item["path"] == citation.source_file
                or (len(Path(citation.source_file).parts) == 1 and Path(item["path"]).name == citation.source_file)
            )]
            if not matches:
                return False
            if citation.offset and not any(citation.offset < item["size_bytes"] for item in matches):
                return False
    return True
