"""Compare managed custody and database views with a saved, verified run."""

from __future__ import annotations

import json
from dataclasses import asdict, fields
from pathlib import Path
from typing import Any

from .db_backend import DatabaseBackend
from .integrity import compare_inventory, verify_run
from .manifest import REPORT_ARTIFACT_NAMES, hash_input_tree
from .models import CaseReport, Finding, TimelineEvent
from .reviews import load_case_report
from .security import SecurityError, bounded_tree_paths


def verified_case_report(case: dict[str, Any]) -> CaseReport:
    """Load only a report whose evidence, artifacts, and review log still match.

    The caller holds the output directory lock through any following write.
    An imported case may have a new managed ID; its original report ID stays
    intact so the archived report and manifest retain their original hashes.
    """
    output = Path(case["output_dir"])
    try:
        result = verify_run(output / "run_manifest.json", input_dir=Path(case["evidence_dir"]))
        if not result["match"]:
            raise SecurityError("Saved run integrity check failed; no database projection was changed")
        return load_case_report(output / "case_report.json")
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        raise SecurityError(f"Saved report could not be verified: {exc}") from exc


def custody_changes(db: DatabaseBackend, case: dict[str, Any]) -> dict[str, list[str]]:
    artifacts = db.get_artifacts(case["case_id"])
    if any(row.get("_json_errors") for row in artifacts):
        raise SecurityError("Stored artifact provenance contains invalid JSON")
    recorded = [
        {"path": row["rel_path"], "sha256": row["sha256"], "size_bytes": row["size_bytes"]}
        for row in artifacts
    ]
    root = Path(case["evidence_dir"])
    changes = compare_inventory(recorded, hash_input_tree(root))
    indexed = {row["path"] for row in recorded}
    for path in bounded_tree_paths(root):
        if path.is_symlink() or (not path.is_dir() and not path.is_file()):
            relative = str(path.relative_to(root))
            category = "modified" if relative in indexed else "added"
            changes[category].append(relative)
    return {key: sorted(set(paths)) for key, paths in changes.items()}


def finding_projection_changes(report: CaseReport, rows: list[dict[str, Any]]) -> dict[str, list[str]]:
    expected = {item.finding_id: asdict(item) for item in report.findings}
    names = {field.name for field in fields(Finding)}
    observed = {row["finding_id"]: {key: row.get(key) for key in names} for row in rows}
    if len(expected) != len(report.findings) or len(observed) != len(rows):
        raise SecurityError("Report or database has duplicate finding identities")
    corrupt = {row["finding_id"] for row in rows if row.get("_json_errors")}
    return {
        "missing": sorted(expected.keys() - observed.keys()),
        "extra": sorted(observed.keys() - expected.keys()),
        "modified": sorted(key for key in expected.keys() & observed.keys() if expected[key] != observed[key] or key in corrupt),
    }


def _timeline_matches(report: CaseReport, rows: list[dict[str, Any]]) -> bool:
    if any(row.get("_json_errors") for row in rows):
        return False
    names = {field.name for field in fields(TimelineEvent)}
    expected = [asdict(item) for item in report.timeline]
    observed = [{key: row.get(key) for key in names} for row in rows]
    # Database ordering is not significant, but duplicate events are.
    def canonical(items: list[dict[str, Any]]) -> list[str]:
        return sorted(json.dumps(item, sort_keys=True, allow_nan=False) for item in items)

    return canonical(expected) == canonical(observed)


def inspect_case_integrity(db: DatabaseBackend, case: dict[str, Any]) -> dict[str, Any]:
    """Inspect under the caller's case/output locks without running a model."""
    errors: list[str] = []
    changes: dict[str, list[str]] = {"added": [], "missing": [], "modified": []}
    custody_match = False
    try:
        changes = custody_changes(db, case)
        custody_match = not any(changes.values())
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        errors.append(f"Custody check failed: {exc}")
    output = Path(case["output_dir"])
    present = (output / "run_manifest.json").exists() or (output / "run_manifest.json").is_symlink()
    run = None
    projection: dict[str, list[str]] | None = None
    timeline_match = None
    try:
        if present:
            run = verify_run(output / "run_manifest.json", input_dir=Path(case["evidence_dir"]))
            if run["report_match"] and run["artifacts_match"]:
                report = load_case_report(output / "case_report.json")
                projection = finding_projection_changes(report, db.get_findings(case["case_id"]))
                timeline_match = _timeline_matches(report, db.get_timeline(case["case_id"]))
        elif any((output / name).exists() or (output / name).is_symlink() for name in (*REPORT_ARTIFACT_NAMES, "analyst_reviews.jsonl")) or db.get_findings(case["case_id"]) or db.get_timeline(case["case_id"]):
            errors.append("A report or database projection exists without its run manifest")
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        errors.append(f"Run check failed: {exc}")
    projection_match = projection is not None and not any(projection.values()) and timeline_match is True
    return {
        "case_id": case["case_id"],
        "match": custody_match and not errors and (not present or bool(run and run["match"] and projection_match)),
        "custody_match": custody_match,
        "custody_changes": changes,
        "report_present": present,
        "run": run,
        "projection_match": projection_match if present else None,
        "finding_changes": projection,
        "timeline_match": timeline_match,
        "errors": errors,
    }
