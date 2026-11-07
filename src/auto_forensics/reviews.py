"""Analyst accept, reject, and annotate for one finding.

The decision is appended to ``analyst_reviews.jsonl`` in the run
directory. That file is the custody log: actor, time, and note. Replay
reads it and applies the same entries, so the report hash still matches.
A second accept or reject is refused unless the caller passes override.
The earlier line stays in the log.
"""

from __future__ import annotations

import json
from dataclasses import fields
from pathlib import Path
from typing import Any

from .file_ops import directory_lock
from .manifest import MAX_REPORT_BYTES, read_run_manifest
from .models import (
    IOC,
    BinaryFeature,
    BinaryStringMatch,
    CaseReport,
    Citation,
    Finding,
    IOCEnrichment,
    TimelineEvent,
    utc_now_iso,
)
from .pipeline import rewrite_published_report
from .security import SecurityError, read_limited_text
from .timeline import parse_iso
from .version import __version__

ANALYST_REVIEW_LOG = "analyst_reviews.jsonl"
_DECISIONS = {"accept", "reject"}


class ReviewError(ValueError):
    """A review failed; the message identifies any saved decision needing repair."""


def record_review(
    output_dir: Path,
    *,
    finding_id: str,
    decision: str,
    actor: str,
    note: str = "",
    override: bool = False,
    at: str | None = None,
    input_dir: Path | None = None,
) -> dict[str, Any]:
    """Verify and lock a run before recording an analyst decision."""
    output_dir = output_dir.resolve()
    try:
        with directory_lock(output_dir):
            return record_review_locked(
                output_dir, finding_id=finding_id, decision=decision, actor=actor,
                note=note, override=override, at=at, input_dir=input_dir,
            )
    except SecurityError as exc:
        raise ReviewError(str(exc)) from exc


def record_review_locked(
    output_dir: Path, *, finding_id: str, decision: str, actor: str,
    note: str = "", override: bool = False, at: str | None = None, input_dir: Path | None = None,
) -> dict[str, Any]:
    """Record under an output lock already held by a managed-case operation."""
    from .integrity import verify_run

    if read_run_manifest(output_dir / "run_manifest.json").get("tool_version") != __version__:
        raise ReviewError("Review requires the tool version recorded in the manifest; no decision was recorded")
    result = verify_run(output_dir / "run_manifest.json", input_dir=input_dir)
    if not result["match"]:
        raise ReviewError("Run integrity check failed before review; no decision was recorded")
    return _record_review(output_dir, finding_id=finding_id, decision=decision, actor=actor,
                          note=note, override=override, at=at)


def _record_review(
    output_dir: Path,
    *,
    finding_id: str,
    decision: str,
    actor: str,
    note: str,
    override: bool,
    at: str | None,
) -> dict[str, Any]:
    """Append one review and publish it on the report.

    ``at`` is set by the caller only when replaying a stored entry.
    A normal review uses the current UTC time.
    """
    report_path = output_dir / "case_report.json"
    if not report_path.is_file():
        raise ReviewError("case report was not found in the output directory")
    if not isinstance(decision, str) or type(override) is not bool:
        raise ReviewError("decision must be text and override must be a boolean")
    action = decision.strip().lower()
    if action not in {"accept", "reject", "annotate"}:
        raise ReviewError("decision must be accept, reject, or annotate")
    clean_actor = _clean_actor(actor)
    clean_note = _clean_note(note, required=action == "annotate")
    clean_id = _clean_id(finding_id)
    log_path = output_dir / ANALYST_REVIEW_LOG
    entries = read_review_log(log_path)
    if action in _DECISIONS and not override:
        prior = _latest_decision(entries, clean_id)
        if prior is not None:
            raise ReviewError(
                f"{prior['actor']} already set this finding to {prior['action']} at {prior['at']}"
            )
    report = load_case_report(report_path)
    finding = _finding(report, clean_id)
    entry = {
        "finding_id": clean_id,
        "action": action,
        "actor": clean_actor,
        "at": utc_now_iso() if at is None else at,
        "note": clean_note,
        "override": bool(override),
    }
    _validate_entry(entry)
    apply_entry(finding, entry)
    previous = log_path.read_bytes().decode("utf-8") if log_path.exists() else ""
    if previous and not previous.endswith("\n"):
        previous += "\n"
    log_content = previous + json.dumps(entry, ensure_ascii=True, sort_keys=True) + "\n"
    entries.append(entry)
    rewrite_published_report(
        report,
        output_dir,
        review_log=ANALYST_REVIEW_LOG,
        review_count=len(entries),
        review_log_content=log_content,
    )
    return entry


def apply_review_log(output_dir: Path, log_path: Path) -> bool:
    """Apply a custody log onto a freshly written report.

    Returns False when a logged finding is not in the report. The
    report is left unchanged in that case, so a replay hash misses.
    """
    if not log_path.exists() and not log_path.is_symlink():
        return True
    entries = read_review_log(log_path)
    if not entries:
        return True
    content = log_path.read_bytes().decode("utf-8")
    output_dir = output_dir.resolve()
    with directory_lock(output_dir):
        report = load_case_report(output_dir / "case_report.json")
        by_id = {item.finding_id: item for item in report.findings}
        for entry in entries:
            finding = by_id.get(entry["finding_id"])
            if finding is None:
                return False
            apply_entry(finding, entry)
        rewrite_published_report(
            report, output_dir, review_log=ANALYST_REVIEW_LOG,
            review_count=len(entries), review_log_content=content,
        )
    return True


def apply_entry(finding: Finding, entry: dict[str, Any]) -> None:
    """Set one finding from a log line. Applying the same line twice is the same."""
    action = str(entry.get("action") or "")
    note = str(entry.get("note") or "")
    if action == "annotate":
        finding.review_note = note
        return
    if action == "accept":
        if finding.verification == "not verified" and finding.machine_verification:
            finding.verification = finding.machine_verification
        finding.review_status = "accepted"
        finding.review_actor = str(entry.get("actor") or "")
        finding.review_at = str(entry.get("at") or "")
        finding.analyst_verified = True
        if note:
            finding.review_note = note
        return
    if action == "reject":
        if finding.verification != "not verified":
            finding.machine_verification = finding.verification
        finding.verification = "not verified"
        finding.review_status = "rejected"
        finding.review_actor = str(entry.get("actor") or "")
        finding.review_at = str(entry.get("at") or "")
        finding.analyst_verified = False
        if note:
            finding.review_note = note


def read_review_log(path: Path) -> list[dict[str, Any]]:
    """Read the custody log. A broken line is an error, not a skipped review."""
    if path.is_symlink() or not path.is_file():
        if not path.exists() and not path.is_symlink():
            return []
        raise ReviewError("analyst review log must be a regular file")
    with path.open("rb") as handle:
        raw = handle.read(8 * 1024 * 1024 + 1)
    if len(raw) > 8 * 1024 * 1024:
        raise ReviewError("analyst review log exceeds its size limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeError as exc:
        raise ReviewError("analyst review log is not UTF-8") from exc
    entries: list[dict[str, Any]] = []
    decided: set[str] = set()
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ReviewError("analyst review log has a line that is not JSON") from exc
        if not isinstance(item, dict):
            raise ReviewError("analyst review log has a line that is not a record")
        _validate_entry(item)
        if item["action"] in _DECISIONS:
            if item["finding_id"] in decided and not item["override"]:
                raise ReviewError("analyst review log silently overwrites a prior decision")
            decided.add(item["finding_id"])
        entries.append(item)
    return entries


def _validate_entry(entry: dict[str, Any]) -> None:
    if set(entry) != {"finding_id", "action", "actor", "at", "note", "override"}:
        raise ReviewError("analyst review log has an invalid record shape")
    if not isinstance(entry["action"], str) or entry["action"] not in {"accept", "reject", "annotate"}:
        raise ReviewError("analyst review log has an invalid action")
    if not isinstance(entry["actor"], str) or _clean_actor(entry["actor"]) != entry["actor"]:
        raise ReviewError("analyst review log has an invalid actor")
    if not isinstance(entry["note"], str) or _clean_note(entry["note"], required=entry["action"] == "annotate") != entry["note"]:
        raise ReviewError("analyst review log has an invalid note")
    if not isinstance(entry["finding_id"], str) or _clean_id(entry["finding_id"]) != entry["finding_id"]:
        raise ReviewError("analyst review log has an invalid finding identifier")
    if type(entry["override"]) is not bool:
        raise ReviewError("analyst review log has an invalid override flag")
    timestamp = entry["at"]
    try:
        if not isinstance(timestamp, str) or len(timestamp) > 64:
            raise ValueError("invalid timestamp")
        if parse_iso(timestamp, require_timezone=True) is None:
            raise ValueError("invalid timestamp or missing timezone")
    except ValueError as exc:
        raise ReviewError("analyst review log has an invalid timestamp") from exc


def load_case_report(path: Path) -> CaseReport:
    """Load ``case_report.json`` back into a report."""
    raw = json.loads(read_limited_text(path, MAX_REPORT_BYTES))
    return CaseReport(
        case_id=str(raw.get("case_id") or ""),
        generated_at=str(raw.get("generated_at") or ""),
        binary_features=[_binary_from_dict(item) for item in raw.get("binary_features") or []],
        findings=[_finding_from_dict(item) for item in raw.get("findings") or []],
        timeline=[_from_dict(TimelineEvent, item) for item in raw.get("timeline") or []],
        summary=dict(raw.get("summary") or {}),
        iocs=[_from_dict(IOC, item) for item in raw.get("iocs") or []],
        enrichments=[_from_dict(IOCEnrichment, item) for item in raw.get("ioc_enrichments") or []],
    )


def _finding_from_dict(item: dict[str, Any]) -> Finding:
    payload = {key: value for key, value in item.items() if key in _FIELD_NAMES[Finding]}
    payload["citations"] = [
        _from_dict(Citation, citation) for citation in item.get("citations") or [] if isinstance(citation, dict)
    ]
    return Finding(**payload)


def _binary_from_dict(item: dict[str, Any]) -> BinaryFeature:
    payload = {key: value for key, value in item.items() if key in _FIELD_NAMES[BinaryFeature]}
    payload["string_matches"] = [_from_dict(BinaryStringMatch, match) for match in item.get("string_matches") or []]
    return BinaryFeature(**payload)


def _from_dict(cls: type, item: dict[str, Any]) -> Any:
    names = _FIELD_NAMES[cls]
    return cls(**{key: value for key, value in item.items() if key in names})


_FIELD_NAMES: dict[type, set[str]] = {
    cls: {item.name for item in fields(cls)}
    for cls in (Finding, Citation, BinaryFeature, BinaryStringMatch, TimelineEvent, IOC, IOCEnrichment)
}


def _finding(report: CaseReport, finding_id: str) -> Finding:
    for item in report.findings:
        if item.finding_id == finding_id:
            return item
    raise ReviewError(f"finding {finding_id} is not in the report")


def _latest_decision(entries: list[dict[str, Any]], finding_id: str) -> dict[str, Any] | None:
    found: dict[str, Any] | None = None
    for entry in entries:
        if entry.get("finding_id") == finding_id and entry.get("action") in _DECISIONS:
            found = entry
    return found


def _clean_actor(value: str) -> str:
    if not isinstance(value, str):
        raise ReviewError("actor is required")
    text = " ".join(value.split())
    if not text or len(text) > 120:
        raise ReviewError("actor is required")
    return text


def _clean_note(value: str, *, required: bool) -> str:
    if not isinstance(value, str):
        raise ReviewError("note must be text")
    text = " ".join(value.split())
    if required and not text:
        raise ReviewError("an annotation needs a note")
    if len(text) > 2000:
        raise ReviewError("note is too long")
    return text


def _clean_id(value: str) -> str:
    if not isinstance(value, str):
        raise ReviewError("finding id is required")
    text = value.strip()
    if not text or any(char.isspace() for char in text) or len(text) > 200:
        raise ReviewError("finding id is required")
    return text
