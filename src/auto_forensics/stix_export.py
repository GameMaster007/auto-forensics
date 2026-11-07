"""STIX 2.1 observables and review-bearing notes, without threat verdicts."""

from __future__ import annotations

import ipaddress
import json
import math
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any

from .ioc_pipeline import normalize_ioc_value
from .models import IOC, CaseReport, Finding
from .security import SecurityError

# Producer namespace, distinct from the STIX shared SCO namespace. Include
# object type in the name to avoid reusing a UUID across object types.
_NAMESPACE = uuid.UUID("b4f8568e-4030-4b8f-9d45-03e596ee800d")


def _stix_id(stix_type: str, *parts: Any) -> str:
    name = json.dumps([stix_type, *parts], sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
    return f"{stix_type}--{uuid.uuid5(_NAMESPACE, name)}"


def _timestamp(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    except (ValueError, TypeError, AttributeError, OverflowError) as exc:
        raise SecurityError("STIX export requires a valid report timestamp") from exc


def _confidence(finding: Finding) -> int:
    value = finding.confidence
    return round(value * 100) if type(value) in {int, float} and 0 <= value <= 1 and math.isfinite(value) else 0


def _observable(ioc: IOC) -> dict[str, Any] | None:
    value = normalize_ioc_value(ioc.ioc_type, ioc.value)
    if value is None:
        return None
    if ioc.ioc_type == "ip":
        kind = "ipv4-addr" if ipaddress.ip_address(value).version == 4 else "ipv6-addr"
        payload: dict[str, Any] = {"type": kind, "value": value}
    elif ioc.ioc_type in {"url", "domain"}:
        payload = {"type": "url" if ioc.ioc_type == "url" else "domain-name", "value": value}
    elif ioc.ioc_type in {"hash", "md5", "sha1", "sha256"}:
        algorithm = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}[len(value)]
        payload = {"type": "file", "hashes": {algorithm: value}}
    else:
        return None
    return {**payload, "spec_version": "2.1", "id": _stix_id(payload["type"], payload)}


def _observation_times(ioc: IOC, generated_at: str) -> tuple[str, str, str]:
    if not ioc.first_seen and not ioc.last_seen:
        return generated_at, generated_at, "analysis-time"
    try:
        first = _timestamp(ioc.first_seen or ioc.last_seen or generated_at)
        last = _timestamp(ioc.last_seen or ioc.first_seen or generated_at)
        if first <= last:
            return first, last, "reported-observation-time"
    except SecurityError:
        pass
    return generated_at, generated_at, "analysis-time; invalid reported interval"


def build_stix_bundle(
    report: CaseReport, *, review_times: dict[str, str] | None = None,
    review_history: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Use notes for findings and standard SCOs for observable candidates.

    An accept verifies the finding, not the maliciousness of every address
    it mentions. No indicator or ``indicates`` relationship is synthesized.
    IDs are deterministic in a producer-specific namespace.
    """
    for records, key in ((report.findings, "finding_id"), (report.iocs, "ioc_id")):
        identities = [getattr(record, key) for record in records]
        if any(not isinstance(identity, str) or not identity for identity in identities) or len(set(identities)) != len(identities):
            raise SecurityError("STIX export requires unique nonempty finding and observable identities")
    created = _timestamp(report.generated_at)
    modified = created
    scope = [report.case_id, created]
    identity_id = _stix_id("identity", scope, "producer")
    grouping_id = _stix_id("grouping", scope)
    common = {"spec_version": "2.1", "created": created, "modified": created, "created_by_ref": identity_id}
    objects: dict[str, dict[str, Any]] = {
        identity_id: {
            "type": "identity", "id": identity_id, "spec_version": "2.1", "created": created, "modified": created,
            "name": "Auto Forensics Framework", "identity_class": "system",
        },
    }
    ioc_refs: dict[str, str] = {}
    for ioc in report.iocs:
        observable = _observable(ioc)
        if observable is None:
            note_id = _stix_id("note", scope, "unmapped-observable", ioc.ioc_id)
            objects[note_id] = {
                **common, "type": "note", "id": note_id, "abstract": "Unmapped observable candidate",
                "content": f"Candidate type={ioc.ioc_type}, value={ioc.value} could not be represented as a standard observable.",
                "object_refs": [grouping_id], "labels": ["unmapped-observable"],
                "x_auto_forensics_ioc_id": ioc.ioc_id,
            }
            ioc_refs[ioc.ioc_id] = note_id
            continue
        objects[observable["id"]] = observable
        observed_id = _stix_id("observed-data", scope, ioc.ioc_id)
        first, last, basis = _observation_times(ioc, created)
        objects[observed_id] = {
            **common, "type": "observed-data", "id": observed_id,
            "first_observed": first, "last_observed": last, "number_observed": 1,
            "object_refs": [observable["id"]], "labels": ["observable-candidate", ioc.ioc_type],
            "x_auto_forensics_ioc_id": ioc.ioc_id, "x_auto_forensics_time_basis": basis,
            "x_auto_forensics_count_basis": "one exported candidate record; occurrence counts not inferred",
        }
        if ioc.sources:
            objects[observed_id]["x_auto_forensics_sources"] = list(ioc.sources)
        if ioc.metadata:
            objects[observed_id]["x_auto_forensics_provenance"] = dict(ioc.metadata)
        ioc_refs[ioc.ioc_id] = observed_id

    for finding in report.findings:
        note_modified = created
        for value in (finding.review_at, (review_times or {}).get(finding.finding_id)):
            if value:
                note_modified = max(note_modified, _timestamp(value))
        modified = max(modified, note_modified)
        note_id = _stix_id("note", scope, "finding", finding.finding_id)
        status = finding.review_status if finding.review_status in {"accepted", "rejected"} else "unverified"
        refs = [grouping_id, *(ioc_refs[key] for key in finding.ioc_refs if key in ioc_refs)]
        content = [finding.title, f"Analyst review: {status}", f"Machine verification: {finding.verification}",
                   f"Severity: {finding.severity}; tactic: {finding.tactic}", *finding.evidence]
        if finding.review_actor:
            content.append(f"Decision by {finding.review_actor} at {finding.review_at}")
        if finding.review_note:
            content.append(f"Analyst note: {finding.review_note}")
        note: dict[str, Any] = {
            **common, "type": "note", "id": note_id, "abstract": finding.title or "Untitled forensic finding",
            "modified": note_modified,
            "content": "\n".join(content), "object_refs": sorted(set(refs)),
            "labels": ["forensic-finding", f"analyst-{status}"], "confidence": _confidence(finding),
            "x_auto_forensics_finding_id": finding.finding_id, "x_auto_forensics_review_status": status,
            "x_auto_forensics_analyst_verified": finding.analyst_verified is True and status == "accepted",
        }
        for key in ("verification", "machine_verification"):
            if getattr(finding, key):
                note[f"x_auto_forensics_{key}"] = getattr(finding, key)
        if finding.citations:
            note["x_auto_forensics_citations"] = [asdict(citation) for citation in finding.citations]
        history = [entry for entry in review_history or [] if entry.get("finding_id") == finding.finding_id]
        if history:
            note["x_auto_forensics_review_history"] = history
        if finding.review_actor:
            note["authors"] = [finding.review_actor]
        objects[note_id] = note

    objects[grouping_id] = {
        **common, "type": "grouping", "id": grouping_id, "context": "unspecified", "modified": modified,
        "name": f"Forensic case {report.case_id}",
        "description": "Forensic triage findings and observable candidates. Analyst review is recorded on each finding note; observation alone is not a threat verdict.",
        "object_refs": sorted(objects),
    }
    if modified != created:
        objects[grouping_id]["x_auto_forensics_latest_review_at"] = modified
    ordered = [objects[key] for key in sorted(objects)]
    return {"type": "bundle", "id": _stix_id("bundle", ordered), "objects": ordered}
