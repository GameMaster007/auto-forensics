"""Validate imported report fields before rendering or database projection."""

from __future__ import annotations

import math
import types
from dataclasses import MISSING, fields
from typing import Any, Union, get_args, get_origin, get_type_hints

from .models import IOC, BinaryFeature, BinaryStringMatch, CaseReport, Citation, Finding, IOCEnrichment, TimelineEvent
from .security import SecurityError, validate_json_nesting

_RECORDS = (CaseReport, Finding, Citation, BinaryFeature, BinaryStringMatch, TimelineEvent, IOC, IOCEnrichment)
_HINTS = {record: get_type_hints(record) for record in _RECORDS}


def _valid(value: Any, expected: Any, depth: int = 0) -> bool:
    if expected is Any:
        return True
    if depth > 64:
        return False
    origin = get_origin(expected)
    if origin in {Union, types.UnionType}:
        return any(_valid(value, option, depth + 1) for option in get_args(expected))
    if origin is list:
        return isinstance(value, list) and all(_valid(item, get_args(expected)[0], depth + 1) for item in value)
    if origin is dict:
        key_type, value_type = get_args(expected)
        return isinstance(value, dict) and all(
            _valid(key, key_type, depth + 1) and _valid(item, value_type, depth + 1) for key, item in value.items()
        )
    if expected in _HINTS:
        if not isinstance(value, dict):
            return False
        for field in fields(expected):
            if field.name not in value:
                if field.default is MISSING and field.default_factory is MISSING:
                    return False
            elif not _valid(value[field.name], _HINTS[expected][field.name], depth + 1):
                return False
        return True
    if expected is float:
        if type(value) not in {int, float}:
            return False
        try:
            return math.isfinite(value)
        except OverflowError:
            return False
    if expected in {int, bool, str, type(None)}:
        return type(value) is expected
    return False


def validate_report_data(raw: Any) -> None:
    """Accept the known report schema, retaining unknown extension fields.

    Hash validity does not imply field validity: a producer can checksum an
    object that cannot safely become a Finding or a database parameter.
    """
    validate_json_nesting(raw)
    if not isinstance(raw, dict):
        raise SecurityError("Published report must be an object")
    payload = dict(raw)
    if "ioc_enrichments" in raw:
        payload["enrichments"] = raw["ioc_enrichments"]
    if not _valid(payload, CaseReport):
        raise SecurityError("Published report has invalid record field types or missing required fields")
    for name, identifier in (("findings", "finding_id"), ("iocs", "ioc_id")):
        seen: set[str] = set()
        for record in raw.get(name, []):
            identity = record[identifier]
            if not identity.strip() or len(identity) > 128 or identity in seen:
                raise SecurityError(f"Published report has invalid or duplicate {identifier} values")
            seen.add(identity)
    for finding in raw["findings"]:
        for name in ("confidence", "confidence_low", "confidence_high"):
            value = finding.get(name)
            if value is not None and not 0 <= value <= 1:
                raise SecurityError("Published report has an invalid finding confidence")
    summary = raw["summary"]
    for key in ("total_findings", "timeline_events", "ioc_count", "analyst_accepted", "analyst_rejected", "analyst_unverified"):
        if key in summary and (type(summary[key]) is not int or summary[key] < 0):
            raise SecurityError("Published report has invalid summary counts")
    for key, expected in (("severity_breakdown", dict[str, int]), ("verified_finding_ids", list[str]), ("verification", list[dict[str, Any]])):
        if key in summary and not _valid(summary[key], expected):
            raise SecurityError("Published report has invalid summary field types")
    for verdict in summary.get("verification", []):
        if any(key in verdict and not isinstance(verdict[key], str) for key in ("finding_id", "verdict", "reason", "judge", "artifact_id", "source_file")):
            raise SecurityError("Published report has invalid verifier field types")
