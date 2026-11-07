"""Keep untrusted provider data and old cache rows safe for JSON projection."""

from __future__ import annotations

import json
import math
from typing import Any

from .security import validate_json_nesting

MAX_ENRICHMENT_BYTES = 4 * 1024 * 1024


def nonnegative_count(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        return None
    try:
        count = int(value)
        return count if count >= 0 and (not isinstance(value, float) or value == count) else None
    except (ValueError, OverflowError):
        return None


def virustotal_counts(stats: Any) -> tuple[int, int, int] | None:
    if not isinstance(stats, dict):
        return None
    counts = [nonnegative_count(stats.get(key, 0)) for key in ("malicious", "suspicious", "harmless")]
    malicious, suspicious, harmless = counts
    if malicious is None or suspicious is None or harmless is None:
        return None
    return malicious, suspicious, harmless


def abuse_score(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        return None
    try:
        score = float(value)
    except (ValueError, OverflowError):
        return None
    return score if math.isfinite(score) and 0 <= score <= 100 else None


def finite_json_object(raw: Any) -> dict[str, Any] | None:
    try:
        if isinstance(raw, str):
            if len(raw.encode("utf-8")) > MAX_ENRICHMENT_BYTES:
                return None
            raw = json.loads(raw)
        if not isinstance(raw, dict):
            return None
        validate_json_nesting(raw)
        encoded = json.dumps(raw, allow_nan=False, ensure_ascii=False)
        if len(encoded.encode("utf-8")) > MAX_ENRICHMENT_BYTES:
            return None
    except (ValueError, TypeError, RecursionError, OverflowError):
        return None
    return raw


def enrichment_payload(
    confidence: Any, details: Any, *, provider: str = "", verdict: str = "",
) -> tuple[float, dict[str, Any]] | None:
    if type(confidence) not in {int, float} or not 0 <= confidence <= 1:
        return None
    decoded = finite_json_object(details)
    if provider == "virustotal" and decoded is not None and virustotal_counts(decoded.get("analysis_stats")) is None:
        return None
    if provider == "abuseipdb" and decoded is not None and abuse_score(decoded.get("abuse_confidence_score")) is None:
        return None
    if provider == "malwarebazaar" and decoded is not None:
        status = decoded.get("query_status")
        expected = {"ok": "malicious", "hash_not_found": "not_found"}.get(status) if isinstance(status, str) else None
        if expected is None or verdict != expected:
            return None
    return (float(confidence), decoded) if decoded is not None else None
