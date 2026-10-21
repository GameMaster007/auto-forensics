"""Stable identifiers for records that must survive a replay."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def stable_id(prefix: str, *parts: Any) -> str:
    """Return ``prefix`` plus 12 hex characters derived from ``parts``.

    The same parts always produce the same id. Nothing here uses the
    clock or a random source.
    """
    payload = json.dumps(parts, sort_keys=True, default=str, ensure_ascii=True, separators=(",", ":"))
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]
    return f"{prefix}-{digest}"
