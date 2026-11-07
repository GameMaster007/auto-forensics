"""Bound JSON response bodies and keep request credentials off redirects."""

from __future__ import annotations

import http.client
import json
import urllib.request
from typing import Any

from .security import validate_json_nesting

_PRIVATE_HEADERS = {"authorization", "x-apikey", "auth-key", "key"}


def private_request(url: str, *, method: str, data: bytes | None, headers: dict[str, str]) -> urllib.request.Request:
    request = urllib.request.Request(url=url, method=method, data=data)
    for name, value in headers.items():
        if name.lower() in _PRIVATE_HEADERS:
            request.add_unredirected_header(name, value)
        else:
            request.add_header(name, value)
    return request


def json_object(text: str) -> dict[str, Any] | None:
    try:
        value = json.loads(text)
        validate_json_nesting(value)
    except (ValueError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


def read_json_response(response: Any, *, max_bytes: int) -> dict[str, Any] | None:
    declared = (getattr(response, "headers", None) or {}).get("Content-Length")
    expected_length = int(declared) if declared is not None else None
    if expected_length is not None and (expected_length < 0 or expected_length > max_bytes):
        return None
    raw = response.read(max_bytes + 1)
    if len(raw) > max_bytes:
        return None
    if expected_length is not None and len(raw) != expected_length:
        raise http.client.IncompleteRead(raw, max(0, expected_length - len(raw)))
    try:
        return json_object(raw.decode("utf-8"))
    except UnicodeError:
        return None
