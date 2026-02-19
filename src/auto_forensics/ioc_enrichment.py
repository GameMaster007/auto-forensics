from __future__ import annotations

import base64
import json
import logging
import math
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Any

from .models import IOC, IOCEnrichment

logger = logging.getLogger(__name__)


def _request_json(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: dict[str, Any] | None = None,
    timeout_seconds: int = 20,
    retries: int = 0,
    backoff_base_seconds: float = 0.75,
    backoff_max_seconds: float = 8.0,
) -> dict[str, Any] | None:
    attempts = max(0, int(retries)) + 1

    def _sleep_for_attempt(attempt_index: int, retry_after: str | None = None) -> None:
        if retry_after:
            try:
                retry_value = float(retry_after)
                if retry_value > 0:
                    time.sleep(min(backoff_max_seconds, retry_value))
                    return
            except ValueError:
                pass
        duration = min(backoff_max_seconds, backoff_base_seconds * math.pow(2, attempt_index))
        if duration > 0:
            time.sleep(duration)

    raw_body = None
    req_headers = dict(headers or {})
    if body is not None:
        raw_body = urllib.parse.urlencode(body).encode("utf-8")
        req_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    for attempt_idx in range(attempts):
        request = urllib.request.Request(url=url, method=method, headers=req_headers, data=raw_body)
        try:
            with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
                text = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            status = int(getattr(exc, "code", 0) or 0)
            retryable = status in {408, 409, 425, 429, 500, 502, 503, 504}
            if retryable and attempt_idx < attempts - 1:
                retry_after = exc.headers.get("Retry-After") if exc.headers else None
                _sleep_for_attempt(attempt_idx, retry_after=retry_after)
                continue
            if status >= 400:
                logger.debug("HTTP %d from enrichment API %s: %s", status, url, exc.reason)
            return None
        except urllib.error.URLError as exc:
            logger.debug("URL error contacting enrichment API %s: %s", url, exc.reason)
            if attempt_idx < attempts - 1:
                _sleep_for_attempt(attempt_idx)
                continue
            return None
        except (TimeoutError, ValueError) as exc:
            logger.debug("Network error contacting enrichment API %s: %s", url, exc)
            if attempt_idx < attempts - 1:
                _sleep_for_attempt(attempt_idx)
                continue
            return None

        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return None
        return payload if isinstance(payload, dict) else None
    return None


@dataclass(slots=True)
class EnrichmentConfig:
    virustotal_api_key: str | None = None
    malwarebazaar_api_key: str | None = None
    abuseipdb_api_key: str | None = None
    enable_whois_lookup: bool = False
    http_retries: int = 2
    backoff_base_seconds: float = 0.75
    backoff_max_seconds: float = 8.0


def enabled_providers(config: EnrichmentConfig) -> list[str]:
    providers: list[str] = ["malwarebazaar"]
    if config.virustotal_api_key:
        providers.append("virustotal")
    if config.abuseipdb_api_key:
        providers.append("abuseipdb")
    if config.enable_whois_lookup:
        providers.append("whois")
    return providers


def _request_kwargs(config: EnrichmentConfig) -> dict[str, Any]:
    return {
        "retries": config.http_retries,
        "backoff_base_seconds": config.backoff_base_seconds,
        "backoff_max_seconds": config.backoff_max_seconds,
    }


def _vt_enrich(ioc: IOC, api_key: str, config: EnrichmentConfig) -> IOCEnrichment | None:
    if ioc.ioc_type in {"sha256", "md5", "hash"}:
        url = f"https://www.virustotal.com/api/v3/files/{urllib.parse.quote(ioc.value, safe='')}"
    elif ioc.ioc_type == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{urllib.parse.quote(ioc.value, safe='')}"
    elif ioc.ioc_type == "domain":
        url = f"https://www.virustotal.com/api/v3/domains/{urllib.parse.quote(ioc.value, safe='')}"
    elif ioc.ioc_type == "url":
        encoded = base64.urlsafe_b64encode(ioc.value.encode("utf-8")).decode("ascii").rstrip("=")
        url = f"https://www.virustotal.com/api/v3/urls/{encoded}"
    else:
        return None

    payload = _request_json(url, headers={"x-apikey": api_key}, **_request_kwargs(config))
    if not payload:
        return None
    attrs = payload.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {}) if isinstance(attrs, dict) else {}
    malicious = float(stats.get("malicious", 0) or 0)
    suspicious = float(stats.get("suspicious", 0) or 0)
    harmless = float(stats.get("harmless", 0) or 0)
    total = malicious + suspicious + harmless
    ratio = (malicious + suspicious) / total if total > 0 else 0.0
    verdict = "malicious" if ratio >= 0.25 else "suspicious" if ratio > 0 else "unknown"
    return IOCEnrichment(
        enrichment_id=f"vt-{uuid.uuid4().hex[:10]}",
        ioc_id=ioc.ioc_id,
        provider="virustotal",
        verdict=verdict,
        confidence=min(1.0, 0.4 + ratio),
        details={"analysis_stats": stats},
    )


def _malwarebazaar_enrich(ioc: IOC, config: EnrichmentConfig, api_key: str | None = None) -> IOCEnrichment | None:
    if ioc.ioc_type not in {"sha256", "md5", "hash"}:
        return None
    headers = {}
    if api_key:
        headers["API-KEY"] = api_key
    payload = _request_json(
        "https://mb-api.abuse.ch/api/v1/",
        method="POST",
        headers=headers,
        body={"query": "get_info", "hash": ioc.value},
        **_request_kwargs(config),
    )
    if not payload:
        return None
    data = payload.get("data")
    if not isinstance(data, list) or not data:
        return IOCEnrichment(
            enrichment_id=f"mb-{uuid.uuid4().hex[:10]}",
            ioc_id=ioc.ioc_id,
            provider="malwarebazaar",
            verdict="not_found",
            confidence=0.6,
            details={},
        )
    first = data[0] if isinstance(data[0], dict) else {}
    signature = str(first.get("signature") or "")
    tags = first.get("tags") if isinstance(first.get("tags"), list) else []
    return IOCEnrichment(
        enrichment_id=f"mb-{uuid.uuid4().hex[:10]}",
        ioc_id=ioc.ioc_id,
        provider="malwarebazaar",
        verdict="malicious",
        confidence=0.9,
        details={"signature": signature, "tags": tags},
    )


def _abuseipdb_enrich(ioc: IOC, api_key: str, config: EnrichmentConfig) -> IOCEnrichment | None:
    if ioc.ioc_type != "ip":
        return None
    url = (
        "https://api.abuseipdb.com/api/v2/check?"
        + urllib.parse.urlencode({"ipAddress": ioc.value, "maxAgeInDays": 90, "verbose": ""})
    )
    payload = _request_json(url, headers={"Key": api_key, "Accept": "application/json"}, **_request_kwargs(config))
    if not payload:
        return None
    data = payload.get("data", {}) if isinstance(payload.get("data", {}), dict) else {}
    score = float(data.get("abuseConfidenceScore", 0) or 0)
    verdict = "malicious" if score >= 50 else "suspicious" if score > 0 else "unknown"
    return IOCEnrichment(
        enrichment_id=f"abuseipdb-{uuid.uuid4().hex[:10]}",
        ioc_id=ioc.ioc_id,
        provider="abuseipdb",
        verdict=verdict,
        confidence=min(1.0, max(0.3, score / 100.0)),
        details={"abuse_confidence_score": score, "usage_type": data.get("usageType")},
    )


def _rdap_whois_enrich(ioc: IOC, config: EnrichmentConfig) -> IOCEnrichment | None:
    if ioc.ioc_type not in {"domain", "ip"}:
        return None
    if ioc.ioc_type == "domain":
        url = f"https://rdap.org/domain/{urllib.parse.quote(ioc.value)}"
    else:
        url = f"https://rdap.org/ip/{urllib.parse.quote(ioc.value)}"
    payload = _request_json(url, **_request_kwargs(config))
    if not payload:
        return None
    handle = str(payload.get("handle") or "")
    status = payload.get("status") if isinstance(payload.get("status"), list) else []
    return IOCEnrichment(
        enrichment_id=f"rdap-{uuid.uuid4().hex[:10]}",
        ioc_id=ioc.ioc_id,
        provider="whois",
        verdict="informational",
        confidence=0.5,
        details={"handle": handle, "status": status},
    )


def enrich_ioc(ioc: IOC, config: EnrichmentConfig) -> list[IOCEnrichment]:
    output: list[IOCEnrichment] = []

    if config.virustotal_api_key:
        vt = _vt_enrich(ioc, config.virustotal_api_key, config)
        if vt is not None:
            output.append(vt)

    mb = _malwarebazaar_enrich(ioc, config, config.malwarebazaar_api_key)
    if mb is not None:
        output.append(mb)

    if config.abuseipdb_api_key:
        abuse = _abuseipdb_enrich(ioc, config.abuseipdb_api_key, config)
        if abuse is not None:
            output.append(abuse)

    if config.enable_whois_lookup:
        whois = _rdap_whois_enrich(ioc, config)
        if whois is not None:
            output.append(whois)

    return output
