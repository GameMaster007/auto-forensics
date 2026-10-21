from __future__ import annotations

import hashlib
import ipaddress
import re
from typing import Any

from .models import IOC, BinaryFeature, Finding, TimelineEvent

URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b")
HASH_RE = re.compile(r"\b[A-Fa-f0-9]{32,64}\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# File extensions that are commonly mistaken as domain TLDs.
_DOMAIN_EXTENSION_BLOCKLIST = frozenset({
    "exe", "dll", "sys", "bin", "bat", "cmd", "ps1", "vbs",
    "log", "txt", "csv", "xml", "json", "zip", "tar", "gz",
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "lnk", "pf", "mft", "hiv", "hive", "dmp", "mem", "raw",
})

# Maximum text length to run regex extraction against to bound CPU/memory.
_MAX_IOC_TEXT_BYTES = 4 * 1024 * 1024


def _canonical_ioc_id(ioc_type: str, value: str) -> str:
    digest = hashlib.sha1(f"{ioc_type}:{value.lower()}".encode("utf-8")).hexdigest()[:16]
    return f"ioc-{digest}"


def _add_ioc(
    sink: dict[tuple[str, str], IOC],
    ioc_type: str,
    value: str,
    source: str,
    metadata: dict[str, Any] | None = None,
) -> None:
    normalized = value.strip()
    if not normalized:
        return
    key = (ioc_type, normalized.lower())
    if key not in sink:
        sink[key] = IOC(
            ioc_id=_canonical_ioc_id(ioc_type, normalized),
            ioc_type=ioc_type,
            value=normalized,
            sources=[source],
            metadata=metadata or {},
        )
        return

    item = sink[key]
    if source not in item.sources:
        item.sources.append(source)
    if metadata:
        item.metadata.update(metadata)


def _is_valid_ipv4(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _extract_from_text(text: str) -> dict[str, set[str]]:
    # Guard against massive strings that would make regex scanning very slow.
    if len(text) > _MAX_IOC_TEXT_BYTES:
        text = text[:_MAX_IOC_TEXT_BYTES]

    urls: set[str] = set()
    for raw_url in URL_RE.findall(text):
        # Strip trailing punctuation characters that appear at URL boundaries in prose.
        cleaned = raw_url.rstrip(".,;):\"'>]")
        if cleaned:
            urls.add(cleaned)

    hashes = {x.lower() for x in HASH_RE.findall(text)}
    ips = {x for x in IP_RE.findall(text) if _is_valid_ipv4(x)}

    domains: set[str] = set()
    for raw_domain in DOMAIN_RE.findall(text):
        lower = raw_domain.lower()
        # Skip if the TLD (last label) is a common file extension or all-digit label.
        tld = lower.rsplit(".", 1)[-1]
        if tld in _DOMAIN_EXTENSION_BLOCKLIST:
            continue
        if lower.replace(".", "").isdigit():
            continue
        domains.add(lower)

    return {
        "url": urls,
        "hash": hashes,
        "ip": ips,
        "domain": domains,
    }


def extract_iocs(
    binary_features: list[BinaryFeature],
    findings: list[Finding],
    timeline: list[TimelineEvent],
) -> list[IOC]:
    out: dict[tuple[str, str], IOC] = {}

    for binary in binary_features:
        _add_ioc(out, "sha256", binary.sha256, source="binary_analysis", metadata={"path": binary.path})
        _add_ioc(out, "md5", binary.md5, source="binary_analysis", metadata={"path": binary.path})
        for value in binary.string_hits:
            for ioc_type, values in _extract_from_text(value).items():
                for item in values:
                    _add_ioc(out, ioc_type, item, source="binary_string")

    for finding in findings:
        joined = " ".join([finding.title, finding.recommendation, *finding.evidence])
        for ioc_type, values in _extract_from_text(joined).items():
            for item in values:
                _add_ioc(out, ioc_type, item, source=f"finding:{finding.finding_id}")

    for event in timeline:
        chunks: list[str] = [event.description]
        chunks.extend(str(v) for v in event.related.values())
        for key in ("query", "host", "tls_sni", "dst_ip", "src_ip", "path", "command"):
            value = event.related.get(key)
            if value:
                chunks.append(str(value))
        for ioc_type, values in _extract_from_text(" ".join(chunks)).items():
            for item in values:
                _add_ioc(out, ioc_type, item, source=f"timeline:{event.event_type}")

    return sorted(out.values(), key=lambda item: (item.ioc_type, item.value.lower()))
