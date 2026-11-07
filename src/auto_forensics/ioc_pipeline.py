from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import asdict
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .citations import citation_for_binary
from .models import IOC, BinaryFeature, Citation, Finding, TimelineEvent
from .verifier import claim_lines

URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b")
HASH_RE = re.compile(r"\b(?:[A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})\b")
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
    digest = hashlib.sha256(f"{ioc_type}:{value}".encode("utf-8")).hexdigest()[:24]
    return f"ioc-{digest}"


def normalize_ioc_value(ioc_type: str, value: str) -> str | None:
    """Normalize only case-insensitive components; retain URL path/query case."""
    if not isinstance(value, str) or not value.strip():
        return None
    value = value.strip()
    if ioc_type == "url":
        if any(ord(char) <= 32 for char in value):
            return None
        try:
            parsed = urlsplit(value)
            if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
                return None
            host = parsed.hostname.encode("idna").decode("ascii").lower()
            if ":" in host:
                host = f"[{ipaddress.ip_address(host).compressed}]"
            credentials = parsed.netloc.rsplit("@", 1)[0] + "@" if "@" in parsed.netloc else ""
            port = f":{parsed.port}" if parsed.port is not None else ""
            return urlunsplit((parsed.scheme.lower(), credentials + host + port, parsed.path, parsed.query, parsed.fragment))
        except (ValueError, UnicodeError):
            return None
    if ioc_type == "ip":
        try:
            address = ipaddress.ip_address(value)
            return str(address) if "%" not in value else None
        except ValueError:
            return None
    if ioc_type in {"sha256", "sha1", "md5", "hash"}:
        sizes = {"sha256": {64}, "sha1": {40}, "md5": {32}, "hash": {32, 40, 64}}
        return value.lower() if len(value) in sizes[ioc_type] and re.fullmatch(r"[A-Fa-f0-9]+", value) else None
    if ioc_type == "domain":
        try:
            domain = value.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError:
            return None
        return domain if len(domain) <= 253 and DOMAIN_RE.fullmatch(domain) else None
    return value


def _add_ioc(
    sink: dict[tuple[str, str], IOC],
    ioc_type: str,
    value: str,
    source: str,
    metadata: dict[str, Any] | None = None,
) -> str | None:
    if ioc_type == "hash":
        ioc_type = {32: "md5", 40: "sha1", 64: "sha256"}.get(len(value), "hash")
    normalized = normalize_ioc_value(ioc_type, value)
    if not normalized:
        return None
    key = (ioc_type, normalized)
    if key not in sink:
        sink[key] = IOC(
            ioc_id=_canonical_ioc_id(ioc_type, normalized),
            ioc_type=ioc_type,
            value=normalized,
            sources=[source],
            metadata=metadata or {},
        )
        return sink[key].ioc_id

    item = sink[key]
    if source not in item.sources:
        item.sources.append(source)
    if metadata:
        for field_name, field_value in metadata.items():
            if field_name in {"citations", "paths"}:
                combined = [*(item.metadata.get(field_name) or []), *field_value]
                unique = {json.dumps(entry, sort_keys=True): entry for entry in combined}
                item.metadata[field_name] = [unique[key] for key in sorted(unique)]
            else:
                item.metadata[field_name] = field_value
    return item.ioc_id


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
        provenance = {"paths": [binary.path], "citations": [asdict(citation_for_binary(binary))]}
        _add_ioc(out, "sha256", binary.sha256, source="binary_analysis", metadata=provenance.copy())
        _add_ioc(out, "md5", binary.md5, source="binary_analysis", metadata=provenance.copy())
        for value in binary.string_hits:
            for ioc_type, values in _extract_from_text(value).items():
                for item in values:
                    _add_ioc(out, ioc_type, item, source="binary_string", metadata=provenance.copy())

    for finding in findings:
        finding.ioc_refs = []
        if not finding.citations or not all(citation.is_complete() for citation in finding.citations):
            continue
        # Titles and recommendations are analyst/model interpretation. Only
        # cited evidence sentences contribute observations from a finding.
        for line in claim_lines(finding):
            for ioc_type, values in _extract_from_text(line).items():
                for item in values:
                    reference = _add_ioc(out, ioc_type, item, source=f"finding:{finding.finding_id}",
                                         metadata={"citations": [asdict(citation) for citation in finding.citations]})
                    if reference:
                        finding.ioc_refs.append(reference)
        finding.ioc_refs = sorted(set(finding.ioc_refs))

    for event in timeline:
        raw = event.related.get("citation")
        try:
            citation = Citation(**raw) if isinstance(raw, dict) else None
        except TypeError:
            continue
        if citation is None or not citation.is_complete() or "artifact" not in event.tags:
            continue
        chunks: list[str] = [event.description]
        for key in ("query", "host", "source_host", "source_ip", "tls_sni", "dst_ip", "src_ip", "path", "command"):
            field_value = event.related.get(key)
            if field_value:
                chunks.append(str(field_value))
        for ioc_type, values in _extract_from_text(" ".join(chunks)).items():
            for item in values:
                _add_ioc(out, ioc_type, item, source=f"timeline:{event.event_type}", metadata={"citations": [asdict(citation)]})

    return sorted(out.values(), key=lambda item: (item.ioc_type, item.value.lower(), item.value))
