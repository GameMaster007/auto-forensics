"""Threat intelligence correlation engine for Auto Forensics.

Correlates extracted IOCs against multiple threat intelligence feeds
and provides risk scoring based on TI data.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class TICorrelationResult:
    """Result of TI correlation for a single IOC."""
    ioc_value: str
    ioc_type: str
    feed_name: str
    threat_type: str | None
    confidence: int  # 0-100
    first_seen: str | None
    last_seen: str | None
    tags: list[str]
    raw_data: dict[str, Any]


@dataclass(slots=True)
class ThreatActorInfo:
    """Information about a threat actor from TI feeds."""
    actor_name: str
    aliases: list[str]
    description: str
    mitre_groups: list[str]
    attribution: list[str]


class ThreatIntelCorrelator:
    """Correlates IOCs against threat intelligence feeds."""

    # Known threat actor names and patterns
    THREAT_ACTORS: dict[str, ThreatActorInfo] = {
        "apt28": ThreatActorInfo(
            actor_name="APT28",
            aliases=["Fancy Bear", "Sofacy", "Strontium", "TSAR TEAM"],
            description="Russian state-sponsored APT group",
            mitre_groups=["G0007"],
            attribution=["Russia", "GRU"],
        ),
        "apt29": ThreatActorInfo(
            actor_name="APT29",
            aliases=["Cozy Bear", "The Dukes", "CozyDuke"],
            description="Russian state-sponsored APT group",
            mitre_groups=["G0016"],
            attribution=["Russia", "SVR"],
        ),
        "lazarus": ThreatActorInfo(
            actor_name="Lazarus Group",
            aliases=["Guardians of Peace", "ZINC", "Hidden Cobra"],
            description="North Korean state-sponsored APT group",
            mitre_groups=["G0032"],
            attribution=["North Korea", "Bureau 121"],
        ),
    }

    def __init__(
        self,
        feeds_config: dict[str, dict[str, Any]] | None = None,
        cache_dir: Path | None = None,
    ) -> None:
        """Initialize the correlator with feed configurations.

        Args:
            feeds_config: Dict mapping feed names to their config dicts.
                Each config should have 'url', 'api_key' (optional),
                'enabled' (bool), and 'cache_ttl_minutes'.
            cache_dir: Directory to cache TI data.
        """
        self.feeds_config = feeds_config or {}
        self.cache_dir = cache_dir
        self._cache: dict[str, tuple[datetime, dict[str, Any]]] = {}

    def correlate_iocs(
        self,
        iocs: list[dict[str, Any]],
        feeds: list[str] | None = None,
    ) -> list[TICorrelationResult]:
        """Correlate a list of IOCs against enabled TI feeds.

        Args:
            iocs: List of IOC dicts with 'value' and 'type' keys.
            feeds: Specific feeds to use (None = all enabled).

        Returns:
            List of correlation results.
        """
        results: list[TICorrelationResult] = []
        enabled_feeds = [
            name for name, cfg in self.feeds_config.items()
            if cfg.get("enabled", True) and (feeds is None or name in feeds)
        ]

        for ioc in iocs:
            ioc_value = str(ioc.get("value", ""))
            ioc_type = str(ioc.get("type", "unknown"))

            for feed_name in enabled_feeds:
                feed_results = self._check_feed(feed_name, ioc_value, ioc_type)
                results.extend(feed_results)

        return results

    def _check_feed(
        self,
        feed_name: str,
        ioc_value: str,
        ioc_type: str,
    ) -> list[TICorrelationResult]:
        """Check an IOC against a specific feed."""
        config = self.feeds_config.get(feed_name)
        if not config:
            return []

        try:
            if feed_name == "alienvault_otx":
                return self._check_alienvault_otx(config, ioc_value, ioc_type)
            elif feed_name == "misp":
                return self._check_misp(config, ioc_value, ioc_type)
            elif feed_name == "abuse_ch":
                return self._check_abuse_ch(config, ioc_value, ioc_type)
            elif feed_name == "local_cache":
                return self._check_local_cache(config, ioc_value, ioc_type)
        except Exception as exc:
            logger.warning("TI feed %s check failed for %s: %s", feed_name, ioc_value, exc)

        return []

    def _check_alienvault_otx(
        self,
        config: dict[str, Any],
        ioc_value: str,
        ioc_type: str,
    ) -> list[TICorrelationResult]:
        """Check IOC against AlienVault OTX."""
        api_key = config.get("api_key")
        if not api_key:
            return []

        # Check cache first
        cache_key = f"otx:{ioc_value}"
        if cache_key in self._cache:
            cache_time, cached_data = self._cache[cache_key]
            ttl = config.get("cache_ttl_minutes", 60)
            if (datetime.now(timezone.utc) - cache_time).seconds < ttl * 60:
                return self._parse_otx_response(ioc_value, ioc_type, cached_data)

        url = f"https://otx.alienvault.com/api/v1/indicators/{ioc_type}/{ioc_value}/general"
        headers = {"X-OTX-API-KEY": api_key}

        try:
            req = Request(url, headers=headers)
            with urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                self._cache[cache_key] = (datetime.now(timezone.utc), data)
                return self._parse_otx_response(ioc_value, ioc_type, data)
        except HTTPError as e:
            if e.code == 404:
                return []  # Not found = no threat intel
            raise

    def _parse_otx_response(
        self,
        ioc_value: str,
        ioc_type: str,
        data: dict[str, Any],
    ) -> list[TICorrelationResult]:
        """Parse AlienVault OTX response."""
        results = []

        pulse_info = data.get("pulse_info", {})
        pulses = pulse_info.get("pulses", [])

        if pulses:
            # Calculate confidence based on number of pulses
            confidence = min(50 + len(pulses) * 10, 100)

            # Collect tags from all pulses
            all_tags: set[str] = set()
            for pulse in pulses:
                all_tags.update(pulse.get("tags", []))

            results.append(TICorrelationResult(
                ioc_value=ioc_value,
                ioc_type=ioc_type,
                feed_name="AlienVault OTX",
                threat_type=self._classify_threat_type(all_tags),
                confidence=confidence,
                first_seen=pulses[0].get("created"),
                last_seen=pulses[-1].get("modified"),
                tags=list(all_tags)[:20],  # Limit tags
                raw_data=data,
            ))

        return results

    def _check_misp(
        self,
        config: dict[str, Any],
        ioc_value: str,
        ioc_type: str,
    ) -> list[TICorrelationResult]:
        """Check IOC against MISP instance."""
        base_url = config.get("url", "").rstrip("/")
        api_key = config.get("api_key")

        if not base_url or not api_key:
            return []

        # Map our IOC types to MISP types
        misp_type = self._to_misp_type(ioc_type)

        url = f"{base_url}/attributes/restSearch"
        headers = {
            "Authorization": api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        body = json.dumps({
            "returnFormat": "json",
            "type": misp_type,
            "value": ioc_value,
        })

        req = Request(url, data=body.encode(), headers=headers, method="POST")
        with urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return self._parse_misp_response(ioc_value, ioc_type, data)

    def _parse_misp_response(
        self,
        ioc_value: str,
        ioc_type: str,
        data: dict[str, Any],
    ) -> list[TICorrelationResult]:
        """Parse MISP response."""
        results = []
        attributes = data.get("response", {}).get("Attribute", [])

        if attributes:
            # Collect tags and event info
            all_tags: set[str] = set()
            threat_levels: list[int] = []

            for attr in attributes:
                all_tags.update(attr.get("Tag", []))
                event = attr.get("Event", {})
                threat_levels.append(event.get("threat_level_id", 4))

            # Calculate confidence from threat levels (lower is more severe)
            avg_threat = sum(threat_levels) / len(threat_levels)
            confidence = max(100 - int(avg_threat) * 20, 10)

            results.append(TICorrelationResult(
                ioc_value=ioc_value,
                ioc_type=ioc_type,
                feed_name="MISP",
                threat_type=self._classify_threat_type(all_tags),
                confidence=confidence,
                first_seen=attributes[0].get("timestamp"),
                last_seen=attributes[-1].get("timestamp"),
                tags=list(all_tags)[:20],
                raw_data=data,
            ))

        return results

    def _check_abuse_ch(
        self,
        config: dict[str, Any],
        ioc_value: str,
        ioc_type: str,
    ) -> list[TICorrelationResult]:
        """Check IOC against Abuse.ch feeds."""
        results = []

        # Check MalwareBazaar for file hashes
        if ioc_type == "hash" and len(ioc_value) in [32, 64]:
            results.extend(self._check_malwarebazaar(config, ioc_value))

        # Check ThreatFox for IOCs
        if ioc_type in ["ip", "domain", "url"]:
            results.extend(self._check_threatfox(config, ioc_value, ioc_type))

        return results

    def _check_malwarebazaar(
        self,
        config: dict[str, Any],
        file_hash: str,
    ) -> list[TICorrelationResult]:
        """Check hash against MalwareBazaar."""
        url = "https://mb-api.abuse.ch/api/v1/"
        data = f"query=get_info&hash={file_hash}"

        req = Request(
            url,
            data=data.encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )

        with urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode("utf-8"))

            if result.get("query_status") == "ok" and result.get("data"):
                sample = result["data"][0]
                return [TICorrelationResult(
                    ioc_value=file_hash,
                    ioc_type="hash",
                    feed_name="MalwareBazaar",
                    threat_type="malware",
                    confidence=90,
                    first_seen=sample.get("first_seen"),
                    last_seen=sample.get("last_seen"),
                    tags=[sample.get("signature", "unknown")],
                    raw_data=result,
                )]

        return []

    def _check_threatfox(
        self,
        config: dict[str, Any],
        ioc_value: str,
        ioc_type: str,
    ) -> list[TICorrelationResult]:
        """Check IOC against ThreatFox."""
        url = "https://threatfox-api.abuse.ch/api/v1/"
        body = json.dumps({
            "query": "search_ioc",
            "search_term": ioc_value,
        })

        req = Request(
            url,
            data=body.encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read().decode("utf-8"))

                if result.get("query_status") == "ok" and result.get("data"):
                    ioc_data = result["data"][0]
                    return [TICorrelationResult(
                        ioc_value=ioc_value,
                        ioc_type=ioc_type,
                        feed_name="ThreatFox",
                        threat_type=ioc_data.get("threat_type", "unknown"),
                        confidence=min(ioc_data.get("confidence_level", 50), 100),
                        first_seen=ioc_data.get("first_seen"),
                        last_seen=ioc_data.get("last_seen"),
                        tags=[ioc_data.get("malware", "unknown")],
                        raw_data=result,
                    )]
        except HTTPError as e:
            if e.code == 404:
                return []
            raise

        return []

    def _check_local_cache(
        self,
        config: dict[str, Any],
        ioc_value: str,
        ioc_type: str,
    ) -> list[TICorrelationResult]:
        """Check IOC against local cache file."""
        cache_file = Path(config.get("path", "ti_cache.json"))
        if not cache_file.exists():
            return []

        try:
            data = json.loads(cache_file.read_text())
            iocs = data.get("iocs", {})

            if ioc_value in iocs:
                entry = iocs[ioc_value]
                return [TICorrelationResult(
                    ioc_value=ioc_value,
                    ioc_type=ioc_type,
                    feed_name="Local Cache",
                    threat_type=entry.get("threat_type"),
                    confidence=entry.get("confidence", 50),
                    first_seen=entry.get("first_seen"),
                    last_seen=entry.get("last_seen"),
                    tags=entry.get("tags", []),
                    raw_data=entry,
                )]
        except (json.JSONDecodeError, OSError):
            pass

        return []

    def _to_misp_type(self, ioc_type: str) -> str:
        """Convert internal IOC type to MISP attribute type."""
        mapping = {
            "ip": "ip-dst",
            "domain": "domain",
            "url": "url",
            "hash": "sha256",
            "md5": "md5",
            "sha1": "sha1",
            "sha256": "sha256",
        }
        return mapping.get(ioc_type.lower(), ioc_type)

    def _classify_threat_type(self, tags: set[str]) -> str | None:
        """Classify threat type from tags."""
        tag_str = " ".join(tags).lower()

        classifications = [
            ("apt", "apt"),
            ("ransomware", "ransomware"),
            ("trojan", "trojan"),
            ("malware", "malware"),
            ("phishing", "phishing"),
            ("c2", "c2-server"),
            ("botnet", "botnet"),
            ("miner", "cryptominer"),
        ]

        for keyword, classification in classifications:
            if keyword in tag_str:
                return classification

        return None

    def get_threat_actor_info(self, actor_name: str) -> ThreatActorInfo | None:
        """Get information about a threat actor."""
        actor_lower = actor_name.lower()

        for key, info in self.THREAT_ACTORS.items():
            if key == actor_lower or actor_lower in [a.lower() for a in info.aliases]:
                return info

        return None

    def correlate_case_with_ti(
        self,
        case_id: str,
        ioc_pipeline_func: callable,
    ) -> dict[str, Any]:
        """Correlate all IOCs from a case with threat intelligence.

        Args:
            case_id: The case ID to correlate.
            ioc_pipeline_func: Function that extracts IOCs from the case.

        Returns:
            Dict with correlation results and summary.
        """
        iocs = ioc_pipeline_func(case_id)
        results = self.correlate_iocs(iocs)

        # Group by threat type
        by_threat: dict[str, list[TICorrelationResult]] = {}
        for r in results:
            threat = r.threat_type or "unknown"
            by_threat.setdefault(threat, []).append(r)

        # Calculate overall risk score
        total_iocs = len(iocs)
        malicious_iocs = len(set(r.ioc_value for r in results))
        risk_score = min((malicious_iocs / max(total_iocs, 1)) * 100, 100)

        # Check for threat actor associations
        threat_actors: set[str] = set()
        for r in results:
            for tag in r.tags:
                actor = self.get_threat_actor_info(tag)
                if actor:
                    threat_actors.add(actor.actor_name)

        return {
            "case_id": case_id,
            "total_iocs": total_iocs,
            "malicious_iocs": malicious_iocs,
            "risk_score": round(risk_score, 2),
            "threat_actors": list(threat_actors),
            "threat_types": {
                threat: len(items) for threat, items in by_threat.items()
            },
            "correlations": [
                {
                    "ioc": r.ioc_value,
                    "type": r.ioc_type,
                    "feed": r.feed_name,
                    "threat_type": r.threat_type,
                    "confidence": r.confidence,
                    "tags": r.tags[:10],
                }
                for r in results[:100]  # Limit detailed results
            ],
        }
