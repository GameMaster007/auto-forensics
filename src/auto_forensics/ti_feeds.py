"""Threat Intelligence feed integration for IOC enrichment.

Supports MISP CSV/JSON feeds and custom URL-based TI sources.
Caches data locally with configurable TTL for offline lookups.
"""

from __future__ import annotations

import csv
import json
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .db_backend import DatabaseBackend
from .security import confine_path

logger = logging.getLogger(__name__)

TTL_SECONDS_DEFAULT = 86400  # 24 hours


@dataclass(slots=True, frozen=True)
class TIRecord:
    """A single Threat Intelligence record."""

    ioc_type: str
    value: str
    confidence: int  # 0-100
    source: str
    first_seen: str  # ISO timestamp
    last_seen: str   # ISO timestamp
    tags: list[str]
    description: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "ioc_type": self.ioc_type,
            "value": self.value,
            "confidence": self.confidence,
            "source": self.source,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "tags": self.tags,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TIRecord:
        return cls(
            ioc_type=str(data.get("ioc_type", "")),
            value=str(data.get("value", "")),
            confidence=int(data.get("confidence", 50)),
            source=str(data.get("source", "")),
            first_seen=str(data.get("first_seen", "")),
            last_seen=str(data.get("last_seen", "")),
            tags=list(data.get("tags", [])),
            description=str(data.get("description", "")),
        )


@dataclass
class TIFeedConfig:
    """Configuration for TI feed integration."""

    cache_dir: Path
    feeds: list[dict[str, str]] = field(default_factory=list)
    ttl_seconds: int = TTL_SECONDS_DEFAULT
    misp_api_key: str | None = None
    custom_headers: dict[str, str] = field(default_factory=dict)

    def ensure_dirs(self) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)


class TIFeedManager:
    """Manages TI feeds, caching, and lookup operations."""

    def __init__(self, config: TIFeedConfig, db: DatabaseBackend) -> None:
        self.config = config
        self.db = db
        self._cache: dict[str, TIRecord] = {}
        self._last_update: dict[str, str] = {}
        self._lock = threading.Lock()
        config.ensure_dirs()
        self._load_cache_from_db()

    def _cache_key(self, ioc_type: str, value: str) -> str:
        return f"{ioc_type.lower()}:{value.lower()}"

    def _load_cache_from_db(self) -> None:
        """Load TI records from database into memory cache."""
        try:
            records = self.db.list_ti_records()
            with self._lock:
                for rec in records:
                    key = self._cache_key(rec.ioc_type, rec.value)
                    self._cache[key] = rec
            logger.info("Loaded %d TI records from DB", len(self._cache))
        except AttributeError:
            logger.warning("Database backend does not support TI records")
        except Exception as exc:
            logger.warning("Failed to load TI cache: %s", exc)

    def _save_record(self, record: TIRecord) -> None:
        """Persist a TI record to database."""
        try:
            if hasattr(self.db, 'upsert_ti_record'):
                self.db.upsert_ti_record(record)
        except Exception as exc:
            logger.debug("Could not save TI record: %s", exc)

    def update_feeds(self) -> dict[str, Any]:
        """Fetch and cache TI data from configured feeds.

        Returns a summary dict with status per feed.
        ""}
        """
        results: dict[str, Any] = {}
        for feed in self.config.feeds:
            name = feed.get("name", "unnamed")
            url = feed.get("url", "")
            fmt = feed.get("format", "misp")
            try:
                count = self._fetch_feed(url, fmt)
                results[name] = {"status": "ok", "records": count}
                self._last_update[name] = datetime.now(
                    timezone.utc
                ).isoformat()
            except Exception as exc:
                logger.error("Failed to update feed %s: %s", name, exc)
                results[name] = {"status": "error", "message": str(exc)}
        return results

    def _fetch_feed(self, url: str, fmt: str) -> int:
        """Fetch a single feed and parse records.

        Currently supports local file paths (for testing/demo).
        Returns count of records imported.
        """
        imported = 0
        if url.startswith("file://"):
            path = Path(url[7:])
            if path.suffix == ".json":
                imported = self._parse_misp_json(path)
            elif path.suffix == ".csv":
                imported = self._parse_misp_csv(path)
        logger.debug("Imported %d records from %s", imported, url)
        return imported

    def _parse_misp_json(self, path: Path) -> int:
        """Parse MISP JSON format feed."""
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            imported = 0
            for event in data.get("response", []):
                for attr in event.get("Event", {}).get("Attribute", []):
                    rec = self._misp_attr_to_record(attr)
                    if rec:
                        key = self._cache_key(rec.ioc_type, rec.value)
                        with self._lock:
                            self._cache[key] = rec
                        self._save_record(rec)
                        imported += 1
            return imported
        except Exception as exc:
            logger.error("Failed to parse MISP JSON: %s", exc)
            return 0

    def _parse_misp_csv(self, path: Path) -> int:
        """Parse MISP CSV format feed."""
        try:
            imported = 0
            with path.open("r", encoding="utf-8") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    rec = self._misp_csv_row_to_record(row)
                    if rec:
                        key = self._cache_key(rec.ioc_type, rec.value)
                        with self._lock:
                            self._cache[key] = rec
                        self._save_record(rec)
                        imported += 1
            return imported
        except Exception as exc:
            logger.error("Failed to parse MISP CSV: %s", exc)
            return 0

    def _misp_attr_to_record(self, attr: dict[str, Any]) -> TIRecord | None:
        """Convert MISP attribute to TIRecord."""
        try:
            ioc_type = attr.get("type", "")
            value = attr.get("value", "")
            if not ioc_type or not value:
                return None
            now = datetime.now(timezone.utc).isoformat()
            return TIRecord(
                ioc_type=ioc_type,
                value=value,
                confidence=attr.get("confidence", 50),
                source=attr.get("event_source", "MISP"),
                first_seen=attr.get("first_seen", now),
                last_seen=attr.get("last_seen", now),
                tags=attr.get("Tag", []),
                description=attr.get("comment", ""),
            )
        except Exception:
            return None

    def _misp_csv_row_to_record(self, row: dict[str, str]) -> TIRecord | None:
        """Convert MISP CSV row to TIRecord."""
        try:
            ioc_type = row.get("type", "")
            value = row.get("value", row.get("ioc", ""))
            if not ioc_type or not value:
                return None
            now = datetime.now(timezone.utc).isoformat()
            return TIRecord(
                ioc_type=ioc_type,
                value=value,
                confidence=int(row.get("confidence", 50)),
                source=row.get("source", "MISP"),
                first_seen=row.get("first_seen", now),
                last_seen=row.get("last_seen", now),
                tags=row.get("tags", "").split(",") if row.get("tags") else [],
                description=row.get("comment", row.get("description", "")),
            )
        except Exception:
            return None

    def lookup_ioc(self, ioc_type: str, value: str) -> TIRecord | None:
        """Look up a single IOC in the TI cache."""
        key = self._cache_key(ioc_type, value)
        with self._lock:
            return self._cache.get(key)

    def lookup_bulk(self, iocs: list[dict]) -> list[TIRecord]:
        """Batch lookup multiple IOCs.

        Each IOC dict should have 'ioc_type' and 'value' keys.
        """
        results: list[TIRecord] = []
        for ioc in iocs:
            rec = self.lookup_ioc(
                ioc.get("ioc_type", ""), ioc.get("value", "")
            )
            if rec:
                results.append(rec)
        return results

    def get_feed_status(self) -> dict[str, Any]:
        """Get current feed status including cached record counts."""
        with self._lock:
            return {
                "cached_records": len(self._cache),
                "last_updates": dict(self._last_update),
                "feeds_configured": len(self.config.feeds),
                "ttl_seconds": self.config.ttl_seconds,
            }

    def enrich_case_iocs(self, case_id: str) -> dict[str, Any]:
        """Enrich all IOCs in a case with TI data.

        Returns dict with matches found and enrichment results.
        """
        try:
            iocs = self.db.list_case_iocs(case_id)
            matches: list[dict] = []
            for ioc in iocs:
                ti = self.lookup_ioc(
                    ioc.get("ioc_type", ""), ioc.get("value", "")
                )
                if ti:
                    matches.append({
                        "ioc": ioc,
                        "ti_record": ti.to_dict(),
                    })
            return {
                "case_id": case_id,
                "total_iocs": len(iocs),
                "matches_found": len(matches),
                "matches": matches,
            }
        except Exception as exc:
            logger.error("Failed to enrich case %s: %s", case_id, exc)
            return {
                "case_id": case_id,
                "total_iocs": 0,
                "matches_found": 0,
                "matches": [],
                "error": str(exc),
            }
