"""Autonomous drop-folder watcher.

Polls a directory every ``interval`` seconds.  For each new disk image or
subdirectory it:
  1. Derives a valid case ID from the filename stem.
  2. Calls ``service.process_drop_item()``.
  3. Records the result in ``.af_processed.json`` so items are not reprocessed.
"""
from __future__ import annotations

import json
import logging
import re
import signal
import time
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)

# Mirror DISK_IMAGE_EXTENSIONS without importing disk_image at module level
# (disk_image has heavy optional deps that may not be present)
IMAGE_EXTENSIONS: frozenset[str] = frozenset(
    {".e01", ".dd", ".img", ".raw", ".vmdk", ".vhd", ".vhdx", ".aff"}
)

_REGISTRY_FILENAME = ".af_processed.json"

# Allowed characters in a case ID
_SAFE_CHAR_RE = re.compile(r"[^A-Za-z0-9._-]")
# Must start with an alphanumeric character
_LEADING_NON_ALNUM_RE = re.compile(r"^[^A-Za-z0-9]+")


def derive_case_id(stem: str) -> str:
    """Convert an arbitrary filename stem into a valid auto-forensics case ID.

    Rules:
    - Keep only ``[A-Za-z0-9._-]`` characters.
    - Strip leading non-alphanumeric characters.
    - Truncate to 64 characters.
    - Prepend ``af-`` if the result is empty or still starts with a non-alnum.
    """
    cleaned = _SAFE_CHAR_RE.sub("", stem)
    cleaned = _LEADING_NON_ALNUM_RE.sub("", cleaned)
    cleaned = cleaned[:64]
    if not cleaned or not cleaned[0].isalnum():
        cleaned = "af-" + cleaned
    # Minimum length is 2
    if len(cleaned) < 2:
        cleaned = "af-" + cleaned
    return cleaned


# ---------------------------------------------------------------------------
# Processed registry
# ---------------------------------------------------------------------------


class ProcessedRegistry:
    """Persistent set of already-processed drop items.

    Backed by a JSON file in *drop_dir*.  Safe for single-threaded use.
    """

    def __init__(self, drop_dir: Path) -> None:
        self._path = drop_dir / _REGISTRY_FILENAME
        self._data: dict[str, dict[str, Any]] = self._load()

    def _load(self) -> dict[str, dict[str, Any]]:
        if not self._path.exists():
            return {}
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                return raw
        except (json.JSONDecodeError, OSError):
            pass
        return {}

    def _save(self) -> None:
        try:
            self._path.write_text(
                json.dumps(self._data, indent=2), encoding="utf-8"
            )
        except OSError as exc:
            logger.warning("Failed to save processed registry %s: %s", self._path, exc)

    def is_processed(self, name: str) -> bool:
        return name in self._data

    def mark_processed(
        self,
        name: str,
        case_id: str,
        status: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        self._data[name] = {
            "case_id": case_id,
            "status": status,
            "details": details or {},
        }
        self._save()

    def all_entries(self) -> dict[str, dict[str, Any]]:
        return dict(self._data)


# ---------------------------------------------------------------------------
# Drop watcher
# ---------------------------------------------------------------------------


class DropWatcher:
    """Poll *drop_dir* and auto-process new disk images and directories.

    Parameters
    ----------
    service:
        An ``AutoForensicsService`` instance used to create/ingest/analyze cases.
    drop_dir:
        Directory to watch.
    interval:
        Poll interval in seconds.
    enable_llm:
        Whether to enable LLM analysis.
    auto_extract:
        Whether to attempt disk image mounting for image files.
    """

    def __init__(
        self,
        service: Any,
        drop_dir: Path,
        interval: int = 30,
        enable_llm: bool = True,
        auto_extract: bool = True,
    ) -> None:
        self._service = service
        self._drop_dir = Path(drop_dir)
        self._interval = max(5, int(interval))
        self._enable_llm = enable_llm
        self._auto_extract = auto_extract
        self._stop = False
        self._registry = ProcessedRegistry(self._drop_dir)
        self._processed_count = 0
        self._last_item: str | None = None

    def stop(self) -> None:
        """Signal the watcher to exit on the next poll cycle."""
        self._stop = True

    def run(
        self,
        *,
        live_display_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        """Poll forever (blocking).  Calls *live_display_callback* after each cycle.

        Installs SIGINT / SIGTERM handlers to stop cleanly on Ctrl+C.
        """
        original_sigint = signal.getsignal(signal.SIGINT)
        original_sigterm = signal.getsignal(signal.SIGTERM)

        def _stop_handler(signum: int, frame: object) -> None:
            logger.info("DropWatcher received signal %d — stopping after current cycle.", signum)
            self._stop = True

        signal.signal(signal.SIGINT, _stop_handler)
        signal.signal(signal.SIGTERM, _stop_handler)

        try:
            self._poll_loop(live_display_callback=live_display_callback)
        finally:
            signal.signal(signal.SIGINT, original_sigint)
            signal.signal(signal.SIGTERM, original_sigterm)

    def _poll_loop(
        self,
        live_display_callback: Callable[[dict[str, Any]], None] | None,
    ) -> None:
        while not self._stop:
            self._scan_once()
            status = {
                "processed": self._processed_count,
                "last_item": self._last_item,
                "drop_dir": str(self._drop_dir),
                "interval": self._interval,
            }
            if live_display_callback is not None:
                try:
                    live_display_callback(status)
                except Exception:
                    pass
            # Sleep in small increments so we can respond to stop() promptly
            for _ in range(self._interval * 2):
                if self._stop:
                    break
                time.sleep(0.5)

    def _scan_once(self) -> None:
        """Single scan pass — process any new items in drop_dir."""
        if not self._drop_dir.exists():
            logger.debug("Drop dir does not exist yet: %s", self._drop_dir)
            return

        try:
            entries = list(self._drop_dir.iterdir())
        except OSError as exc:
            logger.warning("Cannot list drop dir %s: %s", self._drop_dir, exc)
            return

        for entry in sorted(entries, key=lambda p: p.name):
            name = entry.name
            # Skip hidden files and the registry file itself
            if name.startswith(".") or name == _REGISTRY_FILENAME:
                continue
            if self._registry.is_processed(name):
                continue

            # Check if it is a disk image or directory
            is_image = entry.is_file() and entry.suffix.lower() in IMAGE_EXTENSIONS
            is_dir = entry.is_dir()
            if not is_image and not is_dir:
                continue

            case_id = derive_case_id(entry.stem if entry.is_file() else entry.name)
            logger.info(
                "DropWatcher: processing new item '%s' as case %s", name, case_id
            )
            try:
                result = self._service.process_drop_item(
                    entry,
                    case_id,
                    enable_llm=self._enable_llm,
                    auto_extract=self._auto_extract,
                )
                self._registry.mark_processed(name, case_id, "success", details=result)
                self._processed_count += 1
                self._last_item = name
                logger.info(
                    "DropWatcher: finished case %s — %s finding(s)",
                    case_id,
                    result.get("findings", 0),
                )
            except Exception as exc:
                logger.error(
                    "DropWatcher: error processing '%s': %s", name, exc
                )
                self._registry.mark_processed(
                    name, case_id, "error", details={"error": str(exc)}
                )
