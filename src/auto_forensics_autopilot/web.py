"""Local review page for the autopilot.

    auto-forensics-autopilot serve [--workspace DIR] [--port 8765]

Runs on 127.0.0.1 only. Every API call needs the session token printed when
the server starts (the page reads it from the URL fragment, which browsers
never send to a server or in a Referer). The browser is started on a private
launcher file that forwards to that link, so the token never appears on a
command line other users of the computer can read. Other websites in the same browser
cannot call the API: there is no CORS, the Host header must be the loopback
address, and requests without the token are refused.

Fingerprints come only from the server's memory, captured when a run finishes
or a draft is signed, and are never re-read from the run folder: a fingerprint
recomputed from files someone replaced would vouch for the replacement. The
page keeps offering them until the analyst confirms they copied them, and the
server window prints them too. The analyst types them back to sign and export.

Evidence-derived text is returned as JSON and the page sets it with
``textContent`` only; nothing from a case is inserted as HTML. Text this
module adds to a response (headlines, folder names, excerpts) is bounded and
has control and text-direction characters replaced first.

The one page that needs no token is ``/report/<nonce>``: the exported HTML
report, opened in a new tab through a random link that stops working after
five minutes. It is served under a policy that forbids scripts and network
requests and sandboxes the document away from this server's origin.
"""

from __future__ import annotations

import csv
import hashlib
import html
import importlib.util
import io
import json
import os
import re
import secrets
import socket
import stat
import sys
import tempfile
import threading
import time
import webbrowser
from collections import OrderedDict
from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
from pathlib import Path, PurePath, PurePosixPath
from typing import Any, Callable, Iterator

from pydantic import BaseModel, Field

from auto_forensics.artifacts import evtx_reader_name
from auto_forensics.file_ops import directory_lock
from auto_forensics.models import utc_now_iso
from auto_forensics.security import SecurityError, stays_in_tree
from auto_forensics.timeline import timeline_sort_key
from auto_forensics.version import __version__ as CORE_VERSION

from . import AUTOPILOT_VERSION, signoff
from .agents import MAX_SCAN_BYTES, lines_of
from .coordinator import _safe_time, canonical_sha256
from .disk_images import disk_support
from .orchestrator import CUSTODY_FILE, DRAFT_JSON, MANIFEST_FILE, STAGES, read_json, start
from .report_html import render_html

STATIC = Path(__file__).with_name("static")
RUN_ID = re.compile(r"^[A-Za-z0-9._-]{2,64}-\d{8}T\d{6}Z$")
EXPORT_STAMP = re.compile(r"^\d{8}T\d{6}Z$")
CASE_ID = re.compile(r"^[A-Za-z0-9._-]{2,64}$")
NONCE = re.compile(r"^[A-Za-z0-9_-]{43,128}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SAFE_PART = re.compile(r"^[^/\\\x00-\x1f]{1,255}$")
MAX_BODY = 1024 * 1024
MAX_RUNNING = 2

PAGE_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; "
            "font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; sandbox"
REPORT_LINK_SECONDS = 300
MAX_REPORT_LINKS = 64
MAX_REPORT_BYTES = 32 * 1024 * 1024

MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_CITATIONS = 20
MAX_EXCERPT_CHARS = 4000
HEX_WINDOW = 256
# A cited file up to this size is read once into memory: hashed, checked and excerpted from the same bytes.
MAX_ROW_FILE_BYTES = 64 * 1024 * 1024
MAX_CACHED_RECORD_CHARS = 40_000_000
MAX_CACHED_HASHES = 256
MAX_CACHED_RECORD_FILES = 2
MAX_CACHED_ARTIFACT_RUNS = 8
CACHE_STRIPES = 16
MAX_TITLE_CHARS = 300
MAX_RECOMMENDATION_CHARS = 1000

MAX_BROWSE_FOLDERS = 500
MAX_BROWSE_ENTRIES = 5000
BROWSE_COUNT_ENTRIES = 20_000
BROWSE_COUNT_SECONDS = 0.4
MAX_PATH_CHARS = 4096

MAX_DISK_ITEMS = 200
MAX_DISK_TEXT = 300

LAUNCHER_SECONDS = 60.0

OLLAMA_PORT = 11434
OLLAMA_TIMEOUT = 0.3
OLLAMA_CACHE_SECONDS = 15.0

# What each agent does, in words for someone who has never seen the code.
AGENT_LABELS = {
    "core_pipeline": "Main analysis: logs, behaviour rules and timeline",
    "injection_sentinel": "Check for text written to mislead an AI",
    "secrets_sweep": "Search for passwords, keys and tokens",
    "memory": "Memory image analysis",
    "archive": "Open ZIP archives and analyse what is inside",
    "disk_image": "Open disk images and analyse what is inside",
    "disk_artifacts": "Read USB, file, browsing and clean-up traces from disk images",
}
AGENT_STATUSES = {"waiting", "running", "ok", "failed", "skipped"}

# Control characters, invisible characters, text-direction overrides and lone surrogates.
_UNSAFE = re.compile(r"[\x00-\x1f\x7f-\x9f\u200b-\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069\ufeff\ud800-\udfff]")
_UNSAFE_EXCEPT_NEWLINE = re.compile(
    r"[\x00-\x09\x0b-\x1f\x7f-\x9f\u200b-\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069\ufeff\ud800-\udfff]")

FILE_ATTRIBUTE_HIDDEN = 0x2
FILE_ATTRIBUTE_SYSTEM = 0x4


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _say(message: str) -> None:
    print(message, flush=True)


def _text(value: Any, limit: int = 300) -> str:
    """Text taken from a case or the file system, made safe to hand to the page: one line, bounded."""
    # Cut first: the substitution is one character for one, so the result is the same, without scanning
    # a long value whole.
    return _UNSAFE.sub(" ", ("" if value is None else str(value))[:limit])


def _capped(value: Any, limit: int) -> Any:
    """A string cut to ``limit`` characters with an ellipsis; anything else unchanged."""
    if isinstance(value, str) and len(value) > limit:
        return value[:limit - 1] + "\u2026"
    return value


def _excerpt(text: str) -> tuple[str, bool]:
    """Evidence text for the analyst: line breaks kept, tabs to spaces, anything else unsafe to U+FFFD."""
    cut = len(text) > MAX_EXCERPT_CHARS
    text = text[:MAX_EXCERPT_CHARS].replace("\r\n", "\n").replace("\t", " ").replace("\r", " ")
    return _UNSAFE_EXCEPT_NEWLINE.sub("\ufffd", text), cut


def _hex_dump(data: bytes, start: int) -> str:
    """Offset, sixteen bytes in hex, and the same bytes as text with dots for anything unprintable."""
    lines = []
    for index in range(0, len(data), 16):
        chunk = data[index:index + 16]
        left = " ".join(f"{byte:02x}" for byte in chunk[:8])
        right = " ".join(f"{byte:02x}" for byte in chunk[8:])
        shown = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
        lines.append(f"{start + index:08x}  {left:<23}  {right:<23}  |{shown}|")
    return "\n".join(lines)


def _csv_fields(data: bytes, row: int) -> str | None:
    """One CSV record as ``column: value`` lines.

    ``row`` is counted the way the core's CSV parser and verifier count it:
    the physical line on which the record ends (``csv`` reader ``line_num``).
    The bytes are decoded as the core reads the file: UTF-8 with replacement,
    no newline translation, a leading byte-order mark dropped.
    """
    text = data.decode("utf-8", errors="replace").removeprefix("\ufeff")
    reader = csv.DictReader(io.StringIO(text, newline=""))
    _ = reader.fieldnames
    for record in reader:
        if reader.line_num == row:
            return "\n".join(f"{'(extra)' if key is None else key}: {'' if value is None else value}"
                             for key, value in record.items())
        if reader.line_num > row:
            break
    return None


def _json_record(text: str) -> str:
    """A JSON record on several indented lines; any other text unchanged.

    For a JSON record the core's row reader returns the record on one line
    followed by its values again; only the record itself is worth showing.
    """
    first = text.split("\n", 1)[0]
    if not first.lstrip().startswith("{"):
        return text
    try:
        record = json.loads(first)
    except ValueError:
        return text
    return json.dumps(record, indent=2, ensure_ascii=False) if isinstance(record, dict) else text


def _sig(path: Path) -> tuple[int, int] | None:
    """Modification time and size: enough to tell a cached answer is stale without reading the file."""
    try:
        status = path.stat()
    except OSError:
        return None
    return status.st_mtime_ns, status.st_size


def _read_json(path: Path, limit: int = MAX_JSON_BYTES) -> Any:
    if path.stat().st_size > limit:
        raise ValueError("file is too large to read")
    return json.loads(path.read_text(encoding="utf-8"))


def _int_or_none(value: Any) -> int | None:
    return value if type(value) is int and value >= 0 else None


# --------------------------------------------------------------------------
# Folder browser
# --------------------------------------------------------------------------


def parent_of(path: str, flavour: type[PurePath] = PurePath) -> str | None:
    """The folder above ``path``, or None at the top (``/``, ``C:\\`` or a network share)."""
    pure = flavour(path)
    return None if pure.parent == pure else str(pure.parent)


def is_absolute_path(path: str, flavour: type[PurePath] = PurePath) -> bool:
    """True for ``/x``, ``C:\\x`` and ``\\\\server\\share``; false for ``x``, ``C:x`` and (on Windows) ``\\x``."""
    return bool(path) and "\x00" not in path and flavour(path).is_absolute()


def drives_from_mask(mask: int) -> list[str]:
    """Drive roots from the Windows GetLogicalDrives bit mask (bit 0 is A:)."""
    return [f"{chr(ord('A') + bit)}:\\" for bit in range(26) if mask >> bit & 1]


def is_hidden(name: str, attributes: int = 0, flags: int = 0, *, windows: bool = False) -> bool:
    """Dot folders everywhere; on Windows also ``$`` folders and the hidden or system attribute; macOS's hidden flag."""
    if name.startswith(".") or (windows and name.startswith("$")):
        return True
    if attributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM):
        return True
    return bool(flags & getattr(stat, "UF_HIDDEN", 0x8000))


def _windows_drives() -> list[str]:
    try:
        import ctypes

        return drives_from_mask(int(ctypes.windll.kernel32.GetLogicalDrives()))  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 - no drive list is better than no browser
        return ["C:\\"]


def browse_roots(home: Path, *, windows: bool | None = None) -> list[dict[str, str]]:
    """Starting points for the folder browser: home, the usual folders that exist, then drives."""
    windows = sys.platform == "win32" if windows is None else windows
    roots = [{"name": "Home folder", "path": str(home)}]
    for name in ("Desktop", "Downloads", "Documents"):
        # Windows often keeps these inside OneDrive.
        for candidate in (home / name, home / "OneDrive" / name):
            if candidate.is_dir():
                roots.append({"name": name, "path": str(candidate)})
                break
    if windows:
        roots += [{"name": f"Drive {drive[:2]}", "path": drive} for drive in _windows_drives()]
    else:
        roots.append({"name": "Whole computer (/)", "path": "/"})
        roots += [{"name": f"Connected drives ({extra})", "path": extra}
                  for extra in ("/Volumes", "/media", "/mnt") if Path(extra).is_dir()]
    return [root for root in roots if not _UNSAFE.search(root["path"])]


def _count_files(folders: list[str], files: int, size: int, deadline: float) -> tuple[int, int, bool]:
    """Add the files below ``folders`` to a count, within an entry and time budget. Links are not followed."""
    pending = list(folders)
    seen = 0
    complete = True
    while pending:
        try:
            with os.scandir(pending.pop()) as entries:
                for entry in entries:
                    seen += 1
                    if seen > BROWSE_COUNT_ENTRIES or time.monotonic() > deadline:
                        return files, size, False
                    if entry.is_dir(follow_symlinks=False):
                        pending.append(entry.path)
                    elif entry.is_file(follow_symlinks=False):
                        files += 1
                        size += entry.stat(follow_symlinks=False).st_size
        except OSError:
            complete = False  # a folder that cannot be opened: the total is no longer the whole story
    return files, size, complete


def browse(raw: str, *, home: Path | None = None) -> dict[str, Any]:
    """One folder for the picker: its sub-folders (never file names) and how much it holds.

    ``file_count`` and ``total_bytes`` cover the folder and everything below
    it, which is what a run would read. When that is too much to count in a
    moment, ``total_bytes`` is None, ``count_complete`` is false and
    ``file_count`` is the number counted so far (read it as "at least").
    """
    home = home or Path.home()
    windows = sys.platform == "win32"
    result: dict[str, Any] = {"path": "", "parent": None, "folders": [], "truncated": False, "file_count": 0,
                              "total_bytes": None, "count_complete": False, "roots": browse_roots(home), "error": None}
    text = (raw or "").strip()
    if text and (len(text) > MAX_PATH_CHARS or not is_absolute_path(text)):
        result.update(path=_text(text, MAX_PATH_CHARS), error="That is not a full folder path. Pick a folder from the list.")
        return result
    target = Path(text) if text else home
    try:
        target = target.resolve()
    except (OSError, RuntimeError):
        pass
    if _UNSAFE.search(str(target)):
        result.update(path=_text(target, MAX_PATH_CHARS),
                      error="This folder's name contains characters that cannot be shown safely. Rename it first.")
        return result
    result.update(path=str(target), parent=parent_of(str(target)))
    folders: list[dict[str, str]] = []
    below: list[str] = []
    truncated = False
    files = size = 0
    unreadable = False
    scanned = 0
    try:
        if not target.is_dir():
            result["error"] = "This folder does not exist. It may have been moved, or its drive is not connected."
            return result
        with os.scandir(target) as entries:
            for entry in entries:
                scanned += 1
                if scanned > MAX_BROWSE_ENTRIES:
                    # A folder this big is not read to the end: the list and the count are partial.
                    truncated = unreadable = True
                    break
                try:
                    if entry.is_symlink():
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        below.append(entry.path)
                        status = entry.stat(follow_symlinks=False)
                        if _UNSAFE.search(entry.name) or is_hidden(
                                entry.name, getattr(status, "st_file_attributes", 0), getattr(status, "st_flags", 0),
                                windows=windows):
                            continue
                        folders.append({"name": entry.name, "path": str(target / entry.name)})
                    elif entry.is_file(follow_symlinks=False):
                        files += 1
                        size += entry.stat(follow_symlinks=False).st_size
                except OSError:
                    unreadable = True  # one entry that cannot be examined does not hide the rest
    except PermissionError:
        result["error"] = "This folder cannot be opened: this computer did not give permission to look inside it."
        return result
    except OSError as exc:
        result["error"] = f"This folder cannot be opened ({type(exc).__name__})."
        return result
    folders.sort(key=lambda item: (item["name"].casefold(), item["name"]))
    if truncated:
        below = []  # the folder alone already exceeds the counting budget
    files, size, complete = _count_files(below, files, size, time.monotonic() + BROWSE_COUNT_SECONDS)
    complete = complete and not unreadable
    result.update(folders=folders[:MAX_BROWSE_FOLDERS], truncated=truncated or len(folders) > MAX_BROWSE_FOLDERS,
                  file_count=files, total_bytes=size if complete else None, count_complete=complete)
    return result


# --------------------------------------------------------------------------
# What this install can do
# --------------------------------------------------------------------------


def ollama_reachable(timeout: float = OLLAMA_TIMEOUT) -> bool:
    """True when Ollama answers on this computer. One short request to 127.0.0.1; nothing leaves the machine."""
    deadline = time.monotonic() + timeout
    try:
        with socket.create_connection(("127.0.0.1", OLLAMA_PORT), timeout=timeout) as sock:
            sock.settimeout(max(0.01, deadline - time.monotonic()))
            sock.sendall(b"GET /api/version HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
            sock.settimeout(max(0.01, deadline - time.monotonic()))
            head = sock.recv(32)
    except OSError:
        return False
    return head.startswith(b"HTTP/1.") and head[8:12] == b" 200"


def _has_module(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


# --------------------------------------------------------------------------
# Disk summaries
# --------------------------------------------------------------------------


def _disk_text(value: Any) -> str:
    return _text(value, MAX_DISK_TEXT).strip()


def _first(row: dict[str, Any], *keys: str) -> str:
    for key in keys:
        if row.get(key) not in (None, "", [], {}):
            return _disk_text(row[key])
    return ""


def _plugin_rows(summary: dict[str, Any], name: str) -> list[dict[str, Any]]:
    plugins = summary.get("plugins") if isinstance(summary.get("plugins"), dict) else {}
    block = plugins.get(name) if isinstance(plugins.get(name), dict) else {}
    rows = block.get("rows") if isinstance(block.get("rows"), list) else []
    return [row for row in rows if isinstance(row, dict)]


def disk_view(summary: Any, fallback_name: str) -> dict[str, Any]:
    """The few facts about one disk image the page shows, read tolerantly from ``disk_summary.json``.

    Unknown keys are ignored and anything missing becomes an empty value, so
    a summary written by a newer or older build still displays.
    """
    summary = summary if isinstance(summary, dict) else {}
    properties = summary.get("properties") if isinstance(summary.get("properties"), dict) else {}

    def fact(name: str) -> str:
        value = properties.get(name)
        if value in (None, ""):
            value = summary.get(name)
        if isinstance(value, list):
            value = ", ".join(str(item) for item in value[:10])
        return "" if isinstance(value, dict) else _disk_text(value)

    users: list[str] = []
    for row in _plugin_rows(summary, "users"):
        name = _first(row, "name", "username", "user", "value")
        if name and name not in users:
            users.append(name)
    if not users and isinstance(summary.get("user_folders"), list):
        # Profile folder names still say who used the machine when the registry could not be read.
        for folder in summary["user_folders"]:
            name = _disk_text(str(folder).replace("\\", "/").rstrip("/").rsplit("/", 1)[-1])
            if name and name not in users:
                users.append(name)
    if not users and isinstance(summary.get("users"), list):
        users = [_disk_text(item.get("name") if isinstance(item, dict) else item) for item in summary["users"]]

    artifacts = summary.get("artifacts") if isinstance(summary.get("artifacts"), dict) else {}

    def rows_of(block: Any, key: str) -> list[dict[str, Any]]:
        value = block.get(key) if isinstance(block, dict) else None
        return [row for row in value if isinstance(row, dict)][:MAX_DISK_ITEMS] if isinstance(value, list) else []

    def joined(row: dict[str, Any], key: str) -> str:
        value = row.get(key)
        return _disk_text(", ".join(str(item) for item in value[:10])) if isinstance(value, list) else _disk_text(value)

    # The artefact agent's device list is richer (volume names, drive letters) than the plugin's.
    devices = rows_of(artifacts, "usb_devices") or _plugin_rows(summary, "usb")
    if not devices and isinstance(summary.get("usb_devices"), list):
        devices = [row for row in summary["usb_devices"] if isinstance(row, dict)]
    usb = []
    for row in devices[:MAX_DISK_ITEMS]:
        maker = " ".join(part for part in (_first(row, "vendor"), _first(row, "product")) if part)
        usb.append({
            "name": _first(row, "friendly_name", "friendlyname", "name") or _disk_text(maker) or "Unnamed device",
            "serial": _first(row, "serial", "serial_number"),
            "first_seen": _first(row, "first_seen", "first_insert", "first_install"),
            "last_seen": _first(row, "last_seen", "last_insert", "last_removal"),
            "volume_names": joined(row, "volume_names"),
            "drive_letters": joined(row, "drive_letters"),
        })

    programs = []
    other = artifacts.get("other_watched_programs") if isinstance(artifacts.get("other_watched_programs"), dict) else {}
    groups = [("Cloud storage", rows_of(artifacts, "cloud_clients")),
              ("Clean-up or wiping tool", rows_of(artifacts, "anti_forensic_tools")),
              ("E-mail", rows_of(artifacts, "email_clients"))]
    groups += [(_disk_text(str(kind).replace("_", " ").capitalize()), rows_of(other, kind)) for kind in list(other)[:20]]
    for kind, rows in groups:
        for row in rows:
            programs.append({"kind": kind, "program": _first(row, "program", "name"), "evidence": _first(row, "evidence"),
                             "first_seen": _first(row, "first_seen"), "last_seen": _first(row, "last_seen")})
    shares = [{"share": _first(row, "share"), "drive_letters": joined(row, "drive_letters"),
               "first_seen": _first(row, "first_seen"), "last_seen": _first(row, "last_seen")}
              for row in rows_of(artifacts, "network_shares")]
    searches = [{"term": _first(row, "term"), "time": _first(row, "time"), "themes": joined(row, "themes")}
                for row in rows_of(artifacts, "flagged_searches")]
    system = artifacts.get("system") if isinstance(artifacts.get("system"), dict) else {}
    accounts = [{"name": _first(row, "name"), "last_logon": _first(row, "last_logon"),
                 "logon_count": _first(row, "logon_count"), "disabled": bool(row.get("disabled"))}
                for row in rows_of(system, "user_accounts")]
    bin_info = artifacts.get("recycle_bin") if isinstance(artifacts.get("recycle_bin"), dict) else {}
    records = artifacts.get("records") if isinstance(artifacts.get("records"), dict) else {}
    activity = [{"kind": _disk_text(str(kind).replace("_", " ")), "count": count}
                for kind, count in sorted(records.items(), key=lambda kv: str(kv[0]))[:60] if isinstance(count, int)]

    volumes = []
    for item in summary.get("volumes") if isinstance(summary.get("volumes"), list) else []:
        if isinstance(item, dict):
            label, kind = _first(item, "label", "name"), _first(item, "filesystem", "type")
            volumes.append(_disk_text(f"{label} ({kind})" if label and kind else label or kind))
        else:
            volumes.append(_disk_text(item))

    gaps = []
    for item in summary.get("gaps") if isinstance(summary.get("gaps"), list) else []:
        if isinstance(item, dict):
            what, why = _first(item, "what"), _first(item, "why")
            gaps.append(_disk_text(f"{what}: {why}" if what and why else what or why))
        else:
            gaps.append(_disk_text(item))
    plugins = summary.get("plugins") if isinstance(summary.get("plugins"), dict) else {}
    for name, block in plugins.items():
        if isinstance(block, dict) and block.get("status") in {"error", "skipped"}:
            why = "ran out of time" if block.get("status") == "skipped" else _first(block, "error") or "error"
            gaps.append(_disk_text(f"The list of {name} could not be read from this image ({why})."))

    return {
        "image": _disk_text(summary.get("image")) or _disk_text(fallback_name),
        "os": fact("os"), "hostname": fact("hostname"), "version": fact("version"), "timezone": fact("timezone"),
        "users": [name for name in users if name][:MAX_DISK_ITEMS],
        "usb_devices": usb,
        "volumes": [item for item in volumes if item][:MAX_DISK_ITEMS],
        "gaps": [item for item in gaps if item][:MAX_DISK_ITEMS],
        "system": {"computer_name": _first(system, "computer_name"), "os_version": _first(system, "os_version"),
                   "installed": _first(system, "os_install_date"), "last_shutdown": _first(system, "last_shutdown"),
                   "owner": _first(system, "registered_owner"), "time_zone": _first(system, "time_zone")},
        "accounts": accounts,
        "programs": programs,
        "network_shares": shares,
        "searches": searches,
        "recycle_bin": {"items": bin_info.get("items") if isinstance(bin_info.get("items"), int) else 0,
                        "first": _first(bin_info, "first"), "last": _first(bin_info, "last")},
        "activity": activity,
    }


_ISO_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?$")
_DETAIL_SKIP = {"rule", "severity", "title", "technique", "records", "locator", "source", "schema"}
_DETAIL_LABELS = {
    "path": "Path", "time": "When", "user": "User", "seen_in": "Kind of record", "volume": "Drive or share",
    "program": "Program", "run_count": "Times run", "key_path": "Registry key", "name": "Name", "version": "Version",
    "size_bytes": "Size in bytes", "first_seen": "First seen", "last_seen": "Last seen", "share": "Shared folder",
    "term": "Searched for", "url": "Address", "host": "Site", "browser": "Browser", "disc_label": "Disc label",
    "files": "Files and folders", "deleted": "Deleted items", "sync_folder_files": "Files in the sync folder",
    "media": "Discs", "tools": "Tools", "shares": "Shared folders", "searches": "Searches", "visits": "Pages visited",
    "tables": "History tables", "jumps": "Clock jumps", "from_local": "Clock read", "to_local": "Then read",
}


def _detail_label(key: Any) -> str:
    key = str(key)
    return _DETAIL_LABELS.get(key) or _disk_text(key.replace("_", " ").capitalize())


def _detail_cell(value: Any) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, list):
        return _disk_text(", ".join(str(item) for item in value[:10] if not isinstance(item, (dict, list))))
    return "" if isinstance(value, dict) else _disk_text(value)


def artifact_view(detail: Any) -> dict[str, Any]:
    """One disk-artefact finding's recorded detail as plain facts and small tables for the analyst."""
    detail = detail if isinstance(detail, dict) else {}
    facts: list[list[str]] = []
    tables: list[dict[str, Any]] = []
    for key, value in list(detail.items())[:40]:
        if key in _DETAIL_SKIP:
            continue
        if isinstance(value, list) and value and all(isinstance(row, dict) for row in value):
            columns = [name for name in dict.fromkeys(name for row in value[:MAX_DISK_ITEMS] for name in row)
                       if name not in _DETAIL_SKIP][:7]
            rows = [[_detail_cell(row.get(name)) for name in columns] for row in value[:MAX_DISK_ITEMS]]
            tables.append({"title": _detail_label(key), "columns": [_detail_label(name) for name in columns],
                           "rows": rows, "more": max(0, len(value) - MAX_DISK_ITEMS)})
        elif isinstance(value, dict):
            for name, inner in list(value.items())[:30]:
                if name not in _DETAIL_SKIP and not isinstance(inner, dict) and _detail_cell(inner):
                    if isinstance(inner, list) and inner and isinstance(inner[0], dict):
                        continue
                    facts.append([_detail_label(name), _detail_cell(inner)])
        elif _detail_cell(value):
            facts.append([_detail_label(key), _detail_cell(value)])
    return {"facts": facts[:60], "tables": tables[:8]}


def artifact_time(detail: Any) -> str | None:
    """Earliest time the artefact agent recorded for a finding (its own parsed field, not free text)."""
    found: list[str] = []

    def walk(node: Any, depth: int) -> None:
        if depth > 3 or len(found) > 5000:
            return
        if isinstance(node, dict):
            for key, value in node.items():
                if key in {"time", "first_seen"} and isinstance(value, str) and _ISO_TIME.match(value):
                    found.append(value)
                elif isinstance(value, (dict, list)):
                    walk(value, depth + 1)
        elif isinstance(node, list):
            for item in node[:2000]:
                walk(item, depth + 1)

    walk(detail, 0)
    return min(found, key=timeline_sort_key) if found else None


# --------------------------------------------------------------------------
# Reading cited evidence
# --------------------------------------------------------------------------


class _Changed(Exception):
    """The cited file changed, moved or was replaced while it was being read."""


def _identity(status: os.stat_result) -> tuple[int, int, int, int, int]:
    """Device, inode, size, modified time and changed time of a file.

    Setting a file's modified time back with ``utime`` still moves its
    changed time (``st_ctime``), which no ordinary program can set, so on
    Linux and macOS content swapped in place cannot keep this identity. On
    Windows ``st_ctime`` is the creation time and adds no such guarantee.
    """
    return status.st_dev, status.st_ino, status.st_size, status.st_mtime_ns, status.st_ctime_ns


def _open_regular(file: Path) -> tuple[int, os.stat_result]:
    """A read-only descriptor on a regular file (never through a final link), and its status."""
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(file, flags)
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode):
            raise OSError("not a regular file")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, status


def _read_at(descriptor: int, start: int, length: int) -> bytes:
    """Up to ``length`` bytes from ``start``; fewer at the end of the file."""
    os.lseek(descriptor, start, os.SEEK_SET)
    parts: list[bytes] = []
    left = length
    while left > 0:
        chunk = os.read(descriptor, min(left, 1024 * 1024))
        if not chunk:
            break
        parts.append(chunk)
        left -= len(chunk)
    return b"".join(parts)


def _sha256_fd(descriptor: int, size: int) -> str:
    """SHA-256 of exactly ``size`` bytes through an open descriptor; a file that grew or shrank is refused."""
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    left = size
    while left > 0:
        chunk = os.read(descriptor, min(left, 1024 * 1024))
        if not chunk:
            raise _Changed("the file got shorter")
        digest.update(chunk)
        left -= len(chunk)
    if os.read(descriptor, 1):
        raise _Changed("the file got longer")
    return digest.hexdigest()


def _still_same(file: Path, descriptor: int, status: os.stat_result) -> None:
    """Raise ``_Changed`` unless the open file and the file at the path both still have ``status``'s identity."""
    try:
        now_open = os.fstat(descriptor)
        now_named = os.stat(file, follow_symlinks=False)
    except OSError as exc:
        raise _Changed("the file is gone") from exc
    if _identity(now_open) != _identity(status) or _identity(now_named) != _identity(status):
        raise _Changed("the file changed")


@contextmanager
def _snapshot(name: str, data: bytes) -> Iterator[Path]:
    """The given bytes as a private file named ``name``, for readers that take a path. Removed afterwards."""
    with tempfile.TemporaryDirectory(prefix="af-excerpt-") as folder:
        path = Path(folder) / name
        with path.open("xb") as handle:
            handle.write(data)
        yield path


class _Source:
    """One cited file, held open while it is checked and read.

    A file up to ``MAX_ROW_FILE_BYTES`` is read once: ``data`` holds its bytes,
    ``digest`` is their SHA-256, and every excerpt is cut from those bytes.
    A larger file is hashed and read through the same descriptor, and
    ``check`` refuses it if it changed in between.
    """

    def __init__(self, file: Path, descriptor: int, status: os.stat_result, data: bytes | None, digest: str) -> None:
        self.file, self.descriptor, self.status, self.data, self.digest = file, descriptor, status, data, digest

    def read(self, start: int, length: int) -> bytes:
        if self.data is not None:
            return self.data[start:start + length]
        return _read_at(self.descriptor, start, length)

    def check(self) -> None:
        _still_same(self.file, self.descriptor, self.status)


# --------------------------------------------------------------------------
# Run folder locks
# --------------------------------------------------------------------------


def pid_alive(pid: int) -> bool:
    """True when a process with this id runs on this computer (or cannot be ruled out)."""
    if pid <= 0:
        return False
    if pid == os.getpid():
        return True
    if sys.platform == "win32":
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return kernel32.GetLastError() == 5  # access denied: it exists
        try:
            code = ctypes.c_ulong()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return True
            return code.value == 259  # STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True  # it exists but belongs to someone else
    return True


_LOCK_PID = re.compile(r"^pid=(\d{1,10})$", re.MULTILINE)
_LOCK_HOST = re.compile(r"^host=(.{1,255})$", re.MULTILINE)


def clear_stale_lock(lock_file: Path) -> bool:
    """Remove a run folder lock whose recorded owner is no longer running. True when no lock is left.

    The lock records ``pid=`` (and, from this version, ``host=``). A lock with no
    readable owner, an owner on another computer, or an owner still running is kept.
    """
    try:
        before = lock_file.lstat()
        if not stat.S_ISREG(before.st_mode):
            return False
        with lock_file.open("rb") as handle:
            text = handle.read(512).decode("ascii", errors="replace")
    except FileNotFoundError:
        return True
    except OSError:
        return False
    pid = _LOCK_PID.search(text)
    host = _LOCK_HOST.search(text)
    this_host = socket.gethostname().encode("ascii", errors="replace")[:255].replace(b"\n", b"?").decode("ascii")
    if pid is None or (host is not None and host.group(1) != this_host):
        return False
    if pid_alive(int(pid.group(1))):
        return False
    try:
        current = lock_file.lstat()
        if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
            return False  # replaced since it was read: someone else holds it now
        lock_file.unlink()
    except FileNotFoundError:
        pass
    except OSError:
        return False
    return True


# --------------------------------------------------------------------------
# Opening the page
# --------------------------------------------------------------------------


def write_launcher(url: str) -> Path:
    """A one-line page, readable only by this user, that sends the browser to ``url``.

    Opening ``url`` itself would put the session token on the command line of
    the browser launcher, where any user of this computer can read it. The
    browser is given this file's path instead.
    """
    folder = Path(tempfile.mkdtemp(prefix="af-open-"))  # created readable by this user only
    page = folder / "open.html"
    target = html.escape(url, quote=True)
    text = ("<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"referrer\" content=\"no-referrer\">"
            f"<meta http-equiv=\"refresh\" content=\"0;url={target}\"><title>Auto Forensics</title></head>"
            f"<body><p><a href=\"{target}\">Open the Auto Forensics review page</a></p></body></html>\n")
    descriptor = os.open(page, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)
    return page


def remove_launcher(page: Path) -> None:
    try:
        page.unlink(missing_ok=True)
        page.parent.rmdir()
    except OSError:
        pass


def open_in_browser(url: str, *, delay: float = LAUNCHER_SECONDS,
                    opener: Callable[[str], Any] = webbrowser.open) -> tuple[Path, threading.Timer]:
    """Open ``url`` through a launcher file, removed after ``delay`` seconds; returns it and its timer."""
    page = write_launcher(url)
    timer = threading.Timer(delay, remove_launcher, args=(page,))
    timer.daemon = True
    timer.start()
    try:
        opener(page.as_uri())
    except Exception:  # noqa: BLE001 - no browser: the link is printed in the server window
        pass
    return page, timer


# --------------------------------------------------------------------------
# State
# --------------------------------------------------------------------------


def _new_progress() -> dict[str, Any]:
    name, label = STAGES[0]
    return {"stage": name, "stage_number": 1, "stage_total": len(STAGES), "stage_label": label, "agents": [],
            "files_total": 0, "bytes_done": None, "bytes_total": None}


class ReviewState:
    """Runs in one workspace, plus fingerprints held in memory for this session."""

    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace.expanduser().resolve()
        self.runs = self.workspace / "runs"
        self.exports = self.workspace / "exports"
        self.removed = self.workspace / "removed"
        self.runs.mkdir(parents=True, exist_ok=True)
        self.exports.mkdir(parents=True, exist_ok=True)
        self.token = secrets.token_urlsafe(32)
        self.lock = threading.Lock()
        self.jobs: dict[str, dict[str, Any]] = {}
        self._artifact_cache: OrderedDict[str, tuple[Any, dict[str, Any]]] = OrderedDict()
        # Fingerprints still waiting for the analyst to confirm they copied them.
        self.shown: dict[str, dict[str, str]] = {}
        # One-time links to exported HTML reports: nonce -> (run id, export folder, expiry on self.clock).
        self.report_links: dict[str, tuple[str, Path, float]] = {}
        self.clock: Callable[[], float] = time.monotonic
        # Answers that are slow to work out, each stored with the file times it was worked out from.
        self._cache_lock = threading.Lock()
        self._summaries: dict[str, tuple[Any, dict[str, Any]]] = {}
        self._timelines: OrderedDict[str, tuple[Any, dict[str, list[tuple[str, str, int | None]]]]] = OrderedDict()
        # Slow work on one file runs under one of these, picked by the file: two requests for the same
        # file share the work, and requests for unrelated files rarely wait for each other.
        self._stripes = [threading.Lock() for _ in range(CACHE_STRIPES)]
        # Hashes of files too large to read whole, keyed by path and identity (see _identity).
        self._hashes: OrderedDict[tuple[Any, ...], str] = OrderedDict()
        # Parsed records by (file name, SHA-256 of the bytes they were parsed from).
        self._records: OrderedDict[tuple[str, str], dict[int, str]] = OrderedDict()
        self._ollama: tuple[float, bool] | None = None

    # ---- runs --------------------------------------------------------------

    def run_dir(self, run_id: str) -> Path:
        if not RUN_ID.fullmatch(run_id or ""):
            raise SecurityError("Unknown run")
        path = (self.runs / run_id).resolve()
        if path.parent != self.runs or not path.is_dir():
            raise SecurityError("Unknown run")
        return path

    def exported_to(self, run_id: str) -> Path | None:
        """Latest export folder of this run that holds a final report, or None.

        Only ``<run id>-export-<stamp>`` counts: a pattern match would also take
        the exports of another case whose id starts with ``<run id>-export-``.
        """
        found = sorted(path for owner, path in self._exports() if owner == run_id)
        return found[-1] if found else None

    def _exports(self) -> list[tuple[str, Path]]:
        """(run id, folder) for every export folder that holds a final report."""
        out = []
        try:
            for path in self.exports.iterdir():
                run_id, marker, stamp = path.name.rpartition("-export-")
                if (marker and RUN_ID.fullmatch(run_id) and EXPORT_STAMP.fullmatch(stamp)
                        and (path / signoff.FINAL_JSON).is_file()):
                    out.append((run_id, path))
        except OSError:
            pass
        return out

    def _exported_runs(self) -> set[str]:
        """Run ids that have an export, from one pass over the exports folder."""
        return {run_id for run_id, _ in self._exports()}

    def _custody_facts(self, path: Path) -> tuple[str | None, str | None]:
        """(started_at, evidence_folder) from the custody record, or Nones while it does not exist yet."""
        try:
            custody = _read_json(path / CUSTODY_FILE)
            return _safe_time(custody.get("started_at")), _text(custody.get("evidence_dir"), MAX_PATH_CHARS) or None
        except Exception:  # noqa: BLE001 - a run that stopped early has no custody record
            return None, None

    def _summary(self, path: Path) -> dict[str, Any]:
        """Everything the run list shows for a finished run.

        Working this out reads and hashes the draft, so the answer is kept
        until one of the run's files changes (their times and sizes are the key).
        """
        key = tuple(_sig(path / name) for name in (DRAFT_JSON, MANIFEST_FILE, signoff.SIGNOFF_LOG,
                                                    signoff.SIGNATURE_FILE, CUSTODY_FILE))
        with self._cache_lock:
            held = self._summaries.get(path.name)
        if held and held[0] == key:
            return dict(held[1])
        state = signoff.status(path)
        draft = read_json(path / DRAFT_JSON)
        manifest = read_json(path / MANIFEST_FILE)
        started, folder = self._custody_facts(path)
        counts = draft.get("severity_counts") if isinstance(draft.get("severity_counts"), dict) else {}
        summary = {
            "case_id": state["case_id"], "total": state["total"], "pending": len(state["pending"]),
            "signed": state["signed"], "headline": _text(draft.get("headline"), 300),
            "severity_counts": {_text(name, 20): count for name, count in counts.items() if type(count) is int},
            "started_at": started, "finished_at": _safe_time(manifest.get("finished_at")), "evidence_folder": folder,
        }
        with self._cache_lock:
            self._summaries[path.name] = (key, summary)
        return dict(summary)

    def can_remove(self, run_id: str) -> bool:
        """Only a run that failed or never finished: no manifest, no signature, and not going now."""
        if self.jobs.get(run_id, {}).get("state") == "running":
            return False
        path = self.runs / run_id
        return not (path / MANIFEST_FILE).exists() and not (path / signoff.SIGNATURE_FILE).exists()

    def list_runs(self) -> list[dict[str, Any]]:
        out = []
        exported = self._exported_runs()
        for path in sorted(self.runs.iterdir(), reverse=True):
            if not RUN_ID.fullmatch(path.name) or not path.is_dir():
                continue
            job = self.jobs.get(path.name, {})
            entry: dict[str, Any] = {
                "run_id": path.name, "state": job.get("state", "done"), "headline": None, "severity_counts": {},
                "started_at": job.get("started_at"), "evidence_folder": job.get("evidence_folder"),
                "can_remove": False,
            }
            if job.get("state") == "running":
                entry.update(error="", case_id=job.get("case_id"))
            elif job.get("state") == "failed":
                entry.update(error=job.get("error", ""), can_remove=self.can_remove(path.name))
            elif (path / DRAFT_JSON).is_file() and (path / MANIFEST_FILE).is_file():
                try:
                    entry.update(self._summary(path), exported=path.name in exported)
                except Exception as exc:  # noqa: BLE001 - one bad run must not hide the others
                    entry.update(state="error", error=f"run files could not be read ({type(exc).__name__})")
            else:
                started, folder = self._custody_facts(path)
                entry.update(state="incomplete", error="This run stopped before it finished.",
                             started_at=started, evidence_folder=folder, can_remove=self.can_remove(path.name))
            out.append(entry)
        return out

    def start_run(self, input_dir: str, case_id: str, actor: str, llm: str) -> str:
        if not CASE_ID.fullmatch(case_id or ""):
            raise SecurityError("Case ID must be 2-64 letters, numbers, dots, dashes or underscores")
        if llm not in {"off", "mock", "ollama"}:
            raise SecurityError("Model must be off, mock or ollama")
        # Explorer's "Copy as path" wraps the path in quotes.
        evidence = Path(input_dir.strip().strip('"').strip("'").strip()).expanduser()
        if not evidence.is_dir():
            raise SecurityError("The evidence folder does not exist")
        evidence = evidence.resolve()
        if evidence == self.workspace or evidence.is_relative_to(self.workspace) or self.workspace.is_relative_to(evidence):
            raise SecurityError("The evidence folder and the workspace must not contain each other")
        run_id = f"{case_id}-{_stamp()}"
        with self.lock:
            if sum(1 for j in self.jobs.values() if j.get("state") == "running") >= MAX_RUNNING:
                raise SecurityError(f"{MAX_RUNNING} runs are already going; wait for one to finish")
            if any(j.get("state") == "running" and j.get("case_id") == case_id for j in self.jobs.values()):
                raise SecurityError("This case is already running")
            if run_id in self.jobs or (self.runs / run_id).exists():
                raise SecurityError("A run for this case started this second; wait a moment and try again")
            self.jobs[run_id] = {"state": "running", "case_id": case_id, "started": time.time(),
                                 "started_at": utc_now_iso(), "evidence_folder": _text(evidence, MAX_PATH_CHARS),
                                 "progress": _new_progress()}
        threading.Thread(target=self._run, args=(run_id, evidence, case_id, actor, llm), daemon=True).start()
        return run_id

    def _run(self, run_id: str, evidence: Path, case_id: str, actor: str, llm: str) -> None:
        kept = {key: self.jobs[run_id].get(key) for key in ("started_at", "evidence_folder")}
        try:
            draft = start(input_dir=evidence, output_dir=self.runs / run_id, case_id=case_id, actor=actor, llm=llm,
                          progress=lambda event: self._on_progress(run_id, event))
        except Exception as exc:  # noqa: BLE001 - reported on the page
            # Library messages can quote evidence; the page gets the type, this window the detail.
            _say(f"Run {run_id} failed: {type(exc).__name__}: {exc}")
            with self.lock:
                self.jobs[run_id] = {"state": "failed", **kept,
                                     "error": f"{type(exc).__name__} (details in the server window)"}
            return
        with self.lock:
            self.jobs[run_id] = {"state": "done", **kept}
            self.shown[run_id] = {"run_fingerprint": draft["run_fingerprint"]}
        _say(f"Run {run_id} finished. Run fingerprint: {draft['run_fingerprint']}")

    def _on_progress(self, run_id: str, event: dict[str, Any]) -> None:
        """Fold one orchestrator event into what the page polls. Called from the run's threads."""
        with self.lock:
            job = self.jobs.get(run_id)
            if not job or job.get("state") != "running":
                return
            progress = job["progress"]
            kind = event.get("event")
            if kind == "stage":
                progress.update(stage=str(event["stage"]), stage_number=int(event["stage_number"]),
                                stage_total=int(event["stage_total"]), stage_label=str(event["stage_label"]),
                                bytes_done=0 if "bytes_total" in event else None,
                                bytes_total=int(event["bytes_total"]) if "bytes_total" in event else None)
                if "files_total" in event:
                    progress["files_total"] = int(event["files_total"])
            elif kind == "hash":
                progress.update(bytes_done=int(event["bytes_done"]), bytes_total=int(event["bytes_total"]))
            elif kind == "plan":
                progress["files_total"] = int(event.get("files_total", progress["files_total"]))
                progress["agents"] = [
                    {"name": str(agent["name"]),
                     "label": AGENT_LABELS.get(agent["name"], str(agent["name"]).replace("_", " ").capitalize()),
                     "status": agent["status"] if agent["status"] in AGENT_STATUSES else "waiting"}
                    for agent in event.get("agents", [])
                ]
            elif kind == "agent" and event.get("status") in AGENT_STATUSES:
                for agent in progress["agents"]:
                    if agent["name"] == event.get("name"):
                        agent["status"] = event["status"]

    def progress(self, run_id: str) -> dict[str, Any] | None:
        """What a running job is doing now, or None when it is not running."""
        with self.lock:
            job = self.jobs.get(run_id)
            if not job or job.get("state") != "running":
                return None
            view = dict(job["progress"])
            view["agents"] = [dict(agent) for agent in view["agents"]]
            view["elapsed_seconds"] = max(0, int(time.time() - job["started"]))
            return view

    def confirm_copied(self, run_id: str, kind: str) -> None:
        with self.lock:
            held = self.shown.get(run_id, {})
            held.pop(kind, None)
            if not held:
                self.shown.pop(run_id, None)

    def decide(self, run_id: str, ids: list[str], decision: str, actor: str, note: str, override: bool) -> list[str]:
        """Check every id first so a batch is not half-written for a foreseeable reason."""
        path = self.run_dir(run_id)
        draft = read_json(path / DRAFT_JSON)
        known = {f["finding_id"] for f in draft["findings"]}
        decided = signoff.latest_decisions(signoff.read_log(path))
        ids = list(dict.fromkeys(ids))
        if not ids:
            raise SecurityError("Select at least one finding")
        unknown = [i for i in ids if i not in known]
        if unknown:
            raise SecurityError(f"{len(unknown)} selected finding(s) are not in this draft")
        if not override:
            already = [i for i in ids if i in decided]
            if already:
                raise SecurityError(f"{len(already)} selected finding(s) already have a decision; "
                                    "tick 'Change an earlier decision' to replace them")
        try:
            # One call for the batch: the evidence is hashed once, not once per finding.
            entries = signoff.decide_many(path, finding_ids=ids, decision=decision, actor=actor, note=note,
                                          override=override)
        except SecurityError as exc:
            done = getattr(exc, "decided", [])
            raise SecurityError(f"{len(done)} of {len(ids)} decided before this was refused: {exc}") from exc
        except Exception as exc:  # noqa: BLE001
            done = getattr(exc, "decided", [])
            _say(f"Decide on {run_id} failed: {type(exc).__name__}: {exc}")
            raise SecurityError(f"{len(done)} of {len(ids)} decided before an error ({type(exc).__name__})") from exc
        return [entry["finding_id"] for entry in entries]

    def remove_run(self, run_id: str) -> str | None:
        """Take a failed or unfinished run off the list by moving its folder to ``removed/``. Nothing is deleted."""
        if not RUN_ID.fullmatch(run_id or ""):
            raise SecurityError("Unknown run")
        with self.lock:
            job = self.jobs.get(run_id, {})
            if job.get("state") == "running":
                raise SecurityError("This run is still going. Wait for it to finish before removing it.")
            path = self.runs / run_id
            lock_file = self.runs / f".af-{run_id}.lock"
            if path.is_symlink() or not path.is_dir() or path.resolve().parent != self.runs:
                if job.get("state") != "failed":
                    raise SecurityError("Unknown run")
                # The run failed before it made a folder: there is only the list entry to clear,
                # and its lock if whoever left it is no longer running.
                clear_stale_lock(lock_file)
                self.jobs.pop(run_id, None)
                return None
            if not self.can_remove(run_id):
                raise SecurityError("Only a run that failed or did not finish can be removed. "
                                    "This run has a finished draft, so it is kept.")
            with ExitStack() as held:
                # The lock every writer of a run folder takes (a run, a decision, a signature), so a run
                # that another window or the command line is still writing is never moved.
                for attempt in (1, 2):
                    try:
                        held.enter_context(directory_lock(path))
                        break
                    except SecurityError as exc:
                        # A lock left by a program that is no longer running is cleared once, then retried.
                        if attempt == 2 or not clear_stale_lock(lock_file):
                            raise SecurityError(
                                "This run is still being written by another program (another review window or "
                                "the command line). Wait for it to finish, then try again.") from exc
                if not self.can_remove(run_id):
                    raise SecurityError("Only a run that failed or did not finish can be removed. "
                                        "This run has a finished draft, so it is kept.")
                self.removed.mkdir(exist_ok=True)
                moved = self.removed / f"{run_id}-{_stamp()}"
                attempt = 1
                while moved.exists():
                    attempt += 1
                    moved = self.removed / f"{run_id}-{_stamp()}-{attempt}"
                try:
                    path.rename(moved)
                except OSError as exc:
                    _say(f"Remove of {run_id} failed: {type(exc).__name__}: {exc}")
                    raise SecurityError(f"The run folder could not be moved ({type(exc).__name__}). "
                                        "Close anything that has it open and try again.") from exc
            # Leaving the block released the lock this removal took.
            self.jobs.pop(run_id, None)
            self.shown.pop(run_id, None)
        with self._cache_lock:
            self._summaries.pop(run_id, None)
        _say(f"Run {run_id} was removed from the list. Its folder was moved to {moved}")
        return str(moved)

    # ---- event times -------------------------------------------------------

    def _members(self, path: Path) -> dict[str, tuple[str, str, Path, Path, str]]:
        """Files copied out of archives and disk images: cited name -> (kind, folder, file, root, sha256)."""
        found: dict[str, tuple[str, str, Path, Path, str]] = {}
        for kind, base, listing, inner in (("archive", "archives", "archives.json", ()),
                                           ("disk_image", "disk", "disk_images.json", ("files",))):
            root = path / base
            try:
                rows = _read_json(root / listing)
            except Exception:  # noqa: BLE001 - most runs have no archives or images
                continue
            for row in rows if isinstance(rows, list) else []:
                if not isinstance(row, dict):
                    continue
                cited, folder, extracted = row.get("cited_as"), row.get("folder"), row.get("extracted")
                digest = str(row.get("sha256") or "").lower()
                if not (isinstance(cited, str) and isinstance(folder, str) and isinstance(extracted, str)):
                    continue
                relative = PurePosixPath(extracted.replace("\\", "/"))
                if (not SAFE_PART.fullmatch(folder) or folder in {".", ".."} or relative.is_absolute()
                        or ".." in relative.parts or not SHA256.fullmatch(digest)):
                    continue
                found.setdefault(cited, (kind, folder, root.joinpath(folder, *inner, *relative.parts), root, digest))
        return found

    def _timeline(self, path: Path, scope: tuple[str, str] | None) -> dict[str, list[tuple[str, str, int | None]]]:
        """artifact id -> [(time, file sha256, row)] from one core report's own timeline.

        ``scope`` picks the report: None for the run's core report, or the
        archive or disk image whose separate core run produced the finding.
        The times were set by the parsers; only well-formed ones are kept.
        """
        if scope is None:
            report = path / "core" / "case_report.json"
        else:
            report = path / ("archive-runs" if scope[0] == "archive" else "disk-runs") / scope[1] / "core" / "case_report.json"
        # A run's event times never change; the draft and manifest times identify the run.
        key = (_sig(path / DRAFT_JSON), _sig(path / MANIFEST_FILE))
        with self._cache_lock:
            held = self._timelines.get(str(report))
            if held and held[0] == key:
                self._timelines.move_to_end(str(report))
                return held[1]
        index: dict[str, list[tuple[str, str, int | None]]] = {}
        try:
            events = _read_json(report).get("timeline", []) if stays_in_tree(report, path) else []
        except Exception:  # noqa: BLE001 - no core report means no event times
            events = []
        for event in events if isinstance(events, list) else []:
            related = event.get("related") if isinstance(event, dict) else None
            when = _safe_time(event.get("timestamp")) if isinstance(event, dict) else None
            if not isinstance(related, dict) or when is None or not isinstance(related.get("artifact_id"), str):
                continue
            cited = related.get("citation") if isinstance(related.get("citation"), dict) else {}
            rows = index.setdefault(related["artifact_id"], [])
            if len(rows) < 8:
                rows.append((when, str(cited.get("sha256") or "").lower(), _int_or_none(cited.get("row"))))
        with self._cache_lock:
            self._timelines[str(report)] = (key, index)
            while len(self._timelines) > 8:
                self._timelines.popitem(last=False)
        return index

    def event_times(self, path: Path, draft: dict[str, Any]) -> dict[str, str | None]:
        """finding id -> time of the event it cites, looked up by citation artifact id. Never read from text."""
        members = self._members(path)
        out: dict[str, str | None] = {}
        for finding in draft.get("findings", []):
            times = []
            for citation in finding.get("citations", [])[:MAX_CITATIONS]:
                member = members.get(str(citation.get("source_file")))
                scope = (member[0], member[1]) if member and finding.get("worker") in {"archive", "disk_image"} else None
                digest, row = str(citation.get("sha256") or "").lower(), citation.get("row")
                for when, event_digest, event_row in self._timeline(path, scope).get(str(citation.get("artifact_id")), []):
                    # The same id in another file, or another row of this one, is a different event.
                    if event_digest and event_digest != digest:
                        continue
                    if event_row is not None and row is not None and event_row != row:
                        continue
                    times.append(when)
            out[finding["finding_id"]] = min(times, key=timeline_sort_key) if times else None
        return out

    def artifact_details(self, path: Path) -> dict[str, Any]:
        """finding id -> the detail the disk-artefact agent kept for it in the disk summaries."""
        base = path / "disk"
        files = sorted(base.glob("*/disk_summary.json"))[:MAX_DISK_ITEMS] if base.is_dir() else []
        key = tuple((str(f), f.stat().st_size, f.stat().st_mtime_ns) for f in files)
        with self.lock:
            cached = self._artifact_cache.get(str(path))
            if cached and cached[0] == key:
                self._artifact_cache.move_to_end(str(path))
                return cached[1]
        out: dict[str, Any] = {}
        for file in files:
            if file.is_symlink() or not stays_in_tree(file, base):
                continue
            try:
                summary = _read_json(file)
                found = summary["artifacts"]["findings"]
            except Exception:  # noqa: BLE001 - a summary without artefact details is normal
                continue
            if isinstance(found, dict):
                out.update({str(k): v for k, v in found.items() if isinstance(v, dict)})
        with self.lock:
            self._artifact_cache[str(path)] = (key, out)
            self._artifact_cache.move_to_end(str(path))
            while len(self._artifact_cache) > MAX_CACHED_ARTIFACT_RUNS:
                self._artifact_cache.popitem(last=False)
        return out

    def details_for(self, run_id: str, finding_id: str) -> dict[str, Any]:
        return artifact_view(self.artifact_details(self.run_dir(run_id)).get(finding_id))

    # ---- evidence excerpts -------------------------------------------------

    def _stripe(self, key: Any) -> threading.Lock:
        return self._stripes[hash(key) % CACHE_STRIPES]

    def _hash_large(self, file: Path, descriptor: int, status: os.stat_result) -> str:
        """SHA-256 of a file too large to read whole, through its open descriptor.

        Remembered by path and identity (device, inode, size, modified and
        changed time), so opening ten findings that cite one 2 GB image hashes
        it once, and a file rewritten with its modified time set back is
        hashed again. Two requests for the same file share the work.
        """
        key = (str(file), *_identity(status))
        with self._stripe(key):
            with self._cache_lock:
                if key in self._hashes:
                    self._hashes.move_to_end(key)
                    return self._hashes[key]
            digest = _sha256_fd(descriptor, status.st_size)
            _still_same(file, descriptor, status)
            with self._cache_lock:
                self._hashes[key] = digest
                while len(self._hashes) > MAX_CACHED_HASHES:
                    self._hashes.popitem(last=False)
            return digest

    @contextmanager
    def _pinned(self, file: Path) -> Iterator[_Source]:
        """Open a cited file and fingerprint it; the excerpt is read while it is held (see ``_Source``)."""
        descriptor, status = _open_regular(file)
        try:
            if status.st_size <= MAX_ROW_FILE_BYTES:
                data = _read_at(descriptor, 0, status.st_size)
                if len(data) != status.st_size or _read_at(descriptor, status.st_size, 1):
                    raise _Changed("the size changed")
                _still_same(file, descriptor, status)
                source = _Source(file, descriptor, status, data, hashlib.sha256(data).hexdigest())
            else:
                source = _Source(file, descriptor, status, None, self._hash_large(file, descriptor, status))
            yield source
        finally:
            os.close(descriptor)

    def _record_text(self, source: _Source, row: int) -> str | None:
        """The text of record ``row`` of a file the core parses into records (an event log, a registry hive).

        Records are parsed from the checked bytes (a private copy of them) and
        kept for the last two files, unless there is too much text to keep;
        then parsing stops at the cited record.
        """
        from auto_forensics import verifier
        from auto_forensics.plugins import ArtifactParserRegistry

        key = (source.file.name, source.digest)
        with self._stripe(key):
            with self._cache_lock:
                held = self._records.get(key)
                if held is not None:
                    self._records.move_to_end(key)
            if held is not None:
                return held.get(row)
            registry = ArtifactParserRegistry()
            registry.register_defaults()
            if source.data is not None:
                with _snapshot(source.file.name, source.data) as copy:
                    events = registry.parse(copy)
            else:
                # Too large to copy: parsed where it is, and refused if it changed meanwhile.
                events = registry.parse(source.file)
                source.check()
            rows: dict[int, str] = {}
            found: str | None = None
            size = 0
            keep = True
            for index, event in enumerate(events, start=1):
                recorded = event.metadata.get("row")
                number = recorded if isinstance(recorded, int) and recorded >= 1 else index
                if keep:
                    if number in rows:
                        continue
                    rows[number] = verifier._event_text(event)[:MAX_EXCERPT_CHARS + 1]
                    size += len(rows[number])
                    if number == row:
                        found = rows[number]
                    if size > MAX_CACHED_RECORD_CHARS:
                        keep, rows = False, {}
                        if found is not None:
                            break
                elif number == row:
                    found = verifier._event_text(event)[:MAX_EXCERPT_CHARS + 1]
                    break
            if keep:
                with self._cache_lock:
                    self._records[key] = rows
                    while len(self._records) > MAX_CACHED_RECORD_FILES:
                        self._records.popitem(last=False)
            return found

    def _cited_text(self, finding: dict[str, Any], citation: dict[str, Any], source: _Source) -> tuple[str | None, str]:
        """(text, what it is) for one citation of a file whose fingerprint was just confirmed."""
        from auto_forensics import verifier

        file = source.file
        row, offset = citation.get("row"), citation.get("offset")
        if type(row) is int and row >= 1:
            if finding.get("worker") == "memory":
                return None, ("This finding points to a process found in a memory image. "
                              "There is no line of text to show for it.")
            if str(citation.get("artifact_id") or "").startswith("file-"):
                # A text-scanning agent: the row is a physical line of the part of the file it scanned.
                text = next((line for number, line in lines_of(source.read(0, MAX_SCAN_BYTES)) if number == row), None)
                what = f"Line {row} of this file"
            elif verifier._is_structured_artifact(file):
                text = self._record_text(source, row)
                what = f"Record {row} of this file, as the tool reads it"
            elif source.data is None:
                return None, (f"This file is too large to show a row from here. "
                              f"Open it in a viewer and go to row {row}.")
            elif file.suffix.lower() == ".csv":
                text = _csv_fields(source.data, row)
                what = f"Row {row} of this file, with the column names from its first line"
            else:
                # The core's own row reader, so the row shown is the row its verifier checked,
                # run on a private copy of the bytes that were just fingerprinted.
                with _snapshot(file.name, source.data) as copy:
                    text = verifier._read_row(copy, row)
                if text is not None:
                    text = _json_record(text)
                what = f"Row {row} of this file"
            if text is None:
                return None, f"Row {row} could not be found in this file."
            return text, f"{what}, read again just now."
        start = offset if type(offset) is int and offset >= 0 else 0
        start -= start % 16
        data = source.read(start, HEX_WINDOW)
        if not data:
            return None, "This file is shorter than the position the finding points to."
        return _hex_dump(data, start), (f"{len(data)} bytes starting at byte {start}, shown as hexadecimal "
                                        "with the readable characters on the right.")

    def _citation_view(self, finding: dict[str, Any], citation: dict[str, Any], evidence: Path,
                       inventory: dict[str, str], members: dict[str, tuple[str, str, Path, Path, str]],
                       hostile: set[str]) -> dict[str, Any]:
        name = str(citation.get("source_file") or "")
        digest = str(citation.get("sha256") or "").lower()
        view: dict[str, Any] = {
            "source_file": _text(name, 400), "row": _int_or_none(citation.get("row")),
            "offset": _int_or_none(citation.get("offset")), "sha256": digest if SHA256.fullmatch(digest) else "",
            "file_ok": False, "excerpt": None, "excerpt_note": "",
        }

        def stop(note: str) -> dict[str, Any]:
            view.update(file_ok=False, excerpt=None, excerpt_note=note)
            return view

        # Where the file is and which fingerprint it must have: from the custody record, or for a file
        # copied out of an archive or disk image, from the list written when it was copied. The same
        # order the coordinator uses, so a real evidence file is never shadowed by a copy.
        key = Path(name).as_posix() if name else ""
        relative = PurePosixPath(key)
        located: tuple[Path, Path, str] | None = None
        if key in inventory and not relative.is_absolute() and ".." not in relative.parts:
            located = (evidence.joinpath(*relative.parts), evidence, inventory[key])
        elif name in members:
            located = (members[name][2], members[name][3], members[name][4])
        elif key and "/" not in key:
            # The core cites some files by name alone; the custody record says which file that is.
            same = [path for path in inventory if path.rsplit("/", 1)[-1] == key]
            if len(same) > 1:
                same = [path for path in same if inventory[path] == digest]
            if len(same) == 1:
                located = (evidence.joinpath(*PurePosixPath(same[0]).parts), evidence, inventory[same[0]])
        if located is None:
            return stop("This file is not in the list of evidence recorded when the run started, so it cannot be shown.")
        file, root, expected = located
        if not SHA256.fullmatch(digest) or digest != expected:
            return stop("The fingerprint in this finding is not the one recorded for this file when the run "
                        "started, so its contents are not shown.")
        if not stays_in_tree(file, root):
            return stop("This file could not be found where the run read it. It may have been moved or renamed, "
                        "or its drive is not connected.")
        try:
            with self._pinned(file) as source:
                if source.digest != expected:
                    return stop("This file has changed since the run started: its fingerprint no longer matches. "
                                "Its contents are not shown.")
                view["file_ok"] = True
                try:
                    text, note = self._cited_text(finding, citation, source)
                except _Changed:
                    raise
                except Exception as exc:  # noqa: BLE001 - only the type; a library message can quote the file
                    text, note = None, ("The file is unchanged, but this part of it could not be read "
                                        f"({type(exc).__name__}).")
                source.check()
        except _Changed:
            return stop("This file changed while it was being read, so its contents are not shown.")
        except OSError as exc:
            return stop(f"This file could not be read ({type(exc).__name__}).")
        if text is not None:
            view["excerpt"], cut = _excerpt(text)
            note += " The file still matches the fingerprint recorded when the run started."
            if cut:
                note += f" Only the first {MAX_EXCERPT_CHARS:,} characters are shown."
            if name in hostile:
                note += " Warning: this file contains text written to mislead an AI. Treat what it says as untrusted."
        view["excerpt_note"] = note
        return view

    def evidence_for(self, run_id: str, finding_id: str) -> dict[str, Any]:
        """The cited rows of one finding, re-read from the evidence for the analyst to check by eye.

        Nothing here is written to a report or a log, and nothing is read
        from a file whose SHA-256 no longer matches the custody record.
        """
        path = self.run_dir(run_id)
        draft, manifest = signoff._load(path)
        custody = read_json(path / CUSTODY_FILE)
        if canonical_sha256(custody) != manifest.get("custody_sha256"):
            raise SecurityError("The custody record was changed after the run")
        finding = next((f for f in draft["findings"] if f.get("finding_id") == finding_id), None)
        if finding is None:
            raise LookupError("finding")
        evidence = Path(custody["evidence_dir"])
        inventory = {Path(row["path"]).as_posix(): str(row["sha256"]).lower() for row in custody["files"]}
        members = self._members(path)
        hostile = {str(item) for item in draft.get("hostile_files") or []}
        return {"citations": [self._citation_view(finding, citation, evidence, inventory, members, hostile)
                              for citation in finding.get("citations", [])[:MAX_CITATIONS]]}

    # ---- exported report ---------------------------------------------------

    def report_link(self, run_id: str) -> str:
        """A link to the exported HTML report that works for five minutes and cannot be guessed."""
        self.run_dir(run_id)
        folder = self.exported_to(run_id)
        if folder is None:
            raise SecurityError("This run has not been exported yet. Sign it and export it first.")
        nonce = secrets.token_urlsafe(32)
        with self.lock:
            now = self.clock()
            self.report_links = {key: link for key, link in self.report_links.items() if link[2] > now}
            while len(self.report_links) >= MAX_REPORT_LINKS:
                self.report_links.pop(min(self.report_links, key=lambda key: self.report_links[key][2]))
            self.report_links[nonce] = (run_id, folder, now + REPORT_LINK_SECONDS)
        return f"/report/{nonce}"

    def report_page(self, nonce: str) -> str | None:
        """The report a live link points to, or None for a wrong, malformed or expired one."""
        if not NONCE.fullmatch(nonce or ""):
            return None
        given = nonce.encode("ascii")
        found: tuple[str, Path, float] | None = None
        with self.lock:
            now = self.clock()
            self.report_links = {key: link for key, link in self.report_links.items() if link[2] > now}
            for key, link in self.report_links.items():
                if secrets.compare_digest(key.encode("ascii"), given):
                    found = link
        if found is None:
            return None
        run_id, folder, _ = found
        page = folder / signoff.FINAL_HTML
        try:
            if stays_in_tree(page, self.exports):
                if page.stat().st_size > MAX_REPORT_BYTES:
                    return None
                return page.read_text(encoding="utf-8")
            # An export made before the HTML report existed: build the page from its final report.
            final = folder / signoff.FINAL_JSON
            if not stays_in_tree(final, self.exports):
                return None
            manifest_path = self.runs / run_id / MANIFEST_FILE
            manifest = _read_json(manifest_path) if manifest_path.is_file() else {}
            return render_html(_read_json(final), manifest)
        except Exception as exc:  # noqa: BLE001
            _say(f"Report for {run_id} could not be opened: {type(exc).__name__}")
            return None

    # ---- info and disks ----------------------------------------------------

    def info(self) -> dict[str, Any]:
        reader = evtx_reader_name()
        now = time.monotonic()
        if self._ollama is None or now - self._ollama[0] > OLLAMA_CACHE_SECONDS:
            self._ollama = (now, ollama_reachable())
        return {
            "version": AUTOPILOT_VERSION, "core_version": CORE_VERSION, "workspace": str(self.workspace),
            "features": {"evtx": None if reader == "none" else reader, "yara": _has_module("yara"),
                         "disk_images": disk_support()[0], "ollama": self._ollama[1]},
        }

    def disks(self, run_id: str) -> dict[str, Any]:
        path = self.run_dir(run_id)
        disks = []
        base = path / "disk"
        folders = sorted(p for p in base.iterdir() if p.is_dir() and not p.is_symlink()) if base.is_dir() else []
        for folder in folders[:MAX_DISK_ITEMS]:
            summary = folder / "disk_summary.json"
            if not stays_in_tree(summary, base):
                continue
            try:
                disks.append(disk_view(_read_json(summary), folder.name))
            except Exception as exc:  # noqa: BLE001 - one unreadable summary must not hide the others
                view = disk_view({}, folder.name)
                view["gaps"] = [f"The summary of this image could not be read ({type(exc).__name__})."]
                disks.append(view)
        return {"disks": disks}


class StartBody(BaseModel):
    input_dir: str = Field(max_length=4096)
    case_id: str = Field(max_length=64)
    actor: str = Field(max_length=120)
    llm: str = "mock"


class DecideBody(BaseModel):
    finding_ids: list[str] = Field(max_length=5000)
    decision: str
    actor: str = Field(max_length=120)
    note: str = Field(default="", max_length=2000)
    override: bool = False


class SignBody(BaseModel):
    actor: str = Field(max_length=120)
    fingerprint: str = Field(max_length=128)
    statement: str = Field(default="", max_length=2000)
    accept_gaps: bool = False


class ExportBody(BaseModel):
    signature: str = Field(max_length=128)


class CopiedBody(BaseModel):
    kind: str


def _error(status: int, message: str) -> Any:
    from fastapi import HTTPException

    return HTTPException(status_code=status, detail=message)


def create_app(state: ReviewState) -> Any:
    from fastapi import FastAPI, Query, Request
    from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse

    app = FastAPI(title="Auto Forensics review", docs_url=None, redoc_url=None, openapi_url=None)
    token = state.token.encode("ascii")

    def refuse(status: int, message: str) -> Any:
        return JSONResponse({"detail": message}, status_code=status)

    @app.middleware("http")
    async def guard(request: Request, call_next: Any) -> Any:
        host = (request.headers.get("host") or "").split(":")[0]
        if host not in {"127.0.0.1", "localhost"}:
            return refuse(403, "This server only answers on 127.0.0.1")
        if request.url.path.startswith("/api/"):
            # Checked before the body is read, so no other page can make the server buffer anything.
            given = (request.headers.get("x-session-token") or "").encode("utf-8", "replace")
            if not secrets.compare_digest(given, token):
                return refuse(401, "Open the page from the link printed when the server started")
            if request.method == "POST":
                if (request.headers.get("content-type") or "").split(";")[0].strip() != "application/json":
                    return refuse(415, "Send JSON")
                length = request.headers.get("content-length")
                if length is None or not length.isdigit():
                    return refuse(411, "Content-Length is required")
                if int(length) > MAX_BODY:
                    return refuse(413, "Request too large")
        response = await call_next(request)
        if request.url.path.startswith("/report/"):
            # The report is a file from the exports folder. It may use its own inline styles and nothing
            # else, and the sandbox keeps it out of this server's origin even if the file was replaced.
            response.headers["Content-Security-Policy"] = REPORT_CSP
            response.headers["X-Frame-Options"] = "DENY"
        else:
            response.headers["Content-Security-Policy"] = PAGE_CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/")
    def page() -> Any:
        return FileResponse(STATIC / "review.html", media_type="text/html")

    @app.get("/static/{name}")
    def asset(name: str) -> Any:
        allowed = {"review.css": "text/css", "review.js": "text/javascript"}
        if name not in allowed:
            raise _error(404, "Not found")
        return FileResponse(STATIC / name, media_type=allowed[name])

    @app.get("/report/{nonce}")
    def report(nonce: str) -> Any:
        content = state.report_page(nonce)
        if content is None:
            return PlainTextResponse("This report link has expired or is not valid. Go back to the review page "
                                     "and open the report again.", status_code=404)
        return HTMLResponse(content)

    @app.get("/api/info")
    def info() -> Any:
        return state.info()

    @app.get("/api/browse")
    def browse_folder(path: str = Query(default="", max_length=MAX_PATH_CHARS)) -> Any:
        return browse(path)

    @app.get("/api/runs")
    def runs() -> Any:
        return {"workspace": str(state.workspace), "runs": state.list_runs()}

    @app.post("/api/runs")
    def new_run(body: StartBody) -> Any:
        try:
            return {"run_id": state.start_run(body.input_dir, body.case_id.strip(), body.actor, body.llm)}
        except SecurityError as exc:
            raise _error(400, str(exc)[:300]) from exc

    @app.get("/api/runs/{run_id}")
    def run(run_id: str) -> Any:
        progress = state.progress(run_id)
        if progress is not None:
            return {"run_id": run_id, "state": "running", "progress": progress}
        job = state.jobs.get(run_id, {})
        if job.get("state") == "failed":
            return {"run_id": run_id, "state": "failed", "error": job.get("error", ""),
                    "started_at": job.get("started_at"), "evidence_folder": job.get("evidence_folder"),
                    "can_remove": state.can_remove(run_id)}
        try:
            path = state.run_dir(run_id)
            if not ((path / DRAFT_JSON).is_file() and (path / MANIFEST_FILE).is_file()):
                started, folder = state._custody_facts(path)
                return {"run_id": run_id, "state": "incomplete", "error": "This run stopped before it finished.",
                        "started_at": started, "evidence_folder": folder, "can_remove": state.can_remove(run_id)}
            draft = read_json(path / DRAFT_JSON)
            status = signoff.status(path)
            decisions = signoff.latest_decisions(signoff.read_log(path))
            times = state.event_times(path, draft)
            artifact_details = state.artifact_details(path)
            for finding in draft["findings"]:
                # Importers copy evidence text into titles; the page needs only enough to recognise one.
                finding["title"] = _capped(finding.get("title"), MAX_TITLE_CHARS)
                finding["recommendation"] = _capped(finding.get("recommendation"), MAX_RECOMMENDATION_CHARS)
                choice = decisions.get(finding["finding_id"]) or {}
                finding["decision"] = choice.get("decision") if choice.get("decision") in signoff.DECISIONS else "pending"
                finding["decided_by"] = str(choice.get("actor", ""))
                finding["note"] = str(choice.get("note", ""))
                finding["event_time"] = times.get(finding["finding_id"])
                if finding["event_time"] is None and finding.get("worker") == "disk_artifacts":
                    finding["event_time"] = artifact_time(artifact_details.get(finding["finding_id"]))
            started, folder = state._custody_facts(path)
            finished = _safe_time(read_json(path / MANIFEST_FILE).get("finished_at"))
        except SecurityError as exc:
            raise _error(404, f"Run could not be opened: {str(exc)[:200]}") from exc
        except Exception as exc:  # noqa: BLE001
            raise _error(404, f"Run could not be opened: a run file is missing or malformed ({type(exc).__name__})") from exc
        exported = state.exported_to(run_id)
        with state.lock:
            held = dict(state.shown.get(run_id, {}))
        return {"run_id": run_id, "state": "done", "draft": draft, "status": status, "fingerprints": held,
                "final": {"folder": str(exported)} if exported else None,
                "evidence_folder": folder, "started_at": started, "finished_at": finished, "can_remove": False}

    @app.delete("/api/runs/{run_id}")
    def remove(run_id: str) -> Any:
        try:
            moved = state.remove_run(run_id)
        except SecurityError as exc:
            message = str(exc)[:300]
            raise _error(404 if message == "Unknown run" else 400, message) from exc
        return {"removed": True, "run_id": run_id, "moved_to": moved}

    @app.get("/api/runs/{run_id}/findings/{finding_id}/evidence")
    def evidence(run_id: str, finding_id: str) -> Any:
        try:
            return state.evidence_for(run_id, finding_id)
        except LookupError as exc:
            raise _error(404, "This finding is not in the draft") from exc
        except SecurityError as exc:
            message = str(exc)[:300]
            raise _error(404 if message == "Unknown run" else 400, message) from exc
        except Exception as exc:  # noqa: BLE001
            raise _error(400, f"The evidence could not be opened: a run file is missing or malformed "
                              f"({type(exc).__name__})") from exc

    @app.get("/api/runs/{run_id}/findings/{finding_id}/details")
    def details(run_id: str, finding_id: str) -> Any:
        try:
            return state.details_for(run_id, finding_id)
        except SecurityError as exc:
            raise _error(404, str(exc)[:200]) from exc
        except Exception as exc:  # noqa: BLE001
            raise _error(400, f"The details could not be read ({type(exc).__name__})") from exc

    @app.get("/api/runs/{run_id}/disks")
    def disks(run_id: str) -> Any:
        try:
            return state.disks(run_id)
        except SecurityError as exc:
            raise _error(404, str(exc)[:200]) from exc

    @app.post("/api/runs/{run_id}/copied")
    def copied(run_id: str, body: CopiedBody) -> Any:
        if body.kind not in {"run_fingerprint", "signature_fingerprint"}:
            raise _error(400, "Unknown fingerprint")
        state.confirm_copied(run_id, body.kind)
        return {"ok": True}

    @app.post("/api/runs/{run_id}/decide")
    def decide(run_id: str, body: DecideBody) -> Any:
        try:
            done = state.decide(run_id, body.finding_ids, body.decision, body.actor, body.note, body.override)
        except SecurityError as exc:
            raise _error(400, str(exc)[:400]) from exc
        except Exception as exc:  # noqa: BLE001
            raise _error(400, f"Run files could not be read ({type(exc).__name__})") from exc
        return {"decided": done}

    @app.post("/api/runs/{run_id}/sign")
    def sign(run_id: str, body: SignBody) -> Any:
        try:
            signature = signoff.sign(state.run_dir(run_id), actor=body.actor, fingerprint_seen=body.fingerprint,
                                     statement=body.statement, accept_gaps=body.accept_gaps)
        except SecurityError as exc:
            raise _error(400, str(exc)[:300]) from exc
        fp = signature["signature_fingerprint"]
        with state.lock:
            state.shown[run_id] = {"signature_fingerprint": fp}
        _say(f"Run {run_id} signed by {signature['actor']}. Signature fingerprint: {fp}")
        return {"signed_at": signature["signed_at"], "signature_fingerprint": fp, "sealed": bool(signature.get("seal"))}

    @app.post("/api/runs/{run_id}/export")
    def export(run_id: str, body: ExportBody) -> Any:
        try:
            path = state.run_dir(run_id)
            dest = state.exports / f"{run_id}-export-{_stamp()}"
            final = signoff.export(path, dest, signature_seen=body.signature)
        except SecurityError as exc:
            raise _error(400, str(exc)[:300]) from exc
        state.confirm_copied(run_id, "signature_fingerprint")
        _say(f"Run {run_id} exported to {dest}")
        return {"folder": str(dest), "headline": final["headline"], "status": final["status"]}

    @app.post("/api/runs/{run_id}/report-link")
    def report_link(run_id: str) -> Any:
        try:
            return {"url": state.report_link(run_id)}
        except SecurityError as exc:
            message = str(exc)[:300]
            raise _error(404 if message == "Unknown run" else 400, message) from exc

    return app


def serve(workspace: Path, port: int = 8765, open_browser: bool = True) -> int:
    import uvicorn

    # Bind first: if the port is taken, nothing is printed or opened that another program could read.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if sys.platform == "win32":
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    else:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("127.0.0.1", port))
    except OSError:
        sock.close()
        print(f"Port {port} is already in use. Close the other Auto Forensics window, or start with --port 8766.",
              file=sys.stderr)
        return 2
    sock.listen(64)
    state = ReviewState(workspace)
    url = f"http://127.0.0.1:{port}/#token={state.token}"
    print("Auto Forensics review page")
    print(f"  Workspace: {state.workspace}")
    print(f"  Open:      {url}")
    print("  Keep this window open while you work. Press Ctrl+C to stop.")
    print("  Fingerprints are printed here as well; keep them with your case notes.", flush=True)
    launched: list[tuple[Path, threading.Timer]] = []
    if open_browser:
        # The browser gets a private file that forwards to the page, never the token on its command line.
        opener = threading.Timer(1.0, lambda: launched.append(open_in_browser(url)))
        opener.daemon = True
        opener.start()
    server = uvicorn.Server(uvicorn.Config(create_app(state), log_level="warning"))
    try:
        server.run(sockets=[sock])
    finally:
        if open_browser:
            opener.cancel()
        for page, timer in launched:
            timer.cancel()
            remove_launcher(page)
    return 0
