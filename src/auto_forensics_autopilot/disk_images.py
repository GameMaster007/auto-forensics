"""Read disk images (raw/DD, split raw, EnCase E01, VMDK) and copy out key artefacts.

The image in the evidence folder is opened read-only with dissect.target
(the optional ``disk`` extra) and is never changed. A bounded set of
high-value files is copied into ``<run>/disk/<name>-<hash8>/files/``:
event logs, registry hives, Prefetch, LNK files and Jump Lists, browser
history, PowerShell history, scheduled tasks, USB setup logs, Recycle
Bin index files, and the Google Drive sync client's databases and log. Each
copy is hashed while it is written and recorded in
``disk_images.json``. Findings about a copied file cite it as
``<image path>!/<drive>/<path in image>``, for example
``pc.E01!/C:/Windows/System32/winevt/Logs/Security.evtx``.

A small ``disk_summary.json`` sits next to the copies: the OS, host name,
users, USB devices, installed programs and recent files, as dissect
reports them. Every dissect call is wrapped; a failure becomes a coverage
gap, never a crash.

Skipped, and listed as a coverage gap: names that cannot be stored safely
(traversal, control or reserved characters, Windows device names, names
that differ only by case), links, files over ``MAX_FILE_BYTES``, and
anything past the byte or file budget.
"""

from __future__ import annotations

import fnmatch
import hashlib
import importlib.util
import os
import re
import time
from dataclasses import asdict, dataclass, field
from itertools import islice
from pathlib import Path, PurePosixPath
from typing import Any, Iterator

from auto_forensics.security import SecurityError

SEPARATOR = "!"
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_FILES = 5_000
MAX_WALK_DEPTH = 12
MAX_DIR_ENTRIES = 50_000
MAX_PLUGIN_ROWS = 500
MAX_LISTING_ROWS = 2_000
SUMMARY_SECONDS = 300
MAX_WINDOWS_PATH = 250
INSTALL_HINT = "install the disk extra: pip install 'auto-forensics-framework[disk]'"

_WINDOWS_DEVICES = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$"} | {
    f"{prefix}{digit}" for prefix in ("COM", "LPT") for digit in "0123456789¹²³"
}
_BAD_CHARS = set('<>:"|?*\\/')

USER_DIRS = ("Users/*", "Documents and Settings/*")

# (category, pattern relative to a volume root). Matching ignores case.
# "*" matches one folder or file name; "**" matches any depth of folders.
ARTEFACTS: tuple[tuple[str, str], ...] = (
    ("event_log", "Windows/System32/winevt/Logs/*.evtx"),
    ("event_log", "Windows/System32/config/*.evt"),
    ("registry", "Windows/System32/config/SYSTEM"),
    ("registry", "Windows/System32/config/SOFTWARE"),
    ("registry", "Windows/System32/config/SAM"),
    ("registry", "Windows/System32/config/SECURITY"),
    ("registry", "Windows/AppCompat/Programs/Amcache.hve"),
    ("registry", "{user}/NTUSER.DAT"),
    ("registry", "Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat"),
    ("prefetch", "Windows/Prefetch/*.pf"),
    ("lnk", "{user}/AppData/Roaming/Microsoft/Windows/Recent/*.lnk"),
    ("lnk", "{user}/AppData/Roaming/Microsoft/Office/Recent/*.lnk"),
    ("lnk", "Documents and Settings/*/Recent/*.lnk"),
    ("jump_list", "Users/*/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/*.automaticDestinations-ms"),
    ("jump_list", "Users/*/AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations/*.customDestinations-ms"),
    ("browser", "Users/*/AppData/Local/Google/Chrome/User Data/*/History"),
    ("browser", "Users/*/AppData/Local/Microsoft/Edge/User Data/*/History"),
    ("browser", "{user}/AppData/Roaming/Mozilla/Firefox/Profiles/*/places.sqlite"),
    ("browser", "Users/*/AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.dat"),
    ("browser", "Users/*/AppData/Local/Microsoft/Windows/History/History.IE5/index.dat"),
    ("browser", "Users/*/AppData/Local/Microsoft/Windows/History/History.IE5/*/index.dat"),
    ("browser", "Documents and Settings/*/Local Settings/History/History.IE5/index.dat"),
    ("powershell", "Users/*/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt"),
    ("scheduled_task", "Windows/System32/Tasks/**/*"),
    ("scheduled_task", "Windows/Tasks/*.job"),
    ("usb", "Windows/inf/setupapi.dev.log"),
    ("usb", "Windows/setupapi.log"),
    ("recycle_bin", "$Recycle.Bin/*/$I*"),
    ("cloud", "Users/*/AppData/Local/Google/Drive/*/snapshot.db"),
    ("cloud", "Users/*/AppData/Local/Google/Drive/*/sync_config.db"),
    ("cloud", "Users/*/AppData/Local/Google/Drive/*/sync_log.log"),
)
MFT = ("mft", "$MFT")

# Properties and record plugins for disk_summary.json. Each is optional.
SUMMARY_PROPERTIES = ("hostname", "os", "version", "install_date", "activity", "timezone", "domain")
SUMMARY_PLUGINS = ("users", "usb", "applications", "runkeys", "lnk", "recyclebin", "userassist", "services")


def disk_support() -> tuple[bool, str]:
    """(installed, why not) for the optional dissect.target dependency."""
    try:
        found = importlib.util.find_spec("dissect.target") is not None
    except (ImportError, ValueError):
        found = False
    if found:
        return True, ""
    return False, f"dissect.target is not installed; {INSTALL_HINT}"


def _dissect_version() -> str:
    try:
        from importlib.metadata import version

        return version("dissect.target")
    except Exception:  # noqa: BLE001 - only a label
        return "unknown"


class DiskBudget:
    """Bytes and files copied out of every disk image in one run."""

    def __init__(self, total_bytes: int = MAX_TOTAL_BYTES, max_files: int = MAX_FILES,
                 file_bytes: int = MAX_FILE_BYTES) -> None:
        self.total_bytes = total_bytes
        self.max_files = max_files
        self.file_bytes = file_bytes
        self.used_bytes = 0
        self.used_files = 0

    def refusal(self, size: int) -> str | None:
        """Why a file of ``size`` bytes may not be copied, or None."""
        if size > self.file_bytes:
            return f"file is larger than the per-file limit ({self.file_bytes // (1024 * 1024)} MB)"
        if self.used_files >= self.max_files:
            return f"file-count budget reached ({self.max_files} files)"
        if self.used_bytes + size > self.total_bytes:
            return f"byte budget reached ({self.total_bytes // (1024 * 1024)} MB)"
        return None

    def take(self, size: int) -> None:
        reason = self.refusal(size)
        if reason:
            raise SecurityError(reason)
        self.used_bytes += size
        self.used_files += 1


def safe_component(name: str) -> str:
    """Return ``name`` if it can be a file or folder name on Windows, macOS and Linux; else raise."""
    if not name or name in {".", ".."} or len(name) > 255:
        raise SecurityError("Image path has an empty, dot, or overlong name")
    if any(ord(ch) < 32 or ch == "\x7f" for ch in name) or any(ch in _BAD_CHARS for ch in name):
        raise SecurityError("Image path has a control or reserved character")
    if name[-1] in {" ", "."}:
        raise SecurityError("Image path ends with a space or dot")
    if name.split(".")[0].rstrip(" ").upper() in _WINDOWS_DEVICES:
        raise SecurityError("Image path uses a Windows device name")
    if SEPARATOR in name:
        raise SecurityError("Image path contains the citation separator")
    return name


def volume_label(mount: str) -> str:
    """``c:`` -> ``C:``; anything else must already be a safe name."""
    if re.fullmatch(r"[A-Za-z]:", mount):
        return mount.upper()
    return safe_component(mount)


def folder_for(label: str) -> str:
    """Folder name for a volume on disk: ``C:`` -> ``C``."""
    return label[0] if re.fullmatch(r"[A-Z]:", label) else label


@dataclass(slots=True)
class DiskMember:
    image: str
    image_sha256: str
    member: str
    extracted: str
    sha256: str
    size_bytes: int
    category: str
    modified: str = ""

    @property
    def cited_as(self) -> str:
        return f"{self.image}{SEPARATOR}{self.member}"

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["cited_as"] = self.cited_as
        return data


@dataclass(slots=True)
class DiskResult:
    members: list[DiskMember] = field(default_factory=list)
    gaps: list[dict[str, str]] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)

    def gap(self, what: str, why: str) -> None:
        self.gaps.append({"what": what, "why": why})


# --------------------------------------------------------------------------
# Segments
# --------------------------------------------------------------------------

_EWF_SEGMENT = re.compile(r"^(?P<base>.+)\.(?P<kind>ex|lx|e|l|s)(?P<seq>\d\d|[a-z]{2})$", re.IGNORECASE)
_SPLIT_SEGMENT = re.compile(r"^(?P<base>.+)\.(?P<seq>\d{3})$")
_VMDK_EXTENT = re.compile(r"^(?P<base>.+)-(flat|delta|s\d{3}|f\d{3})\.vmdk$", re.IGNORECASE)


def group_images(paths: list[str]) -> tuple[dict[str, list[str]], list[str]]:
    """Split disk-image files into {first file: [all its segments]} and orphan segments.

    The first file is what dissect opens: ``.E01``, ``.001``, the VMDK
    descriptor, or a single raw file. Later segments are found by dissect
    from the first; they are listed here for the custody record.
    """
    by_key = {path.casefold(): path for path in paths}
    groups: dict[str, list[str]] = {}
    orphans: list[str] = []
    parent: dict[str, str] = {}
    for path in sorted(paths):
        ewf = _EWF_SEGMENT.match(path)
        split = _SPLIT_SEGMENT.match(path)
        vmdk = _VMDK_EXTENT.match(path)
        first: str | None = None
        if ewf:
            kind = ewf["kind"]
            first = f"{ewf['base']}.{kind}01"
        elif split:
            first = f"{split['base']}.001"
        elif vmdk:
            descriptor = by_key.get(f"{vmdk['base']}.vmdk".casefold())
            first = descriptor if descriptor is not None else path
        if first is None or first.casefold() == path.casefold():
            groups.setdefault(path, [])
            parent[path] = path
            continue
        owner = by_key.get(first.casefold())
        if owner is None:
            orphans.append(path)
            continue
        parent[path] = owner
    for path, owner in parent.items():
        groups.setdefault(owner, [])
        groups[owner].append(path)
    return {key: sorted(value) for key, value in sorted(groups.items())}, orphans


# --------------------------------------------------------------------------
# Walking an image without following links
# --------------------------------------------------------------------------


def _children(directory: Any) -> list[Any]:
    entries = []
    for entry in islice(directory.iterdir(), MAX_DIR_ENTRIES):
        entries.append(entry)
    return entries


def _is_link(entry: Any) -> bool:
    try:
        return bool(entry.is_symlink())
    except Exception:  # noqa: BLE001 - treat unreadable entries as links: skip them
        return True


def _is_dir(entry: Any) -> bool:
    try:
        return bool(entry.is_dir()) and not _is_link(entry)
    except Exception:  # noqa: BLE001
        return False


def _is_file(entry: Any) -> bool:
    try:
        return bool(entry.is_file()) and not _is_link(entry)
    except Exception:  # noqa: BLE001
        return False


def match_pattern(root: Any, pattern: str) -> Iterator[tuple[list[str], Any]]:
    """Yield (path parts, entry) for files under ``root`` that match ``pattern``, ignoring case."""
    parts = pattern.split("/")

    def walk(node: Any, index: int, trail: list[str], depth: int) -> Iterator[tuple[list[str], Any]]:
        if depth > MAX_WALK_DEPTH:
            return
        piece = parts[index]
        last = index == len(parts) - 1
        if piece == "**":
            # Zero folders, then each sub-folder at any depth.
            yield from walk(node, index + 1, trail, depth)
            for child in _children(node):
                if _is_dir(child):
                    yield from walk(child, index, [*trail, child.name], depth + 1)
            return
        wanted = piece.casefold()
        for child in _children(node):
            if not fnmatch.fnmatchcase(child.name.casefold(), wanted):
                continue
            if last:
                if _is_file(child):
                    yield [*trail, child.name], child
            elif _is_dir(child):
                yield from walk(child, index + 1, [*trail, child.name], depth + 1)

    yield from walk(root, 0, [], 0)


def _patterns(include_mft: bool) -> list[tuple[str, str]]:
    expanded: list[tuple[str, str]] = []
    for category, pattern in (*ARTEFACTS, *((MFT,) if include_mft else ())):
        if "{user}" in pattern:
            expanded.extend((category, pattern.replace("{user}", base)) for base in USER_DIRS)
        else:
            expanded.append((category, pattern))
    return expanded


# --------------------------------------------------------------------------
# Opening and extracting
# --------------------------------------------------------------------------


def open_image(path: Path) -> Any:
    """Open an image read-only. dissect finds E01/split/VMDK segments from the first file."""
    if not disk_support()[0]:
        raise SecurityError(f"Disk images cannot be opened: {INSTALL_HINT}")
    from dissect.target import Target

    return Target.open_raw(path)


def _volumes(target: Any) -> list[tuple[str, Any]]:
    """(label, filesystem) for each filesystem; the label is a drive letter when dissect knows one."""
    mounts = getattr(getattr(target, "fs", None), "mounts", {}) or {}
    labels: list[tuple[str, Any]] = []
    used: set[str] = set()
    for index, fs in enumerate(list(target.filesystems)):
        letters = sorted(name for name, mounted in mounts.items() if mounted is fs and re.fullmatch(r"[a-zA-Z]:", name))
        label = volume_label(letters[0]) if letters else f"fs{index}"
        if label.casefold() in used:
            label = f"fs{index}"
        used.add(label.casefold())
        labels.append((label, fs))
    return labels


def _stat_time(entry: Any) -> str:
    try:
        from datetime import datetime, timezone

        return datetime.fromtimestamp(entry.stat().st_mtime, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except Exception:  # noqa: BLE001 - a timestamp is a convenience
        return ""


def _copy(entry: Any, target: Path, limit: int) -> tuple[str, int]:
    digest = hashlib.sha256()
    written = 0
    with entry.open() as source, target.open("xb") as sink:
        while chunk := source.read(1024 * 1024):
            written += len(chunk)
            if written > limit:
                raise SecurityError("File grew past its recorded size while copying")
            digest.update(chunk)
            sink.write(chunk)
    return digest.hexdigest(), written


def extract_artefacts(target: Any, image_rel: str, image_sha256: str, destination: Path,
                      budget: DiskBudget | None = None, *, include_mft: bool = False,
                      result: DiskResult | None = None) -> DiskResult:
    """Copy matching artefacts from every filesystem in ``target`` into ``destination``."""
    budget = budget or DiskBudget()
    result = result or DiskResult()
    destination.mkdir(parents=True, exist_ok=False)
    seen: set[str] = set()
    folded: set[str] = set()
    unsafe = 0
    case_clash = 0
    volumes = _volumes(target)
    if not volumes:
        result.gap(image_rel, "no readable filesystem in the image (unknown format or encrypted volume)")
    for label, fs in volumes:
        try:
            root = fs.path("/")
        except Exception as exc:  # noqa: BLE001
            result.gap(f"{image_rel}{SEPARATOR}/{label}", f"volume could not be read ({type(exc).__name__})")
            continue
        for category, pattern in _patterns(include_mft):
            try:
                matches = list(match_pattern(root, pattern))
            except Exception as exc:  # noqa: BLE001 - one unreadable folder must not stop the rest
                result.gap(f"{image_rel}{SEPARATOR}/{label}/{pattern}",
                           f"folder could not be listed ({type(exc).__name__})")
                continue
            for parts, entry in matches:
                try:
                    safe_parts = [safe_component(part) for part in parts]
                except SecurityError:
                    unsafe += 1
                    continue
                member = "/" + "/".join([label, *safe_parts])
                rel = PurePosixPath(folder_for(label), *safe_parts).as_posix()
                if rel in seen:
                    continue  # the same file matched by two patterns
                seen.add(rel)
                if rel.casefold() in folded:
                    case_clash += 1
                    continue
                folded.add(rel.casefold())
                cited = f"{image_rel}{SEPARATOR}{member}"
                try:
                    size = int(entry.stat().st_size)
                except Exception as exc:  # noqa: BLE001
                    result.gap(cited, f"file could not be read ({type(exc).__name__})")
                    continue
                reason = budget.refusal(size)
                if reason:
                    result.gap(cited, f"not copied: {reason}")
                    continue
                out = destination / rel
                if os.name == "nt" and len(str(out)) > MAX_WINDOWS_PATH:
                    result.gap(cited, "not copied: the path would be too long for Windows; use a shorter run folder")
                    continue
                budget.take(size)
                out.parent.mkdir(parents=True, exist_ok=True)
                try:
                    sha256, written = _copy(entry, out, size)
                except Exception as exc:  # noqa: BLE001
                    out.unlink(missing_ok=True)
                    result.gap(cited, f"file could not be copied ({type(exc).__name__})")
                    continue
                result.members.append(DiskMember(image_rel, image_sha256, member, rel, sha256, written, category,
                                                 _stat_time(entry)))
    if unsafe:
        result.gap(image_rel, f"{unsafe} file(s) skipped: their names cannot be stored safely on this computer")
    if case_clash:
        result.gap(image_rel, f"{case_clash} file(s) skipped: their names differ only by case from a copied file")
    return result


# --------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------


def _plain(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value[:50]]
    text = str(value)
    return text[:1024]


def _record_dict(record: Any) -> dict[str, Any]:
    try:
        data = record._asdict()
    except Exception:  # noqa: BLE001
        return {"value": _plain(record)}
    return {key: _plain(value) for key, value in data.items() if not key.startswith("_")}


def summarise(target: Any, *, deadline: float | None = None, max_rows: int = MAX_PLUGIN_ROWS) -> tuple[dict[str, Any], list[str]]:
    """Cheap dissect results for ``disk_summary.json`` plus the names of the parts that failed."""
    deadline = deadline or (time.monotonic() + SUMMARY_SECONDS)
    summary: dict[str, Any] = {"properties": {}, "plugins": {}}
    failed: list[str] = []
    for name in SUMMARY_PROPERTIES:
        try:
            value = getattr(target, name)
            summary["properties"][name] = _plain(value() if callable(value) else value)
        except Exception as exc:  # noqa: BLE001 - every dissect call is optional
            # A missing property (no domain, no time zone) is normal; it is noted, not a gap.
            summary["properties"][name] = None
            summary.setdefault("property_errors", {})[name] = type(exc).__name__
    for name in SUMMARY_PLUGINS:
        if time.monotonic() > deadline:
            summary["plugins"][name] = {"status": "skipped", "why": "summary time limit reached"}
            failed.append(f"{name} (time limit)")
            continue
        rows: list[dict[str, Any]] = []
        try:
            if not target.has_function(name):
                summary["plugins"][name] = {"status": "not available", "rows": []}
                continue
            truncated = False
            for record in getattr(target, name)():
                if len(rows) >= max_rows or time.monotonic() > deadline:
                    truncated = True
                    break
                rows.append(_record_dict(record))
            summary["plugins"][name] = {"status": "ok", "rows": rows, "truncated": truncated}
        except Exception as exc:  # noqa: BLE001
            summary["plugins"][name] = {"status": "error", "error": type(exc).__name__, "rows": rows}
            failed.append(f"{name} ({type(exc).__name__})")
    return summary, failed


def _listing(target: Any, volumes: list[tuple[str, Any]], max_rows: int = MAX_LISTING_ROWS) -> dict[str, Any]:
    """Names, sizes and times of files on volumes without Windows (for example a USB stick)."""
    sysvol = getattr(getattr(target, "fs", None), "mounts", {}).get("sysvol")
    rows: list[dict[str, Any]] = []
    truncated = False
    for label, fs in volumes:
        if fs is sysvol:
            continue
        stack: list[tuple[Any, list[str]]] = [(fs.path("/"), [])]
        while stack:
            node, trail = stack.pop()
            if len(trail) > MAX_WALK_DEPTH:
                continue
            try:
                children = sorted(_children(node), key=lambda entry: entry.name, reverse=True)
            except Exception:  # noqa: BLE001
                continue
            for child in children:
                if _is_dir(child):
                    stack.append((child, [*trail, child.name]))
                elif _is_file(child):
                    if len(rows) >= max_rows:
                        truncated = True
                        break
                    try:
                        size = int(child.stat().st_size)
                    except Exception:  # noqa: BLE001
                        size = None
                    rows.append({"path": "/" + "/".join([label, *trail, child.name]), "size_bytes": size,
                                 "modified": _stat_time(child)})
            if truncated:
                break
    return {"rows": rows, "truncated": truncated}


def read_image(path: Path, image_rel: str, image_sha256: str, destination: Path,
               budget: DiskBudget | None = None, *, segments: list[dict[str, Any]] | None = None,
               include_mft: bool = False) -> DiskResult:
    """Open one image, copy artefacts into ``destination/files``, and write the summary dict.

    Raises SecurityError when the image cannot be opened at all.
    """
    try:
        target = open_image(path)
    except SecurityError:
        raise
    except Exception as exc:  # noqa: BLE001 - the library message can quote the image
        raise SecurityError(f"Disk image could not be opened ({type(exc).__name__})") from exc
    result = DiskResult()
    destination.mkdir(parents=True, exist_ok=False)
    extract_artefacts(target, image_rel, image_sha256, destination / "files", budget,
                      include_mft=include_mft, result=result)
    summary, failed = summarise(target)
    for part in failed:
        result.gap(f"{image_rel} summary", f"dissect could not report {part}")
    volumes = _volumes(target)
    summary.update({
        "image": image_rel,
        "image_sha256": image_sha256,
        "segments": segments or [],
        "reader": f"dissect.target {_dissect_version()}",
        "disks": [{"type": type(disk).__name__, "size_bytes": _plain(getattr(disk, "size", None))}
                  for disk in getattr(target, "disks", [])],
        "volumes": [{"label": label, "filesystem": _plain(getattr(fs, "__type__", type(fs).__name__))}
                    for label, fs in volumes],
        "files_copied": len(result.members),
        "bytes_copied": sum(member.size_bytes for member in result.members),
    })
    # Profile folder names: still useful when the registry-based users plugin fails.
    profiles: list[str] = []
    for label, fs in volumes:
        for base in USER_DIRS:
            try:
                parent = fs.path("/").joinpath(*base.split("/")[:-1])
                if _is_dir(parent):
                    profiles.extend(f"/{label}/{base[:-2]}/{child.name}" for child in _children(parent) if _is_dir(child))
            except Exception:  # noqa: BLE001
                continue
    summary["user_folders"] = sorted(profiles)[:MAX_PLUGIN_ROWS]
    try:
        summary["listing"] = _listing(target, volumes)
    except Exception as exc:  # noqa: BLE001
        result.gap(f"{image_rel} listing", f"file listing failed ({type(exc).__name__})")
    if not any(fs is getattr(target.fs, "mounts", {}).get("sysvol") for _, fs in volumes):
        result.gap(image_rel, "no Windows system folder found; only a file listing was recorded")
    result.summary = summary
    return result
