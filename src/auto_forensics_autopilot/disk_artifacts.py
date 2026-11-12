"""Turn the artefacts copied out of a disk image into cited findings about data theft.

``disk_images`` copies registry hives, shortcuts, Jump Lists, browser
databases, Prefetch files, Recycle Bin index files and the device-install
log out of an image. This module reads those copies (``disk_parsers`` and
``disk_registry``) and looks for what an insider leaves behind: USB sticks,
files opened from removable media, CD burning, cloud sync clients, webmail
and upload sites, wiping tools, cleared history, mass deletions,
confidential-looking file names on external media, and tell-tale searches.

Three outputs per image, all inside ``<run>/disk/<image>/``:

* findings, one per device / tool / site category, each citing the records
  it rests on. A citation carries the copy's SHA-256, a byte offset or row,
  and (in the finding's evidence list) the locator and SHA-256 of the
  record, which the coordinator re-reads before it keeps the finding;
* ``artifact_timeline.jsonl``: every dated record, oldest first;
* an ``artifacts`` key added to ``disk_summary.json`` with the details
  (serial numbers, file names, search terms) behind each finding.

Finding titles are built only from this module's own words, counts and
times. Text that came from the evidence (names, paths, serial numbers)
goes to the two files above and never into the draft.
"""

from __future__ import annotations

import json
import re
import sqlite3
import struct
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from auto_forensics.file_ops import atomic_write_text
from auto_forensics.models import Citation, Finding

from .disk_parsers import (
    ParseBudget,
    ParseError,
    Record,
    Rereader,
    clean_text,
    locator_position,
    parse_automatic_destinations,
    parse_chromium_history,
    parse_custom_destinations,
    parse_firefox_places,
    parse_gdrive_config,
    parse_gdrive_snapshot,
    parse_index_dat,
    parse_lnk,
    parse_prefetch,
    parse_recycle_index,
    parse_setupapi,
    parse_webcache,
    url_host,
)
from .disk_registry import hive_kind, parse_hive

WORKER = "disk_artifacts"
TIMELINE_FILE = "artifact_timeline.jsonl"
SUMMARY_KEY = "artifacts"
SCHEMA_VERSION = 1

MAX_CITATIONS = 6
MAX_DETAIL_ROWS = 40
MAX_TIMELINE_ROWS = 50_000
MAX_FINDINGS_PER_RULE = 12
MAX_GAPS_PER_KIND = 8
ANALYSIS_SECONDS = 900
WINDOW = timedelta(minutes=10)
BURST_FILES = 5
MASS_DELETE_ITEMS = 5
CLOCK_JUMP = timedelta(hours=2)

# --------------------------------------------------------------------------
# Watch lists. Everything this agent treats as "interesting" is named here.
# --------------------------------------------------------------------------
#
# Each category has:
#   what          plain words used in finding titles
#   tactic        ATT&CK tactic for findings in this category
#   technique     ATT&CK technique for findings in this category
#   programs      {name shown in findings: (needles, technique override)}
#                 A needle is a lower-case fragment of a program's file name,
#                 install name or command line. It must start a word, so
#                 "nero" matches "NeroInfoTool.exe" but not "generous".
#   domains       web sites; a host matches when it is the domain or ends
#                 with "." + domain
#   folders       {name shown in findings: lower-case folder fragment} for
#                 sync folders
#   search_terms  lower-case fragments of search-engine or Explorer searches
#
# Add to these lists freely; nothing else in the agent names a product.
WATCHLIST: dict[str, dict[str, Any]] = {
    "cloud_storage": {
        "what": "cloud storage",
        "tactic": "exfiltration",
        "technique": "T1567.002",  # Exfiltration to Cloud Storage
        "programs": {
            "Google Drive": (("googledrivesync", "googledrivefs", "google drive", "googledrive", "gdrive"), ""),
            "Dropbox": (("dropbox",), ""),
            "OneDrive": (("onedrive", "skydrive"), ""),
            "iCloud": (("icloud", "apple internet services"), ""),
            "Box": (("boxsync", "box sync", "boxdrive", "box drive"), ""),
            "MEGA": (("megasync", "megaclient"), ""),
            "pCloud": (("pcloud",), ""),
        },
        "domains": ("drive.google.com", "docs.google.com", "accounts.google.com", "dropbox.com", "onedrive.live.com",
                    "skydrive.live.com", "icloud.com", "box.com", "mega.nz", "mega.co.nz", "pcloud.com",
                    "mediafire.com", "4shared.com", "sync.com", "googledrive.com"),
        "folders": {"Google Drive": "\\google drive\\", "Dropbox": "\\dropbox\\", "OneDrive": "\\onedrive\\",
                    "OneDrive (SkyDrive)": "\\skydrive\\", "iCloud": "\\iclouddrive\\", "Box": "\\box sync\\"},
        "search_terms": ("cloud storage", "google drive", "dropbox", "icloud", "onedrive", "file sharing"),
    },
    "webmail": {
        "what": "webmail",
        "tactic": "exfiltration",
        "technique": "T1048",  # Exfiltration Over Alternative Protocol (e-mail)
        "programs": {},
        "domains": ("mail.google.com", "gmail.com", "outlook.live.com", "outlook.com", "hotmail.com", "mail.live.com",
                    "login.live.com", "mail.yahoo.com", "mail.aol.com", "protonmail.com", "proton.me", "mail.com",
                    "gmx.com", "gmx.net", "zoho.com", "tutanota.com", "yandex.com", "mail.ru", "naver.com"),
        "folders": {},
        "search_terms": (),
    },
    "file_transfer": {
        "what": "file transfer",
        "tactic": "exfiltration",
        "technique": "T1567",  # Exfiltration Over Web Service
        "programs": {
            "FileZilla": (("filezilla",), "T1048"),
            "WinSCP": (("winscp",), "T1048"),
            "TeamViewer": (("teamviewer",), "T1219"),
            "AnyDesk": (("anydesk",), "T1219"),
        },
        "domains": ("wetransfer.com", "sendspace.com", "file.io", "transfer.sh", "pastebin.com", "gofile.io",
                    "anonfiles.com", "zippyshare.com", "send-anywhere.com", "filemail.com", "hightail.com",
                    "dropmefiles.com", "ufile.io", "easyupload.io"),
        "folders": {},
        "search_terms": ("send large file", "upload file", "file transfer", "anonymous upload"),
    },
    "anti_forensics": {
        "what": "anti-forensic or wiping",
        "tactic": "defense-evasion",
        "technique": "T1070.004",  # Indicator Removal: File Deletion
        "programs": {
            # Cleaners remove traces of activity (history, recent files, temp files).
            "CCleaner": (("ccleaner", "ccsetup"), "T1070"),
            "BleachBit": (("bleachbit",), "T1070"),
            "PrivaZer": (("privazer",), "T1070"),
            "Wise Disk Cleaner": (("wisediskcleaner", "wise disk cleaner"), "T1070"),
            "Evidence Eliminator": (("evidence eliminator",), "T1070"),
            # Wipers overwrite files or free space so they cannot be recovered.
            "Eraser": (("eraser",), "T1485"),
            "SDelete": (("sdelete",), "T1485"),
            "BCWipe": (("bcwipe",), "T1485"),
            "File Shredder": (("fileshredder", "file shredder", "shredder"), "T1485"),
            "cipher.exe (can wipe free space)": (("cipher.exe",), "T1485"),
            # Whole-disk wipers.
            "KillDisk": (("killdisk",), "T1561.001"),
            "DBAN": (("dban", "darik"), "T1561.001"),
            "Timestomp": (("timestomp",), "T1070.006"),
        },
        "domains": ("ccleaner.com", "piriform.com", "eraser.heidi.ie", "bleachbit.org", "privazer.com", "dban.org",
                    "killdisk.com", "jetico.com", "anti-forensics.com"),
        "folders": {},
        "search_terms": ("anti-forensic", "anti forensic", "antiforensic", "ccleaner", "eraser", "bleachbit", "sdelete",
                         "secure delete", "securely delete", "wipe", "wiping", "shred", "erase", "delete data",
                         "delete history", "clear history", "delete browsing", "cover tracks", "cover your tracks",
                         "remove traces", "system cleaner", "data recovery", "recover data", "recover deleted",
                         "undelete", "unrecoverable"),
    },
    "data_hiding": {
        "what": "data hiding or encryption",
        "tactic": "defense-evasion",
        "technique": "T1027",  # Obfuscated Files or Information
        "programs": {
            "TrueCrypt": (("truecrypt",), ""),
            "VeraCrypt": (("veracrypt",), ""),
            "OpenStego": (("openstego",), "T1027.003"),
            "SilentEye": (("silenteye",), "T1027.003"),
            "S-Tools": (("s-tools",), "T1027.003"),
            "QuickStego": (("quickstego",), "T1027.003"),
            "AxCrypt": (("axcrypt",), ""),
        },
        "domains": ("veracrypt.fr", "truecrypt.org", "openstego.com"),
        "folders": {},
        "search_terms": ("steganograph", "hide data", "hiding data", "data hiding", "hide file", "hidden volume",
                         "encrypt file", "rename extension", "change file extension"),
    },
    "data_leak": {
        "what": "leaking information",
        "tactic": "exfiltration",
        "technique": "",
        "programs": {},
        "domains": (),
        "folders": {},
        "search_terms": ("data leak", "leak", "leaking", "leakage", "exfiltrat", "confidential information",
                         "intellectual property", "trade secret", "steal data", "dlp", "drm", "bypass",
                         "security checkpoint", "external device", "usb history", "cd burning", "burn cd",
                         "how to copy", "without being detected", "without getting caught"),
    },
    "forensic_awareness": {
        "what": "forensic investigation methods",
        "tactic": "defense-evasion",
        "technique": "",
        "programs": {},
        "domains": ("forensicswiki.org", "forensicfocus.com", "forensics.wiki", "sans.org"),
        "folders": {},
        "search_terms": ("forensic", "investigation", "event log", "windows artifacts", "system artifacts",
                         "prefetch", "shellbag", "what does it know about me", "can my employer see"),
    },
    "email_client": {
        "what": "e-mail client",
        "tactic": "exfiltration",
        "technique": "T1048",
        "programs": {
            "Outlook": (("outlook.exe", "microsoft outlook", "outlook"), ""),
            "Thunderbird": (("thunderbird",), ""),
            "Windows Live Mail": (("wlmail", "windows live mail"), ""),
            "Windows Mail": (("winmail", "windows mail"), ""),
        },
        "domains": (),
        "folders": {},
        "search_terms": (),
    },
    "disc_burning": {
        "what": "CD/DVD burning",
        "tactic": "exfiltration",
        "technique": "T1052",  # Exfiltration Over Physical Medium
        "programs": {
            "Windows Disc Image Burner": (("isoburn",), ""),
            "Nero": (("nero",), ""),
            "ImgBurn": (("imgburn",), ""),
            "CDBurnerXP": (("cdbxp", "cdburnerxp"), ""),
            "InfraRecorder": (("infrarecorder",), ""),
            "BurnAware": (("burnaware",), ""),
            "Ashampoo Burning Studio": (("ashampoo burning", "burningstudio"), ""),
            "Roxio": (("roxio",), ""),
        },
        "domains": (),
        "folders": {},
        "search_terms": (),
    },
    "archiver": {
        "what": "archive tool",
        "tactic": "collection",
        "technique": "T1560.001",  # Archive Collected Data: Archive via Utility
        "programs": {"WinRAR": (("winrar", "rar.exe"), ""), "7-Zip": (("7-zip", "7z.exe", "7zfm", "7zg"), ""),
                     "WinZip": (("winzip",), "")},
        "domains": (),
        "folders": {},
        "search_terms": (),
    },
}

# File-name fragments that suggest a document is sensitive. Lower case; a
# fragment must start a word ("design" matches "design_concept.ppt", not
# "redesigned").
CONFIDENTIAL_WORDS: tuple[str, ...] = (
    "secret", "confidential", "proprietary", "restricted", "classified", "internal only", "internal_only",
    "do not distribute", "sensitive", "private", "design", "blueprint", "schematic", "prototype", "pricing", "price",
    "financ", "budget", "salary", "payroll", "revenue", "forecast", "customer list", "client list", "contract",
    "strategy", "roadmap", "merger", "acquisition", "patent", "source code", "password", "credential", "nda",
    "proposal", "technical review", "market analysis", "market share", "trade secret", "plans",
)

# Folder Windows uses to hold files waiting to be burned to a disc.
BURN_STAGING = "\\appdata\\local\\microsoft\\windows\\burn\\"
EXTERNAL_PLACES = ("removable", "optical", "network", "cloud", "burn-staging")
PLACE_WORDS = {"removable": "removable media", "optical": "a CD/DVD", "network": "a network share",
               "cloud": "a cloud sync folder", "burn-staging": "the CD-burning staging folder"}
PLACE_TECHNIQUE = {"removable": ("exfiltration", "T1052.001"), "optical": ("exfiltration", "T1052"),
                   "network": ("collection", "T1039"), "cloud": ("exfiltration", "T1567.002"),
                   "burn-staging": ("collection", "T1074.001")}


def _word_start(fragments: Iterable[str]) -> re.Pattern[str]:
    parts = sorted({re.escape(item) for item in fragments if item}, key=len, reverse=True)
    return re.compile(r"(?<![a-z0-9])(" + "|".join(parts) + ")") if parts else re.compile(r"(?!)")


_CONFIDENTIAL = _word_start(CONFIDENTIAL_WORDS)
_PROGRAMS: list[tuple[str, str, str, re.Pattern[str]]] = [
    (category, label, technique or spec["technique"], _word_start(needles))
    for category, spec in WATCHLIST.items() for label, (needles, technique) in spec["programs"].items()
]
_SEARCHES = {category: _word_start(spec["search_terms"]) for category, spec in WATCHLIST.items()
             if spec["search_terms"]}


def match_program(text: str) -> tuple[str, str, str] | None:
    """(category, program name, technique) for a file name, install name or command line; None when not watched."""
    lowered = text.lower()
    for category, label, technique, pattern in _PROGRAMS:
        if pattern.search(lowered):
            return category, label, technique
    return None


def match_domain(host: str) -> str | None:
    """The watch-list category of a web host, or None."""
    host = host.lower().rstrip(".")
    for category, spec in WATCHLIST.items():
        for domain in spec["domains"]:
            if host == domain or host.endswith("." + domain):
                return category
    return None


def match_search(term: str) -> list[str]:
    lowered = term.lower()
    return [category for category, pattern in _SEARCHES.items() if pattern.search(lowered)]


def looks_confidential(name: str) -> bool:
    return bool(_CONFIDENTIAL.search(name.lower().replace("_", " ")))


# --------------------------------------------------------------------------
# Records with their source file
# --------------------------------------------------------------------------


@dataclass(slots=True)
class Source:
    """One file copied out of the image."""

    cited_as: str
    path: Path
    sha256: str
    member: str
    category: str
    modified: str = ""

    @property
    def user(self) -> str:
        found = re.match(r"^/[^/]+/(Users|Documents and Settings)/([^/]+)/", self.member, re.IGNORECASE)
        return found.group(2) if found else ""


@dataclass(slots=True)
class Item:
    record: Record
    source: Source

    @property
    def fields(self) -> dict[str, Any]:
        return self.record.fields

    @property
    def kind(self) -> str:
        return self.record.kind

    @property
    def time(self) -> str | None:
        return self.record.time


@dataclass(slots=True)
class Touch:
    """A file or folder a user reached, and where it lived."""

    path: str
    when: str | None
    place: str
    volume: str
    item: Item

    @property
    def name(self) -> str:
        return re.split(r"[\\/]", self.path.rstrip("\\/"))[-1]


@dataclass(slots=True)
class ProgramUse:
    category: str
    program: str
    technique: str
    how: str  # installed, configured, run, autostart, shortcut, downloaded
    count: int
    item: Item


@dataclass(slots=True)
class Outcome:
    findings: list[Finding] = field(default_factory=list)
    gaps: list[dict[str, str]] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    timeline_rows: int = 0
    files_parsed: int = 0


def _parse_time(text: str | None) -> datetime | None:
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def _span(times: Iterable[str | None]) -> tuple[str | None, str | None]:
    known = sorted(t for t in times if t)
    return (known[0], known[-1]) if known else (None, None)


def _between(first: str | None, last: str | None) -> str:
    if not first:
        return "no dated record"
    return f"on {first}" if first == last else f"between {first} and {last}"


def _plural(count: int, word: str) -> str:
    if count == 1:
        return f"{count} {word}"
    return f"{count} {word}es" if word.endswith(("ch", "s", "x")) else f"{count} {word}s"


# --------------------------------------------------------------------------
# Parsing the copies
# --------------------------------------------------------------------------

Parser = Callable[[Path], tuple[list[Record], list[str]]]


def _plain(parser: Callable[[Path], list[Record]]) -> Parser:
    return lambda path: (parser(path), [])


def _webcache(path: Path) -> tuple[list[Record], list[str]]:
    problems: list[str] = []
    return parse_webcache(path, problems=problems), problems


def _parser_for(source: Source) -> tuple[str, Parser | None]:
    """(what it is, parser) for a copied file; the parser is None for kinds another agent handles.

    A parser returns (records, problems): a problem is a part of the file it could not read.
    """
    name = source.member.rsplit("/", 1)[-1]
    lowered = name.lower()
    if source.category == "registry":
        kind = hive_kind(name)
        if kind is None:
            return "registry hive this agent does not read (Amcache, SECURITY)", None
        return "registry hive", lambda path: parse_hive(path, kind)
    if source.category == "prefetch":
        return "Prefetch file", _plain(parse_prefetch)
    if source.category == "lnk":
        return "shortcut", _plain(parse_lnk)
    if source.category == "jump_list":
        return "Jump List", _plain(parse_automatic_destinations if lowered.endswith(".automaticdestinations-ms")
                                   else parse_custom_destinations)
    if source.category == "recycle_bin":
        return "Recycle Bin index file", _plain(parse_recycle_index)
    if source.category == "usb":
        return "device-install log", _plain(parse_setupapi)
    if source.category == "cloud":
        if lowered == "snapshot.db":
            return "Google Drive sync database", _plain(parse_gdrive_snapshot)
        if lowered == "sync_config.db":
            return "Google Drive settings database", _plain(parse_gdrive_config)
        return "", None  # sync_log.log is text: the core pipeline and the line-rule agents read it
    if source.category == "browser":
        if lowered == "history":
            browser = "edge" if "/edge/" in source.member.lower() else "chrome"
            return "browser history", lambda path: (parse_chromium_history(path, browser), [])
        if lowered == "places.sqlite":
            return "browser history", _plain(parse_firefox_places)
        if lowered == "webcachev01.dat":
            return "Internet Explorer history database", _webcache
        if lowered == "index.dat":
            return "Internet Explorer history file", _plain(parse_index_dat)
    return "", None


def parse_sources(sources: list[Source], deadline: float) -> tuple[list[Item], list[dict[str, str]], int]:
    """Parse every copy this agent understands. Returns (items, coverage gaps, files parsed)."""
    items: list[Item] = []
    gaps: list[dict[str, str]] = []
    failed: dict[str, list[str]] = defaultdict(list)
    skipped: Counter[str] = Counter()
    parsed = 0
    out_of_time = 0
    for source in sources:
        what, parser = _parser_for(source)
        if parser is None:
            if what:
                skipped[what] += 1
            continue
        if time.monotonic() > deadline:
            out_of_time += 1
            continue
        try:
            records, problems = parser(source.path)
        except ParseBudget as exc:
            gaps.append({"what": source.cited_as, "why": f"{what} not read, a size or time limit was reached: {exc}"})
            continue
        except (ParseError, struct.error, sqlite3.Error, OSError, ValueError, IndexError, KeyError, EOFError,
                UnicodeError, OverflowError, MemoryError, RecursionError) as exc:
            failed[what].append(f"{source.cited_as} ({type(exc).__name__})")
            continue
        except Exception as exc:  # noqa: BLE001 - a parser bug on hostile input is a gap, not a crash
            failed[what].append(f"{source.cited_as} ({type(exc).__name__})")
            continue
        parsed += 1
        for problem in problems:
            gaps.append({"what": source.cited_as, "why": clean_text(problem, 200)})
        items.extend(Item(record, source) for record in records)
    for what, names in sorted(failed.items()):
        for name in names[:MAX_GAPS_PER_KIND]:
            gaps.append({"what": name.rsplit(" (", 1)[0],
                         "why": f"{what} could not be read ({name.rsplit(' (', 1)[1].rstrip(')')}); not analysed"})
        if len(names) > MAX_GAPS_PER_KIND:
            gaps.append({"what": f"{len(names) - MAX_GAPS_PER_KIND} more file(s)",
                         "why": f"{what} could not be read; not analysed"})
    for what, count in sorted(skipped.items()):
        gaps.append({"what": f"{count} file(s)", "why": f"{what}: copied but not analysed for user activity"})
    if out_of_time:
        gaps.append({"what": f"{out_of_time} file(s)", "why": "artefact analysis time limit reached; not parsed"})
    return items, gaps, parsed


# --------------------------------------------------------------------------
# Context: drive letters, time zone, users
# --------------------------------------------------------------------------


@dataclass(slots=True)
class Context:
    usb_letters: set[str] = field(default_factory=set)
    optical_letters: set[str] = field(default_factory=set)
    network_letters: dict[str, str] = field(default_factory=dict)
    usb_volume_serials: set[str] = field(default_factory=set)
    bias_minutes: int | None = None
    sid_users: dict[str, str] = field(default_factory=dict)


def build_context(items: list[Item]) -> Context:
    context = Context()
    for item in items:
        fields = item.fields
        if item.kind == "mounted_device" and re.fullmatch(r"[A-Za-z]:", str(fields.get("mount", ""))):
            letter = fields["mount"].upper()
            if fields.get("is_usb"):
                context.usb_letters.add(letter)
            elif fields.get("is_optical"):
                context.optical_letters.add(letter)
        elif item.kind == "mapped_drive" and fields.get("drive"):
            context.network_letters[fields["drive"]] = fields.get("share", "")
        elif item.kind == "usb_volume_name" and fields.get("volume_serial") and fields.get("serial"):
            context.usb_volume_serials.add(fields["volume_serial"])
        elif item.kind == "system_fact" and fields.get("fact") == "time_zone":
            bias = fields.get("active_bias_minutes", fields.get("bias_minutes"))
            if isinstance(bias, int) and -900 <= bias <= 900:
                context.bias_minutes = bias
        elif item.kind == "user_profile":
            context.sid_users[fields.get("sid", "")] = re.split(r"[\\/]", fields.get("path", ""))[-1]
    return context


def classify_place(path: str, context: Context, drive_type: str = "", volume_serial: str = "") -> tuple[str, str]:
    """(place, volume) for a path. Place is removable, optical, network, cloud, burn-staging or local."""
    lowered = path.lower().replace("/", "\\")
    letter = path[:2].upper() if re.match(r"^[A-Za-z]:", path) else ""
    if drive_type == "removable" or (volume_serial and volume_serial in context.usb_volume_serials):
        return "removable", volume_serial or letter
    if drive_type == "cdrom":
        return "optical", volume_serial or letter
    if drive_type == "network" or lowered.startswith("\\\\"):
        share = "\\".join(lowered.split("\\")[:4]) if lowered.startswith("\\\\") else letter
        return "network", share
    if BURN_STAGING in lowered:
        return "burn-staging", letter
    for label, fragment in WATCHLIST["cloud_storage"]["folders"].items():
        if fragment in lowered + "\\":
            return "cloud", label
    if drive_type in ("", "unknown") and letter:
        # A drive letter says where a path is only as of the last time Windows assigned that letter.
        if letter in context.usb_letters:
            return "removable", letter
        if letter in context.optical_letters:
            return "optical", letter
        if letter in context.network_letters:
            return "network", context.network_letters[letter] or letter
    return "local", letter


_TOUCH_FIELDS = {"open_save": "path", "last_visited": "folder", "office_mru": "path", "shellbag": "path",
                 "typed_path": "path", "browser_file_open": "target_path", "browser_download": "target_path",
                 "archive_history": "path", "run_command": "command"}


def collect_touches(items: list[Item], context: Context) -> list[Touch]:
    touches: list[Touch] = []
    for item in items:
        fields = item.fields
        if item.kind in ("lnk", "jump_list"):
            path = str(fields.get("target_path") or fields.get("dest_path") or "")
            if not path or path.lower().startswith(("http://", "https://")):
                continue
            place, volume = classify_place(path, context, str(fields.get("drive_type", "")),
                                           str(fields.get("volume_serial", "")))
            # A shortcut file is rewritten each time its target is opened, so its own time is the best "opened" time.
            when = item.time if item.kind == "jump_list" else (item.source.modified or item.time)
            touches.append(Touch(path, when, place, volume, item))
        elif item.kind == "cloud_file" and not fields.get("is_folder"):
            touches.append(Touch(str(fields.get("name", "")), item.time, "cloud", str(fields.get("client", "")), item))
        elif item.kind in _TOUCH_FIELDS:
            path = str(fields.get(_TOUCH_FIELDS[item.kind]) or "")
            if not re.match(r"^([A-Za-z]:|\\\\)", path):
                continue
            place, volume = classify_place(path, context)
            touches.append(Touch(path, item.time, place, volume, item))
    return touches


def collect_program_uses(items: list[Item]) -> list[ProgramUse]:
    uses: list[ProgramUse] = []
    for item in items:
        fields = item.fields
        text, how, count = "", "", 1
        if item.kind == "prefetch":
            text, how, count = str(fields.get("program", "")), "run", int(fields.get("run_count") or 1)
        elif item.kind == "user_assist":
            text, how, count = str(fields.get("program", "")), "run", int(fields.get("run_count") or 0)
            if count == 0:
                how = "shortcut"
        elif item.kind == "installed_program":
            text, how = f"{fields.get('name', '')} {fields.get('location', '')}", "installed"
        elif item.kind == "program_key":
            uses.extend(ProgramUse(category, label, technique or WATCHLIST[category]["technique"], "configured", 1,
                                   item)
                        for category, spec in WATCHLIST.items()
                        for label, (_, technique) in spec["programs"].items() if label == fields.get("program"))
            continue
        elif item.kind == "autorun":
            text, how = f"{fields.get('name', '')} {fields.get('command', '')}", "autostart"
        elif item.kind in ("lnk", "jump_list"):
            target = str(fields.get("target_path", ""))
            if target.lower().endswith((".exe", ".msi")):
                text, how = target, "shortcut"
        elif item.kind == "browser_download":
            target = str(fields.get("target_path") or fields.get("url") or "")
            text, how = re.split(r"[\\/]", target)[-1], "downloaded"
        elif item.kind == "mail_client" and fields.get("role") == "default mail client":
            text, how = str(fields.get("name", "")), "configured"
        elif item.kind in ("mail_profile", "mail_store"):
            text, how = str(fields.get("client", "")), "configured"
        elif item.kind == "cloud_account":
            text, how = str(fields.get("client", "")), "signed in"
        if not text.strip():
            continue
        found = match_program(text)
        if found:
            uses.append(ProgramUse(found[0], found[1], found[2], how, max(count, 1), item))
    return uses


# --------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------


class FindingBuilder:
    """Builds findings whose citations the coordinator can re-read, and keeps their details."""

    def __init__(self, image_rel: str, summary_path: str, rereader: Rereader) -> None:
        self.image_rel = image_rel
        self.summary_path = summary_path
        self.rereader = rereader
        self.findings: list[Finding] = []
        self.details: dict[str, dict[str, Any]] = {}
        self.uncitable = 0
        self.over_limit: Counter[str] = Counter()  # what was left without a finding of its own, by plain name

    def _pick(self, items: list[Item]) -> list[Item]:
        """Up to MAX_CITATIONS distinct records, preferring ones with a location smaller than the whole file."""
        seen: set[tuple[str, str]] = set()
        unique: list[Item] = []
        for item in items:
            key = (item.source.cited_as, item.record.locator)
            if key not in seen:
                seen.add(key)
                unique.append(item)
        located = [item for item in unique if item.record.locator != "file"]
        whole = [item for item in unique if item.record.locator == "file"]
        if len(located) <= MAX_CITATIONS:
            return (located + whole)[:MAX_CITATIONS]
        # First, last, and an even spread between them.
        step = (len(located) - 1) / (MAX_CITATIONS - 1)
        return [located[round(index * step)] for index in range(MAX_CITATIONS)]

    def add(self, rule: str, key: str, title: str, severity: str, tactic: str, technique: str, recommendation: str,
            items: list[Item], *, confidence: float = 0.7, detail: dict[str, Any] | None = None) -> None:
        from .agents import stable_id

        citations: list[Citation] = []
        checks: list[str] = []
        for item in self._pick(items):
            locator = item.record.locator
            digest = self.rereader.digest(item.source.path, locator)
            if digest is None and locator != "file":
                # The record could not be read back from its location, so say so and fall back to the whole file.
                locator = "file"
                digest = self.rereader.digest(item.source.path, locator)
            if digest is None:
                continue
            row, offset = locator_position(locator)
            checks.append(f"cite[{len(citations)}]={locator}|{digest}")
            citations.append(Citation(f"file-{item.source.sha256[:16]}", item.source.cited_as, item.source.sha256,
                                      row=row, offset=offset))
        if not citations:
            self.uncitable += 1
            return
        finding_id = stable_id("art", self.image_rel, rule, key)
        pointer = f" Details: {self.summary_path}, key {SUMMARY_KEY}.findings.{finding_id}."
        self.findings.append(Finding(
            finding_id=finding_id, title=title, severity=severity, confidence=confidence, tactic=tactic,
            technique_id=technique,
            evidence=[f"rule={rule}", f"records={len(items)}", *checks],
            recommendation=recommendation + pointer, citations=citations, origin="detector",
        ))
        self.details[finding_id] = {"rule": rule, "title": title, "severity": severity, "technique": technique,
                                    "records": len(items), **(detail or {})}


def _rows(items: Iterable[Item], *names: str) -> list[dict[str, Any]]:
    """Up to MAX_DETAIL_ROWS detail rows: time, where it was read, and the named fields."""
    rows = []
    for item in items:
        row: dict[str, Any] = {"time": item.time, "source": item.source.cited_as, "locator": item.record.locator}
        if item.source.user:
            row["user"] = item.source.user
        row.update({name: item.fields[name] for name in names if item.fields.get(name) not in (None, "")})
        rows.append(row)
        if len(rows) >= MAX_DETAIL_ROWS:
            break
    return rows


def _touch_rows(touches: list[Touch]) -> list[dict[str, Any]]:
    rows = []
    for touch in sorted(touches, key=lambda t: t.when or "")[:MAX_DETAIL_ROWS]:
        rows.append({"time": touch.when, "path": touch.path, "volume": touch.volume, "seen_in": touch.item.kind,
                     "user": touch.item.source.user, "source": touch.item.source.cited_as,
                     "locator": touch.item.record.locator})
    return rows


def _local_to_utc(local: str, bias_minutes: int | None) -> str | None:
    moment = _parse_time(local + "+00:00")
    if moment is None or bias_minutes is None:
        return None
    return (moment + timedelta(minutes=bias_minutes)).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _serial_key(text: str) -> str:
    return re.sub(r"&\d+$", "", text.upper())


def detect_usb_devices(items: list[Item], context: Context, out: FindingBuilder) -> list[dict[str, Any]]:
    devices: dict[str, dict[str, Any]] = {}
    evidence: dict[str, list[Item]] = defaultdict(list)
    for item in items:
        fields = item.fields
        serial = ""
        if item.kind in ("usb_device", "usb_volume_name", "usb_connection", "mounted_device") and fields.get("serial"):
            serial = _serial_key(str(fields["serial"]))
        elif item.kind == "device_install":
            found = re.match(r"USBSTOR\\[^\\]+\\([^\\\s]+)", str(fields.get("device_id", "")), re.IGNORECASE)
            serial = _serial_key(found.group(1)) if found else ""
        if not serial or (item.kind == "mounted_device" and not fields.get("is_usb")):
            continue
        device = devices.setdefault(serial, {"serial": serial, "vendor": "", "product": "", "revision": "",
                                             "friendly_name": "", "serial_is_unique": True, "volume_names": [],
                                             "volume_serials": [], "drive_letters": [], "volume_guids": [],
                                             "first_seen": None, "last_seen": None, "last_removed": None,
                                             "seen_in": []})
        evidence[serial].append(item)
        for name in ("vendor", "product", "revision", "friendly_name"):
            if fields.get(name) and not device[name]:
                device[name] = fields[name]
        if fields.get("serial_is_unique") is False:
            device["serial_is_unique"] = False
        for name, target in (("volume_name", "volume_names"), ("volume_serial", "volume_serials")):
            if fields.get(name) and fields[name] not in device[target]:
                device[target].append(fields[name])
        if item.kind == "mounted_device":
            mount = str(fields.get("mount", ""))
            target = "drive_letters" if re.fullmatch(r"[A-Za-z]:", mount) else "volume_guids"
            if mount not in device[target]:
                device[target].append(mount)
        if item.kind not in device["seen_in"]:
            device["seen_in"].append(item.kind)
        moments = [fields.get("first_install"), fields.get("last_arrival")]
        if item.kind == "device_install":
            moments.append(_local_to_utc(str(fields.get("local_time", "")), context.bias_minutes))
            device.setdefault("first_install_local", fields.get("local_time"))
        elif item.kind in ("usb_device", "usb_connection"):
            moments.append(item.time)
        for moment in moments:
            if moment:
                device["first_seen"] = min(filter(None, (device["first_seen"], moment)))
                device["last_seen"] = max(filter(None, (device["last_seen"], moment)))
        if fields.get("last_removal"):
            device["last_removed"] = max(filter(None, (device["last_removed"], fields["last_removal"])))
    # Which user accounts mounted the device: MountPoints2 holds the volume GUIDs each user saw.
    mounted_by: dict[str, set[str]] = defaultdict(set)
    for item in items:
        if item.kind == "mount_point" and item.fields.get("volume") and item.source.user:
            mounted_by[str(item.fields["volume"]).lower()].add(item.source.user)
        elif item.kind == "usb_bus_device" and _serial_key(str(item.fields.get("serial", ""))) in devices:
            serial = _serial_key(str(item.fields["serial"]))
            devices[serial]["usb_vendor_id"] = item.fields.get("vendor_id")
            devices[serial]["usb_product_id"] = item.fields.get("product_id")
            evidence[serial].append(item)
    ordered = sorted(devices.values(), key=lambda d: (d["first_seen"] or "9", d["serial"]))
    for index, device in enumerate(ordered, start=1):
        users: set[str] = set()
        for guid in device["volume_guids"]:
            users |= mounted_by.get(guid.lower().replace("volume", ""), set())
        device["mounted_by_users"] = sorted(users)
        device["number"] = index
        if index > MAX_FINDINGS_PER_RULE:
            out.over_limit["USB storage device"] += 1
            continue
        sources = _plural(len(device["seen_in"]), "kind") + " of record"
        serial_note = "" if device["serial_is_unique"] else "; it has no real serial number, Windows made one up"
        out.add("usb-device", device["serial"],
                f"USB storage device connected (device {index} of {len(ordered)}): seen "
                f"{_between(device['first_seen'], device['last_seen'])}, confirmed by {sources}{serial_note}",
                "low", "exfiltration", "T1052.001",
                "Find this device and image it. Compare its serial number with any seized USB sticks.",
                evidence[device["serial"]], confidence=0.8, detail={"device": device})
    return ordered


def detect_external_files(touches: list[Touch], out: FindingBuilder) -> None:
    by_volume: dict[tuple[str, str], list[Touch]] = defaultdict(list)
    for touch in touches:
        if touch.place in ("removable", "optical", "network"):
            by_volume[(touch.place, touch.volume)].append(touch)
    ranked = sorted(by_volume.items(), key=lambda pair: -len(pair[1]))
    counts: Counter[str] = Counter()
    for (place, volume), group in ranked:
        counts[place] += 1
        if counts[place] > MAX_FINDINGS_PER_RULE:
            out.over_limit[f"volume or share with files opened on {PLACE_WORDS[place]}"] += 1
            continue
        paths = {touch.path.lower() for touch in group}
        first, last = _span(touch.when for touch in group)
        tactic, technique = PLACE_TECHNIQUE[place]
        out.add(f"files-on-{place}", volume,
                f"Files or folders opened on {PLACE_WORDS[place]}: {_plural(len(paths), 'path')} on one "
                f"{'share' if place == 'network' else 'volume'}, {_between(first, last)}",
                "low" if place == "network" else "medium", tactic, technique,
                "List what was on this volume and ask whether the user was allowed to copy it there.",
                [touch.item for touch in sorted(group, key=lambda t: t.when or "")],
                detail={"place": place, "volume": volume, "paths": len(paths), "files": _touch_rows(group)})
    # Many different files on external media inside a short window.
    dated = sorted((touch for touch in touches if touch.place in ("removable", "optical") and _parse_time(touch.when)),
                   key=lambda t: t.when or "")
    best: list[Touch] = []
    start = 0
    for end in range(len(dated)):
        while _parse_time(dated[end].when) - _parse_time(dated[start].when) > WINDOW:  # type: ignore[operator]
            start += 1
        window = dated[start:end + 1]
        if len({t.path.lower() for t in window}) > len({t.path.lower() for t in best}):
            best = window
    distinct = {touch.path.lower() for touch in best}
    if len(distinct) >= BURST_FILES:
        out.add("external-burst", best[0].when or "",
                f"Many files touched on removable media in a short time: {len(distinct)} different paths within "
                f"{int(WINDOW.total_seconds() // 60)} minutes from {best[0].when}",
                "high", "exfiltration", "T1052.001",
                "This pattern fits bulk copying. Check what was copied and where the media is now.",
                [touch.item for touch in best], detail={"files": _touch_rows(best)})


def detect_confidential_names(touches: list[Touch], items: list[Item], out: FindingBuilder) -> None:
    for place in EXTERNAL_PLACES:
        # On external media a telling folder name counts too ("E:\\Secret Project\\holiday.jpg").
        group = [touch for touch in touches if touch.place == place
                 and looks_confidential(re.sub(r"^([A-Za-z]:|\\\\[^\\]+\\[^\\]+)", "", touch.path))]
        if not group:
            continue
        names = {touch.path.lower() for touch in group}
        first, last = _span(touch.when for touch in group)
        tactic, technique = PLACE_TECHNIQUE[place]
        out.add("confidential-names", place,
                f"Confidential-looking file names on {PLACE_WORDS[place]}: {_plural(len(names), 'name')}, "
                f"{_between(first, last)}",
                "high", tactic, technique,
                "Confirm with the data owner whether these files are sensitive and whether they may leave the company.",
                [touch.item for touch in sorted(group, key=lambda t: t.when or "")],
                confidence=0.6, detail={"place": place, "files": _touch_rows(group)})
    recent = [item for item in items if item.kind == "recent_doc" and looks_confidential(str(item.fields.get("name")))]
    if recent:
        names = {str(item.fields.get("name")).lower() for item in recent}
        out.add("confidential-recent", "recent",
                f"Confidential-looking file names among recently opened documents: {_plural(len(names), 'name')}",
                "low", "collection", "T1005",
                "These names alone do not show where the files went; read them with the removable-media findings.",
                recent, confidence=0.5, detail={"files": _rows(recent, "name", "group")})


def detect_disc_burning(touches: list[Touch], items: list[Item], uses: list[ProgramUse], out: FindingBuilder) -> None:
    staged = [touch for touch in touches if touch.place == "burn-staging"]
    if staged:
        paths = {touch.path.lower() for touch in staged}
        first, last = _span(touch.when for touch in staged)
        out.add("disc-burn-staging", "staging",
                f"Files placed in the Windows CD/DVD burning folder: {_plural(len(paths), 'path')}, "
                f"{_between(first, last)}",
                "medium", "collection", "T1074.001",
                "Files are copied here before Windows burns them to a disc. Look for the disc.",
                [touch.item for touch in staged], detail={"files": _touch_rows(staged)})
    media = [item for item in items if item.kind == "cd_burning" and item.fields.get("what") != "staging folder"
             and (item.fields.get("disc_label") or item.fields.get("total_bytes"))]
    burners = [use for use in uses if use.category == "disc_burning"]
    run = [use for use in burners if use.how == "run"]
    if media or burners:
        tools = sorted({use.program for use in burners})
        first, last = _span([item.time for item in media] + [use.item.time for use in burners])
        parts = []
        if media:
            parts.append(f"{_plural(len(media), 'record')} of a disc in the drive with its label and size")
        if tools:
            parts.append(f"burning tool {', '.join(tools)} " + ("run" if run else "present"))
        # Windows records the disc in the drive for read-only discs too, so that alone stays low.
        out.add("disc-burning", "burning", f"CD/DVD traces: {'; '.join(parts)}, {_between(first, last)}",
                "medium" if run or (media and staged) else "low", "exfiltration", "T1052",
                "Ask for any discs the user made. A burned disc leaves no trace on the network.",
                media + [use.item for use in burners],
                confidence=0.5, detail={"media": _rows(media, "disc_label", "total_bytes", "free_bytes", "volume",
                                                       "live_file_system"),
                                        "tools": _rows([use.item for use in burners], "program", "name", "run_count")})


def _how_summary(uses: list[ProgramUse]) -> tuple[str, int]:
    kinds = sorted({use.how for use in uses}, key=["installed", "configured", "signed in", "autostart", "shortcut",
                                                    "downloaded", "run"].index)
    runs = max((use.count for use in uses if use.how == "run"), default=0)
    words = [f"run {runs} time(s)" if how == "run" else how for how in kinds]
    return ", ".join(words), runs


def detect_programs(uses: list[ProgramUse], touches: list[Touch], out: FindingBuilder) -> dict[str, list[dict[str, Any]]]:
    """One finding per watched program. Returns {category: [program summary]} for the image summary."""
    by_program: dict[tuple[str, str], list[ProgramUse]] = defaultdict(list)
    for use in uses:
        by_program[(use.category, use.program)].append(use)
    cloud_files: dict[str, list[Touch]] = defaultdict(list)
    for touch in touches:
        if touch.place == "cloud":
            cloud_files[touch.volume.split(" (")[0]].append(touch)
    for label in cloud_files:
        by_program.setdefault(("cloud_storage", label), [])
    summary: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for (category, program), group in sorted(by_program.items()):
        spec = WATCHLIST[category]
        how, runs = _how_summary(group) if group else ("", 0)
        files = cloud_files.get(program, []) if category == "cloud_storage" else []
        first, last = _span([use.item.time for use in group if use.how in ("run", "downloaded", "installed")]
                            + [touch.when for touch in files])
        entry = {"program": program, "evidence": how, "run_count": runs, "first_seen": first, "last_seen": last,
                 "files_in_sync_folder": len({touch.path.lower() for touch in files})}
        summary[category].append(entry)
        if category in ("disc_burning", "archiver"):
            continue  # reported by the disc-burning and archive findings
        technique = group[0].technique if group else spec["technique"]
        executed = runs > 0
        if category == "anti_forensics":
            severity = "high" if executed else "medium"
            title = f"Anti-forensic or wiping tool {program}: {how}, {_between(first, last)}"
            advice = ("A cleaning or wiping tool can remove the traces other findings rely on. Check when it ran "
                      "against the times of the copying.")
        elif category == "cloud_storage":
            # OneDrive ships with Windows 10 and starts by itself, so running alone says little.
            severity = "medium" if files or (executed and program != "OneDrive") else "low"
            extra = f", {_plural(entry['files_in_sync_folder'], 'file')} seen in its sync folder" if files else ""
            title = f"Cloud sync client {program}: {how or 'sync folder in use'}{extra}, {_between(first, last)}"
            advice = "Ask the provider or the account owner for the sync history; files in the sync folder leave the PC."
        elif category == "email_client":
            severity = "low"
            title = f"E-mail client {program} in use (a possible way out for files): {how}, {_between(first, last)}"
            advice = "Review the mailbox (OST/PST) for messages with attachments around the times of interest."
        elif category == "data_hiding":
            severity = "medium"
            title = f"Data hiding or encryption tool {program}: {how}, {_between(first, last)}"
            advice = "Look for containers or carrier files this tool could have made."
        else:
            severity = "medium" if executed else "low"
            title = f"File transfer or remote access tool {program}: {how}, {_between(first, last)}"
            advice = "Check the tool's own logs and saved sessions for where files were sent."
        tactic = "impact" if technique in ("T1485", "T1561.001") else spec["tactic"]
        out.add(f"program-{category}", program, title, severity, tactic, technique, advice,
                [use.item for use in sorted(group, key=lambda u: (u.how != "run", u.item.time or ""))]
                + [touch.item for touch in files],
                detail={"program": entry, "records": _rows([use.item for use in group], "program", "name", "run_count",
                                                           "key_path", "command", "target_path", "version"),
                        "sync_folder_files": _touch_rows(files)})
    return summary


def detect_web(items: list[Item], out: FindingBuilder) -> dict[str, dict[str, Any]]:
    by_category: dict[str, list[Item]] = defaultdict(list)
    for item in items:
        host = ""
        if item.kind in ("browser_visit", "browser_download"):
            host = str(item.fields.get("host", ""))
        elif item.kind == "typed_url":
            host = url_host(str(item.fields.get("url", "")))
        category = match_domain(host) if host else None
        if category:
            by_category[category].append(item)
    summary: dict[str, dict[str, Any]] = {}
    for category, group in sorted(by_category.items()):
        spec = WATCHLIST[category]
        hosts = Counter(str(item.fields.get("host") or "typed URL") for item in group)
        first, last = _span(item.time for item in group)
        downloads = sum(1 for item in group if item.kind == "browser_download")
        summary[category] = {"visits": len(group), "sites": dict(hosts.most_common(20)), "first_seen": first,
                             "last_seen": last, "downloads": downloads}
        severity = "low" if category in ("webmail", "forensic_awareness") else "medium"
        out.add("web-sites", category,
                f"Web sites for {spec['what']} visited: {_plural(len(group), 'visit')} to "
                f"{_plural(len(hosts), 'site')}, {_between(first, last)}",
                severity, spec["tactic"], spec["technique"],
                "A visit does not prove an upload. Check proxy or provider logs for the same times.",
                sorted(group, key=lambda item: item.time or ""), confidence=0.5,
                detail={"sites": summary[category]["sites"], "visits": _rows(group, "url", "title", "browser")})
    return summary


def detect_searches(items: list[Item], out: FindingBuilder) -> list[dict[str, Any]]:
    by_category: dict[str, list[Item]] = defaultdict(list)
    flagged: list[dict[str, Any]] = []
    for item in items:
        if item.kind not in ("web_search", "explorer_search"):
            continue
        term = str(item.fields.get("term", ""))
        categories = match_search(term)
        for category in categories:
            by_category[category].append(item)
        if categories:
            flagged.append({"time": item.time, "term": term, "themes": categories, "where": item.kind,
                            "user": item.source.user})
    for category, group in sorted(by_category.items()):
        spec = WATCHLIST[category]
        terms = {str(item.fields.get("term", "")).lower() for item in group}
        first, last = _span(item.time for item in group)
        out.add("searches", category,
                f"Searches about {spec['what']}: {_plural(len(terms), 'different search')}, {_between(first, last)}",
                "medium" if category in ("anti_forensics", "data_leak", "data_hiding") else "low",
                spec["tactic"], spec["technique"],
                "Searches show intent, not action. Line them up with the device and deletion findings.",
                sorted(group, key=lambda item: item.time or ""), confidence=0.5,
                detail={"searches": _rows(group, "term", "browser", "host")})
    return flagged[:400]


def detect_history_clearing(items: list[Item], out: FindingBuilder) -> None:
    emptied = [item for item in items if item.kind == "browser_table_state" and item.fields.get("rows_now") == 0
               and int(item.fields.get("rows_ever") or 0) > 0]
    thinned = [item for item in items if item.kind == "browser_table_state" and item not in emptied
               and int(item.fields.get("rows_ever") or 0) >= 50
               and int(item.fields.get("rows_now") or 0) * 2 < int(item.fields.get("rows_ever") or 0)]
    if emptied:
        out.add("history-cleared", "emptied",
                f"Browser history was cleared: {_plural(len(emptied), 'history table')} now empty that once held rows",
                "medium", "defense-evasion", "T1070",
                "Recover deleted records from the database's free pages or from volume shadow copies.",
                emptied, detail={"tables": _rows(emptied, "browser", "table", "rows_ever", "rows_now")})
    if thinned:
        out.add("history-thinned", "thinned",
                f"Browser history rows are missing: {_plural(len(thinned), 'history table')} holds less than half the "
                "rows it once had (deleted by the user, a cleaner, or the browser's own 90-day expiry)",
                "low", "defense-evasion", "T1070",
                "Compare the oldest remaining visit with the 90-day expiry to tell deletion from ageing.",
                thinned, confidence=0.4, detail={"tables": _rows(thinned, "browser", "table", "rows_ever", "rows_now")})


def detect_deletions(items: list[Item], context: Context, out: FindingBuilder) -> dict[str, Any]:
    deleted = sorted((item for item in items if item.kind == "recycle_bin"), key=lambda item: item.time or "")
    if not deleted:
        return {"items": 0}
    first, last = _span(item.time for item in deleted)
    rows = []
    for item in deleted[:MAX_DETAIL_ROWS]:
        rows.append({"time": item.time, "path": item.fields.get("original_path"),
                     "size_bytes": item.fields.get("size_bytes"),
                     "user": context.sid_users.get(str(item.fields.get("user_sid")), ""),
                     "user_sid": item.fields.get("user_sid"), "source": item.source.cited_as})
    out.add("recycle-bin", "all",
            f"Items in the Recycle Bin: {_plural(len(deleted), 'deleted item')}, {_between(first, last)}",
            "low", "defense-evasion", "T1070.004",
            "The deleted files themselves ($R files) are still in the image; recover and review them.",
            deleted, detail={"deleted": rows})
    dated = [item for item in deleted if _parse_time(item.time)]
    best: list[Item] = []
    start = 0
    for end in range(len(dated)):
        while _parse_time(dated[end].time) - _parse_time(dated[start].time) > WINDOW:  # type: ignore[operator]
            start += 1
        if end - start + 1 > len(best):
            best = dated[start:end + 1]
    if len(best) >= MASS_DELETE_ITEMS:
        out.add("mass-deletion", best[0].time or "",
                f"Mass deletion: {len(best)} items sent to the Recycle Bin within "
                f"{int(WINDOW.total_seconds() // 60)} minutes from {best[0].time}",
                "medium", "defense-evasion", "T1070.004",
                "Check what was deleted and whether it followed the copying of the same files.",
                best, detail={"deleted": _rows(best, "original_path", "size_bytes")})
    secret = [item for item in deleted if looks_confidential(re.split(r"[\\/]", str(item.fields.get("original_path")))[-1])]
    if secret:
        out.add("confidential-deleted", "recycle",
                f"Confidential-looking file names among deleted items: {_plural(len(secret), 'item')}",
                "medium", "defense-evasion", "T1070.004",
                "Recover these files from the Recycle Bin and confirm what they are.",
                secret, confidence=0.6, detail={"deleted": _rows(secret, "original_path", "size_bytes")})
    return {"items": len(deleted), "first": first, "last": last}


def detect_clock_changes(items: list[Item], out: FindingBuilder) -> None:
    by_source: dict[str, list[Item]] = defaultdict(list)
    for item in items:
        if item.kind == "setup_section":
            by_source[item.source.cited_as].append(item)
    for cited, sections in by_source.items():
        jumps: list[tuple[timedelta, Item, Item]] = []
        previous: Item | None = None
        for item in sections:
            now = _parse_time(str(item.fields.get("local_time")) + "+00:00")
            before = _parse_time(str(previous.fields.get("local_time")) + "+00:00") if previous else None
            if now and before and before - now > CLOCK_JUMP:
                jumps.append((before - now, previous, item))  # type: ignore[arg-type]
            previous = item if now else previous
        if not jumps:
            continue
        largest = max(jump[0] for jump in jumps)
        out.add("clock-change", cited,
                f"System clock or time zone changed: local time in the device-install log goes backwards "
                f"{_plural(len(jumps), 'time')}, by up to {int(largest.total_seconds() // 3600)} hours",
                "medium", "defense-evasion", "T1070.006",
                "The log is written in order, so an earlier time after a later one means the clock was set back or "
                "the time zone was changed (Windows setup does this once). Treat times near these points with care.",
                [item for jump in jumps for item in jump[1:]], confidence=0.5,
                detail={"jumps": [{"from_local": jump[1].fields.get("local_time"),
                                   "to_local": jump[2].fields.get("local_time")} for jump in jumps[:MAX_DETAIL_ROWS]]})


def detect_network_shares(items: list[Item], out: FindingBuilder) -> list[dict[str, Any]]:
    shares: dict[str, list[Item]] = defaultdict(list)
    for item in items:
        if item.kind == "mapped_drive" or (item.kind == "mount_point" and item.fields.get("mount_type") == "network"):
            share = str(item.fields.get("share", "")).lower()
            if share:
                shares[share].append(item)
    summary = []
    for share, group in sorted(shares.items()):
        first, last = _span(item.time for item in group)
        letters = sorted({str(item.fields["drive"]) for item in group if item.fields.get("drive")})
        summary.append({"share": share, "drive_letters": letters, "first_seen": first, "last_seen": last,
                        "users": sorted({item.source.user for item in group if item.source.user})})
    if shares:
        everything = [item for group in shares.values() for item in group]
        first, last = _span(item.time for item in everything)
        out.add("network-shares", "all",
                f"Network shares used: {_plural(len(shares), 'share')} mapped or opened, {_between(first, last)}",
                "low", "collection", "T1039",
                "Check the file server's logs for what this account read from these shares.",
                sorted(everything, key=lambda item: item.time or ""), detail={"shares": summary[:MAX_DETAIL_ROWS]})
    return summary


def detect_archives(items: list[Item], out: FindingBuilder) -> None:
    archives = [item for item in items if item.kind == "archive_history"]
    if not archives:
        return
    tools = sorted({str(item.fields.get("tool")) for item in archives})
    first, last = _span(item.time for item in archives)
    out.add("archives", "history",
            f"Archives made or opened with {', '.join(tools)}: {_plural(len(archives), 'archive')} in the tool's history",
            "low", "collection", "T1560.001",
            "Packing files into an archive (sometimes with a misleading name) often comes just before copying them out.",
            archives, confidence=0.5, detail={"archives": _rows(archives, "tool", "path")})


def detect_system_profile(items: list[Item], out: FindingBuilder) -> dict[str, Any]:
    facts = [item for item in items if item.kind == "system_fact"]
    accounts = [item for item in items if item.kind == "user_account"]
    profiles = [item for item in items if item.kind == "user_profile"]
    system: dict[str, Any] = {}
    for item in facts:
        fact = str(item.fields.get("fact"))
        if fact == "time_zone":
            system["time_zone"] = item.fields.get("value")
            system["utc_offset_minutes"] = -int(item.fields.get("active_bias_minutes",
                                                                item.fields.get("bias_minutes", 0)) or 0)
            system["standard_utc_offset_minutes"] = -int(item.fields.get("bias_minutes", 0) or 0)
        elif fact in ("last_shutdown", "os_install_date"):
            system[fact] = item.time
        elif fact == "os_version":
            system["os_version"] = " ".join(str(item.fields.get(name, "")) for name in ("value", "service_pack")).strip()
            system["os_build"] = item.fields.get("build")
        else:
            system[fact] = item.fields.get("value")
    system["user_accounts"] = [{k: v for k, v in item.fields.items()} for item in accounts][:MAX_DETAIL_ROWS]
    system["user_profiles"] = [{"sid": item.fields.get("sid"), "path": item.fields.get("path"),
                                "profile_key_written": item.time} for item in profiles][:MAX_DETAIL_ROWS]
    if facts or accounts:
        known = [word for word, key in (("time zone", "time_zone"), ("install date", "os_install_date"),
                                        ("last shutdown", "last_shutdown"), ("computer name", "computer_name"))
                 if system.get(key)]
        out.add("system-profile", "profile",
                f"System profile recorded: {', '.join(known) or 'no system facts'}; "
                f"{_plural(len(accounts), 'user account')}",
                "info", "", "", "Use the time zone to turn local times in logs into UTC before comparing events.",
                facts + accounts, confidence=0.9, detail={"system": system})
    return system


# --------------------------------------------------------------------------
# Timeline
# --------------------------------------------------------------------------

_SUMMARY_FIELDS: dict[str, tuple[str, tuple[str, ...]]] = {
    "usb_device": ("USB storage device record written", ("vendor", "product", "serial")),
    "usb_connection": ("USB storage device interface registered", ("vendor", "product", "serial")),
    "usb_volume_name": ("USB volume name recorded", ("volume_name", "volume_serial", "serial")),
    "usb_bus_device": ("USB device record written", ("vendor_id", "product_id", "serial")),
    "device_install": ("Device installed", ("device_id",)),
    "mount_point": ("Volume or share mounted by user", ("share", "volume", "drive")),
    "mapped_drive": ("Network drive mapped", ("drive", "share")),
    "lnk": ("File opened (shortcut)", ("target_path", "drive_type", "volume_serial", "volume_label")),
    "jump_list": ("File opened (Jump List)", ("target_path", "drive_type", "volume_serial", "app_id")),
    "recent_doc": ("Recent document", ("name",)),
    "open_save": ("File chosen in an open/save dialog", ("path",)),
    "last_visited": ("Folder used in an open/save dialog", ("program", "folder")),
    "office_mru": ("Office document opened", ("app", "path")),
    "shellbag": ("Folder browsed", ("path",)),
    "typed_path": ("Path typed in Explorer", ("path",)),
    "typed_url": ("URL typed in Internet Explorer", ("url",)),
    "explorer_search": ("Explorer search", ("term",)),
    "user_assist": ("Program run (UserAssist)", ("program", "run_count")),
    "prefetch": ("Program run (Prefetch)", ("program", "run_count")),
    "installed_program": ("Program install record written", ("name", "version")),
    "program_key": ("Program settings key written", ("program", "key_path")),
    "autorun": ("Autostart entry", ("name", "command")),
    "cd_burning": ("CD burning record", ("what", "disc_label", "staging_path")),
    "cloud_file": ("File in cloud sync database", ("client", "side", "name", "size_bytes")),
    "archive_history": ("Archive in tool history", ("tool", "path")),
    "mail_profile": ("Mail profile", ("client", "profile")),
    "mail_store": ("Mail store file", ("client", "path")),
    "browser_visit": ("Web page visited", ("browser", "url")),
    "browser_download": ("File downloaded", ("browser", "target_path", "url")),
    "browser_file_open": ("Local file opened in browser", ("browser", "target_path")),
    "web_search": ("Web search", ("browser", "term")),
    "recycle_bin": ("File deleted to Recycle Bin", ("original_path", "size_bytes")),
    "system_fact": ("System fact", ("fact", "value")),
    "user_account": ("User account created", ("name", "rid")),
    "user_profile": ("User profile key written", ("sid", "path")),
    "optical_drive": ("Optical drive record written", ("friendly_name",)),
    "mounted_device": ("Mounted-devices list written", ("mount", "device")),
}


def timeline_rows(items: list[Item], context: Context) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in items:
        fields = item.fields
        if item.kind == "prefetch":
            for moment in fields.get("last_runs") or []:
                rows.append({"time": moment, "kind": "prefetch",
                             "summary": f"Program run (Prefetch): {fields.get('program')}",
                             "source": item.source.cited_as, "locator": item.record.locator,
                             "fields": {"program": fields.get("program"), "run_count": fields.get("run_count")}})
            continue
        moment = item.time
        approximate = False
        if moment is None and item.kind == "device_install":
            moment = _local_to_utc(str(fields.get("local_time", "")), context.bias_minutes)
            approximate = True
        if item.kind == "lnk" and item.source.modified:
            moment = item.source.modified
        if moment is None or item.kind in ("setup_section", "browser_table_state"):
            continue
        label, names = _SUMMARY_FIELDS.get(item.kind, (item.kind, ()))
        shown = {name: fields[name] for name in names if fields.get(name) not in (None, "")}
        row: dict[str, Any] = {"time": moment, "kind": item.kind,
                               "summary": clean_text(f"{label}: " + ", ".join(str(v) for v in shown.values()), 400),
                               "source": item.source.cited_as, "locator": item.record.locator, "fields": shown}
        if item.source.user:
            row["user"] = item.source.user
        if approximate:
            row["time_note"] = "local log time converted with the registry's current UTC offset"
        rows.append(row)
    rows.sort(key=lambda row: (row["time"], row["kind"], row["source"]))
    if len(rows) > MAX_TIMELINE_ROWS:
        # Keep everything except ordinary web visits first; they are the bulk.
        visits = [row for row in rows if row["kind"] == "browser_visit"]
        others = [row for row in rows if row["kind"] != "browser_visit"]
        rows = sorted(others[:MAX_TIMELINE_ROWS] + visits[:max(0, MAX_TIMELINE_ROWS - len(others))],
                      key=lambda row: (row["time"], row["kind"], row["source"]))
    return rows


# --------------------------------------------------------------------------
# One image
# --------------------------------------------------------------------------


def analyse_image(image_rel: str, image_dir: Path, members: list[Any], *, summary_rel: str = "",
                  seconds: float = ANALYSIS_SECONDS) -> Outcome:
    """Parse the copies of one image, write its timeline and summary keys, and return its findings.

    ``members`` are ``DiskMember`` objects (or anything with the same
    attributes). Nothing here raises for a bad artefact: each failure is a
    coverage gap in the outcome.
    """
    outcome = Outcome()
    files = image_dir / "files"
    sources = [Source(member.cited_as, files / member.extracted, member.sha256, member.member, member.category,
                      getattr(member, "modified", "") or "") for member in members]
    items, outcome.gaps, outcome.files_parsed = parse_sources(sources, time.monotonic() + seconds)
    context = build_context(items)
    touches = collect_touches(items, context)
    uses = collect_program_uses(items)
    summary_path = summary_rel or f"{image_dir.name}/disk_summary.json"
    with Rereader() as rereader:
        out = FindingBuilder(image_rel, summary_path, rereader)
        steps: tuple[tuple[str, Callable[[], Any]], ...] = (
            ("system", lambda: detect_system_profile(items, out)),
            ("usb_devices", lambda: detect_usb_devices(items, context, out)),
            ("external_files", lambda: detect_external_files(touches, out)),
            ("confidential", lambda: detect_confidential_names(touches, items, out)),
            ("disc_burning", lambda: detect_disc_burning(touches, items, uses, out)),
            ("programs", lambda: detect_programs(uses, touches, out)),
            ("web_categories", lambda: detect_web(items, out)),
            ("flagged_searches", lambda: detect_searches(items, out)),
            ("history", lambda: detect_history_clearing(items, out)),
            ("recycle_bin", lambda: detect_deletions(items, context, out)),
            ("clock", lambda: detect_clock_changes(items, out)),
            ("network_shares", lambda: detect_network_shares(items, out)),
            ("archives", lambda: detect_archives(items, out)),
        )
        results: dict[str, Any] = {}
        for name, step in steps:
            try:
                results[name] = step()
            except Exception as exc:  # noqa: BLE001 - one detection failing must not lose the others
                outcome.gaps.append({"what": f"{image_rel} {name}",
                                     "why": f"artefact detection step failed ({type(exc).__name__})"})
        for what, count in sorted(out.over_limit.items()):
            outcome.gaps.append({"what": image_rel, "why": f"{count} more {what}(s) have no finding of their own "
                                                           f"(limit {MAX_FINDINGS_PER_RULE}); see disk_summary.json"})
        if out.uncitable:
            outcome.gaps.append({"what": image_rel, "why": f"{out.uncitable} artefact finding(s) left out: no record "
                                                           "of theirs could be read back for a citation"})
        outcome.findings = out.findings
    rows = timeline_rows(items, context)
    text = "".join(json.dumps(row, sort_keys=True, ensure_ascii=True) + "\n" for row in rows)
    atomic_write_text(image_dir / TIMELINE_FILE, text)
    outcome.timeline_rows = len(rows)
    programs = results.get("programs") or {}
    outcome.summary = {
        "schema": SCHEMA_VERSION,
        "files_parsed": outcome.files_parsed,
        "records": dict(sorted(Counter(item.kind for item in items).items())),
        "system": results.get("system") or {},
        "usb_devices": results.get("usb_devices") or [],
        "network_shares": results.get("network_shares") or [],
        "cloud_clients": programs.get("cloud_storage", []),
        "anti_forensic_tools": programs.get("anti_forensics", []),
        "email_clients": programs.get("email_client", []),
        "other_watched_programs": {name: value for name, value in programs.items()
                                   if name not in ("cloud_storage", "anti_forensics", "email_client")},
        "web_categories": results.get("web_categories") or {},
        "flagged_searches": results.get("flagged_searches") or [],
        "recycle_bin": results.get("recycle_bin") or {"items": 0},
        "findings": out.details,
        "timeline_file": TIMELINE_FILE,
        "timeline_rows": len(rows),
        "gaps": outcome.gaps,
    }
    return outcome


def add_to_summary(summary_file: Path, artifacts: dict[str, Any]) -> None:
    """Add the ``artifacts`` key to an image's ``disk_summary.json``; every existing key is left as it is."""
    try:
        summary = json.loads(summary_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        summary = {}
    if not isinstance(summary, dict):
        summary = {}
    summary[SUMMARY_KEY] = artifacts
    atomic_write_text(summary_file, json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=True) + "\n")
