"""Read-only parsers for the Windows artefacts copied out of a disk image.

Every parser takes the path of a copy in the run folder and returns
``Record`` objects. A record says what it is, when it happened (UTC), a few
plain fields, and a *locator*: where in the copy the record can be read
again. The coordinator uses the locator to re-read the record and compare
a SHA-256 with the one the agent stored, so a finding cannot outlive a
change to the copy it cites.

Locators:

``regk:<offset>``
    The registry key cell that starts at this byte offset of the hive.
``regv:<offset>``
    The registry value cell at this offset, together with its data.
``bytes:<offset>:<length>``
    A byte range of the file (a shortcut, a log line, a Prefetch header).
``sqlite:<table>:<rowid>``
    One row of a browser database, read by its row id.
``file``
    No smaller location could be given (for example a compressed Prefetch
    file or an ESE database); the whole copy is re-hashed instead.

The inputs come from a suspect's disk, so they are treated as hostile:
every offset is bounds-checked, every loop is capped, and each parser
stops at ``ParseBudget``. A parser raises on a file it cannot read; the
agent turns that into a coverage gap.
"""

from __future__ import annotations

import hashlib
import json
import mmap
import re
import shutil
import sqlite3
import struct
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import parse_qs, urlsplit

MAX_RECORDS_PER_FILE = 20_000
MAX_SPAN_BYTES = 1024 * 1024
MAX_VALUE_BYTES = 1024 * 1024
MAX_TEXT = 520
MAX_HIVE_CELLS = 2_000_000
MAX_KEY_CHILDREN = 100_000
MAX_SQLITE_BYTES = 512 * 1024 * 1024
MAX_SQLITE_STEPS = 50_000_000
MAX_LOG_BYTES = 64 * 1024 * 1024
MAX_STREAM_BYTES = 8 * 1024 * 1024
PARSE_SECONDS = 120

_EPOCH_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)
_EPOCH_1970 = datetime(1970, 1, 1, tzinfo=timezone.utc)
_MIN_YEAR, _MAX_YEAR = 1980, 2100


class ParseError(ValueError):
    """The file is not what its name says, or it is damaged."""


class ParseBudget(ParseError):
    """A cap on records, cells or time was reached."""


@dataclass(slots=True)
class Record:
    kind: str
    time: str | None
    fields: dict[str, Any]
    locator: str = "file"


@dataclass(slots=True)
class Deadline:
    seconds: float = PARSE_SECONDS
    started: float = field(default_factory=time.monotonic)

    def check(self) -> None:
        if time.monotonic() - self.started > self.seconds:
            raise ParseBudget("time limit reached")


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------


def _iso(moment: datetime) -> str | None:
    if not _MIN_YEAR <= moment.year <= _MAX_YEAR:
        return None
    return moment.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def filetime_iso(value: int) -> str | None:
    """A Windows FILETIME (100 ns ticks since 1601) as ISO UTC, or None when it is empty or absurd."""
    if not 0 < value < 0x7FFFFFFFFFFFFFFF:
        return None
    try:
        return _iso(_EPOCH_1601 + timedelta(microseconds=value // 10))
    except OverflowError:
        return None


def webkit_iso(value: Any) -> str | None:
    """Chrome time: microseconds since 1601."""
    return filetime_iso(int(value) * 10) if isinstance(value, int) and value > 0 else None


def unix_micro_iso(value: Any) -> str | None:
    """Firefox time: microseconds since 1970."""
    if not isinstance(value, int) or value <= 0:
        return None
    try:
        return _iso(_EPOCH_1970 + timedelta(microseconds=value))
    except OverflowError:
        return None


def unix_iso(value: Any) -> str | None:
    if not isinstance(value, int) or value <= 0:
        return None
    try:
        return _iso(_EPOCH_1970 + timedelta(seconds=value))
    except OverflowError:
        return None


def fat_iso(date: int, clock: int) -> str | None:
    """A FAT date and time pair (as stored in shell items; UTC there)."""
    if not date:
        return None
    try:
        return _iso(datetime(1980 + (date >> 9), (date >> 5) & 0xF, date & 0x1F, clock >> 11, (clock >> 5) & 0x3F,
                             min(59, (clock & 0x1F) * 2), tzinfo=timezone.utc))
    except ValueError:
        return None


def clean_text(value: Any, limit: int = MAX_TEXT) -> str:
    """One line of printable text, cut to ``limit`` characters."""
    text = value if isinstance(value, str) else str(value)
    text = "".join(ch if ch.isprintable() else " " for ch in text)
    return text.strip()[:limit]


def utf16(data: bytes, limit: int = MAX_TEXT) -> str:
    """A NUL-terminated UTF-16-LE string from the start of ``data``."""
    end = len(data) - (len(data) % 2)
    for index in range(0, end, 2):
        if data[index] == 0 and data[index + 1] == 0:
            end = index
            break
    return clean_text(data[:end].decode("utf-16-le", errors="replace"), limit)


def _cstring(data: bytes, start: int, limit: int = 1040) -> bytes:
    if start < 0 or start >= len(data):
        return b""
    end = data.find(b"\0", start, start + limit)
    return data[start:end if end >= 0 else start + limit]


def _wstring(data: bytes, start: int, limit: int = 2080) -> str:
    if start < 0 or start >= len(data):
        return ""
    return utf16(data[start:start + limit])


def rot13(text: str) -> str:
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + 13) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + 13) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_span(path: Path, offset: int, length: int) -> bytes | None:
    """``length`` bytes at ``offset``, or None when the file does not hold them all."""
    if offset < 0 or not 0 < length <= MAX_SPAN_BYTES:
        return None
    with path.open("rb") as handle:
        handle.seek(offset)
        data = handle.read(length)
    return data if len(data) == length else None


# --------------------------------------------------------------------------
# Registry hives (regf)
# --------------------------------------------------------------------------

_HIVE_HEADER = 4096
REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_MULTI_SZ, REG_QWORD = 1, 2, 3, 4, 7, 11


class Hive:
    """A registry hive read straight from its file, keeping the byte offset of every key and value.

    Only the primary file is read. Changes still waiting in ``.LOG1``/``.LOG2``
    are not applied; ``dirty`` is True when the header says such changes exist.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._file = path.open("rb")
        try:
            size = path.stat().st_size
            if size < _HIVE_HEADER + 32:
                raise ParseError("too small to be a registry hive")
            self.data = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)
        except (ValueError, OSError) as exc:
            self._file.close()
            raise ParseError("registry hive could not be mapped") from exc
        if self.data[:4] != b"regf":
            self.close()
            raise ParseError("not a registry hive (no regf signature)")
        seq1, seq2 = struct.unpack_from("<II", self.data, 4)
        self.dirty = seq1 != seq2
        self.root_offset = struct.unpack_from("<I", self.data, 36)[0]
        self.cells_left = MAX_HIVE_CELLS
        self.deadline = Deadline()

    def close(self) -> None:
        try:
            self.data.close()
        finally:
            self._file.close()

    def __enter__(self) -> "Hive":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- cells ---------------------------------------------------------

    def cell(self, offset: int) -> tuple[int, int]:
        """(absolute start, length) of the cell at a hive-relative offset, size field included."""
        self.cells_left -= 1
        if self.cells_left < 0:
            raise ParseBudget("registry cell limit reached")
        if self.cells_left % 4096 == 0:
            self.deadline.check()
        start = _HIVE_HEADER + offset
        if offset < 0 or offset == 0xFFFFFFFF or start + 4 > len(self.data):
            raise ParseError("registry cell offset is outside the hive")
        size = abs(struct.unpack_from("<i", self.data, start)[0])
        if size < 8 or start + size > len(self.data):
            raise ParseError("registry cell size is outside the hive")
        return start, size

    def root(self) -> "RegKey":
        return self.key_at(_HIVE_HEADER + self.root_offset)

    def key_at(self, start: int, parent_path: str = "") -> "RegKey":
        """The key whose cell starts at absolute offset ``start``."""
        absolute, size = self.cell(start - _HIVE_HEADER)
        if size < 0x50 or self.data[absolute + 4:absolute + 6] != b"nk":
            raise ParseError("registry key cell has no nk signature")
        body = absolute + 4
        flags = struct.unpack_from("<H", self.data, body + 2)[0]
        stamp = struct.unpack_from("<Q", self.data, body + 4)[0]
        subkey_count, _, subkey_list = struct.unpack_from("<III", self.data, body + 0x14)
        value_count, value_list = struct.unpack_from("<II", self.data, body + 0x24)
        name_length = struct.unpack_from("<H", self.data, body + 0x48)[0]
        raw = bytes(self.data[body + 0x4C:body + 0x4C + min(name_length, size - 0x50)])
        name = raw.decode("latin-1") if flags & 0x20 else raw.decode("utf-16-le", errors="replace")
        return RegKey(self, absolute, size, name, stamp, subkey_count, subkey_list, value_count, value_list,
                      f"{parent_path}\\{name}" if parent_path else name)

    def value_at(self, start: int) -> "RegValue":
        absolute, size = self.cell(start - _HIVE_HEADER)
        if size < 0x18 or self.data[absolute + 4:absolute + 6] != b"vk":
            raise ParseError("registry value cell has no vk signature")
        body = absolute + 4
        name_length, data_length, data_offset, kind, flags = struct.unpack_from("<HIIIH", self.data, body + 2)
        raw = bytes(self.data[body + 0x14:body + 0x14 + min(name_length, size - 0x18)])
        name = raw.decode("latin-1") if flags & 1 else raw.decode("utf-16-le", errors="replace")
        return RegValue(self, absolute, size, name, kind, data_length, data_offset)

    def open(self, path: str) -> "RegKey | None":
        """The key at ``path`` below the root (``A\\B\\C``), or None."""
        key = self.root()
        key.path = ""
        for part in [piece for piece in path.split("\\") if piece]:
            found = key.subkey(part)
            if found is None:
                return None
            key = found
        return key

    def locator_bytes(self, locator: str) -> bytes | None:
        """The bytes a ``regk:``/``regv:`` locator stands for, or None when it no longer parses."""
        kind, _, text = locator.partition(":")
        try:
            start = int(text)
            if kind == "regk":
                key = self.key_at(start)
                return bytes(self.data[key.offset:key.offset + key.size])
            if kind == "regv":
                value = self.value_at(start)
                return bytes(self.data[value.offset:value.offset + value.size]) + value.data
        except (ParseError, struct.error, ValueError):
            return None
        return None


@dataclass(slots=True)
class RegKey:
    hive: Hive
    offset: int
    size: int
    name: str
    filetime: int
    subkey_count: int
    subkey_list: int
    value_count: int
    value_list: int
    path: str = ""

    @property
    def locator(self) -> str:
        return f"regk:{self.offset}"

    @property
    def time(self) -> str | None:
        return filetime_iso(self.filetime)

    def _child_offsets(self, list_offset: int, depth: int = 0) -> Iterator[int]:
        if depth > 4:
            raise ParseError("registry subkey list is nested too deeply")
        absolute, size = self.hive.cell(list_offset)
        signature = bytes(self.hive.data[absolute + 4:absolute + 6])
        count = struct.unpack_from("<H", self.hive.data, absolute + 6)[0]
        step = 8 if signature in (b"lf", b"lh") else 4
        if signature not in (b"lf", b"lh", b"li", b"ri"):
            raise ParseError("registry subkey list has an unknown signature")
        count = min(count, (size - 8) // step)
        for index in range(count):
            child = struct.unpack_from("<I", self.hive.data, absolute + 8 + index * step)[0]
            if signature == b"ri":
                yield from self._child_offsets(child, depth + 1)
            else:
                yield child

    def subkeys(self) -> Iterator["RegKey"]:
        if not self.subkey_count or self.subkey_list == 0xFFFFFFFF:
            return
        for number, child in enumerate(self._child_offsets(self.subkey_list)):
            if number >= MAX_KEY_CHILDREN:
                raise ParseBudget("registry key has too many subkeys")
            try:
                yield self.hive.key_at(_HIVE_HEADER + child, self.path)
            except ParseBudget:
                raise
            except (ParseError, struct.error):
                continue  # one damaged child does not hide its siblings

    def subkey(self, name: str) -> "RegKey | None":
        wanted = name.casefold()
        for child in self.subkeys():
            if child.name.casefold() == wanted:
                return child
        return None

    def values(self) -> Iterator["RegValue"]:
        if not self.value_count or self.value_list == 0xFFFFFFFF:
            return
        absolute, size = self.hive.cell(self.value_list)
        count = min(self.value_count, (size - 4) // 4, MAX_KEY_CHILDREN)
        for index in range(count):
            offset = struct.unpack_from("<I", self.hive.data, absolute + 4 + index * 4)[0]
            try:
                yield self.hive.value_at(_HIVE_HEADER + offset)
            except ParseBudget:
                raise
            except (ParseError, struct.error):
                continue

    def value(self, name: str) -> "RegValue | None":
        wanted = name.casefold()
        for item in self.values():
            if item.name.casefold() == wanted:
                return item
        return None

    def text(self, name: str) -> str:
        item = self.value(name)
        return item.text if item is not None else ""

    def open(self, path: str) -> "RegKey | None":
        key: RegKey | None = self
        for part in [piece for piece in path.split("\\") if piece]:
            key = key.subkey(part) if key is not None else None
            if key is None:
                return None
        return key


@dataclass(slots=True)
class RegValue:
    hive: Hive
    offset: int
    size: int
    name: str
    kind: int
    data_length: int
    data_offset: int

    @property
    def locator(self) -> str:
        return f"regv:{self.offset}"

    @property
    def data(self) -> bytes:
        length = self.data_length & 0x7FFFFFFF
        if self.data_length & 0x80000000:  # stored inside the value cell
            return struct.pack("<I", self.data_offset)[:min(length, 4)]
        if length == 0:
            return b""
        try:
            absolute, size = self.hive.cell(self.data_offset)
        except ParseBudget:
            raise
        except ParseError:
            return b""
        wanted = min(length, MAX_VALUE_BYTES)
        if length > 16344 and self.hive.data[absolute + 4:absolute + 6] == b"db":
            return self._big_data(absolute, wanted)
        return bytes(self.hive.data[absolute + 4:absolute + 4 + min(wanted, size - 4)])

    def _big_data(self, absolute: int, wanted: int) -> bytes:
        count, list_offset = struct.unpack_from("<HI", self.hive.data, absolute + 6)
        list_start, list_size = self.hive.cell(list_offset)
        out = bytearray()
        for index in range(min(count, (list_size - 4) // 4)):
            segment = struct.unpack_from("<I", self.hive.data, list_start + 4 + index * 4)[0]
            start, size = self.hive.cell(segment)
            out += self.hive.data[start + 4:start + 4 + min(size - 4, 16344)]
            if len(out) >= wanted:
                break
        return bytes(out[:wanted])

    @property
    def text(self) -> str:
        if self.kind in (REG_SZ, REG_EXPAND_SZ):
            return utf16(self.data, 2048)
        if self.kind == REG_MULTI_SZ:
            return clean_text(self.data.decode("utf-16-le", errors="replace").replace("\0", " | "), 2048).strip(" |")
        if self.kind in (REG_DWORD, REG_QWORD):
            return str(self.number)
        return ""

    @property
    def number(self) -> int | None:
        data = self.data
        if self.kind == REG_DWORD and len(data) >= 4:
            return struct.unpack_from("<I", data)[0]
        if self.kind == REG_QWORD and len(data) >= 8:
            return struct.unpack_from("<Q", data)[0]
        if len(data) == 4:
            return struct.unpack_from("<I", data)[0]
        if len(data) == 8:
            return struct.unpack_from("<Q", data)[0]
        return None


def walk_keys(key: RegKey, max_depth: int, limit: int = MAX_RECORDS_PER_FILE) -> Iterator[RegKey]:
    """Depth-first keys below ``key`` (not ``key`` itself), at most ``max_depth`` levels and ``limit`` keys."""
    stack = [(child, 1) for child in key.subkeys()]
    seen = 0
    while stack:
        node, depth = stack.pop()
        seen += 1
        if seen > limit:
            return
        yield node
        if depth < max_depth:
            stack.extend((child, depth + 1) for child in node.subkeys())


# --------------------------------------------------------------------------
# Shell items (the folder-by-folder paths inside shortcuts and MRU lists)
# --------------------------------------------------------------------------

_BEEF0004 = b"\x04\x00\xef\xbe"
_KNOWN_ROOTS = {
    "20d04fe0-3aea-1069-a2d8-08002b30309d": "",  # My Computer
    "450d8fba-ad25-11d0-98a8-0800361b1103": "Documents",
    "f02c1a0d-be21-4350-88b0-7367fc96ef3c": "Network",
    "208d2c60-3aea-1069-a2d7-08002b30309d": "Network",
    "031e4825-7b94-4dc3-b131-e946b44c8dd5": "Libraries",
    "59031a47-3f72-44a7-89c5-5595fe6b30ee": "UserProfile",
    "645ff040-5081-101b-9f08-00aa002f954e": "RecycleBin",
}


def _guid(data: bytes) -> str:
    if len(data) < 16:
        return ""
    a, b, c = struct.unpack_from("<IHH", data)
    return f"{a:08x}-{b:04x}-{c:04x}-{data[8:10].hex()}-{data[10:16].hex()}"


def _item_name(item: bytes) -> tuple[str, str]:
    """(kind, name) for one shell item, or ("", "") when it is a type this reader skips."""
    if len(item) < 4:
        return "", ""
    kind = item[2]
    if kind == 0x1F and len(item) >= 20:
        return "root", _KNOWN_ROOTS.get(_guid(item[4:20]), "")
    if kind & 0x70 == 0x20:  # volume: "E:\"
        name = _cstring(item, 3, 8).decode("latin-1", errors="replace")
        return ("volume", name.rstrip("\\")) if re.fullmatch(r"[A-Za-z]:\\?", name) else ("", "")
    if kind & 0x70 == 0x40:  # network location: "\\server\share"
        return "network", clean_text(_cstring(item, 5, 520).decode("latin-1", errors="replace"))
    if kind & 0x70 == 0x30 or kind == 0x74 or kind == 0xB1:  # file or folder entry
        marker = item.find(_BEEF0004, 14)
        if marker >= 4:
            block = marker - 4
            version = struct.unpack_from("<H", item, block + 2)[0]
            start = block + (46 if version >= 9 else 42 if version == 8 else 38 if version >= 7 else 20)
            name = _wstring(item, start)
            if name:
                return "entry", name
        if kind & 0x04:
            return "entry", _wstring(item, 14)
        return "entry", clean_text(_cstring(item, 14, 260).decode("latin-1", errors="replace"))
    return "", ""


def shell_path(data: bytes, max_items: int = 64) -> str:
    """A best-effort path from an ITEMIDLIST. Unknown item types are skipped, so parts can be missing."""
    parts: list[str] = []
    position = 0
    for _ in range(max_items):
        if position + 2 > len(data):
            break
        size = struct.unpack_from("<H", data, position)[0]
        if size < 2 or position + size > len(data):
            break
        kind, name = _item_name(data[position:position + size])
        position += size
        if not name:
            continue
        if kind in ("volume", "network"):
            parts = [name]
        elif kind == "root":
            parts = [name] if name else []
        else:
            parts.append(name)
    return clean_text("\\".join(parts), 1024)


def _idlist_size(data: bytes, start: int = 0) -> int:
    """Bytes used by the ITEMIDLIST at ``start`` including its terminator."""
    position = start
    while position + 2 <= len(data):
        size = struct.unpack_from("<H", data, position)[0]
        if size == 0:
            return position + 2 - start
        if size < 2:
            break
        position += size
    return len(data) - start


# --------------------------------------------------------------------------
# Shortcuts (LNK)
# --------------------------------------------------------------------------

LNK_MAGIC = b"L\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00F"
DRIVE_TYPES = {0: "unknown", 1: "no-root", 2: "removable", 3: "fixed", 4: "network", 5: "cdrom", 6: "ramdisk"}


def parse_lnk_bytes(data: bytes) -> tuple[dict[str, Any], int]:
    """(fields, bytes used) for the shortcut at the start of ``data``. Raises ParseError when it is not one."""
    if len(data) < 76 or data[:20] != LNK_MAGIC:
        raise ParseError("not a shortcut (no LNK header)")
    flags, attributes = struct.unpack_from("<II", data, 20)
    created, accessed, written, size = struct.unpack_from("<QQQI", data, 28)
    out: dict[str, Any] = {
        "target_created": filetime_iso(created), "target_accessed": filetime_iso(accessed),
        "target_modified": filetime_iso(written), "target_size": size,
        "target_is_folder": bool(attributes & 0x10),
    }
    position = 76
    if flags & 0x1:  # target ID list
        if position + 2 > len(data):
            raise ParseError("shortcut is cut short")
        length = struct.unpack_from("<H", data, position)[0]
        out["id_list_path"] = shell_path(data[position + 2:position + 2 + length])
        position += 2 + length
    if flags & 0x2:  # link info: where the target lived
        if position + 28 > len(data):
            raise ParseError("shortcut is cut short")
        info_size, header_size, info_flags, volume_at, base_at, network_at, suffix_at = struct.unpack_from(
            "<7I", data, position)
        info = data[position:position + min(info_size, 8192)]
        base = suffix = ""
        if header_size >= 0x24 and len(info) >= 0x24:
            base_w, suffix_w = struct.unpack_from("<II", info, 28)
            base = _wstring(info, base_w) if info_flags & 1 and base_w else ""
            suffix = _wstring(info, suffix_w) if suffix_w else ""
        if info_flags & 1 and volume_at and volume_at + 16 <= len(info):
            volume_size, drive_type, serial, label_at = struct.unpack_from("<4I", info, volume_at)
            volume = info[volume_at:volume_at + min(volume_size, 1024)]
            out["drive_type"] = DRIVE_TYPES.get(drive_type, "unknown")
            out["volume_serial"] = f"{serial >> 16:04X}-{serial & 0xFFFF:04X}"
            if label_at == 0x14 and len(volume) >= 0x14:
                out["volume_label"] = _wstring(volume, struct.unpack_from("<I", volume, 16)[0], 128)
            else:
                out["volume_label"] = clean_text(_cstring(volume, label_at, 64).decode("latin-1", errors="replace"))
            if not base:
                base = clean_text(_cstring(info, base_at).decode("latin-1", errors="replace"))
        if info_flags & 2 and network_at and network_at + 20 <= len(info):
            net = info[network_at:]
            _, _, name_at, device_at, _ = struct.unpack_from("<5I", net, 0)
            share = clean_text(_cstring(net, name_at).decode("latin-1", errors="replace"))
            if name_at > 0x14 and len(net) >= 0x1C:
                wide = _wstring(net, struct.unpack_from("<I", net, 0x14)[0])
                share = wide or share
            out["network_share"] = share
            if device_at:
                out["network_device"] = clean_text(_cstring(net, device_at, 16).decode("latin-1", errors="replace"))
            out.setdefault("drive_type", "network")
        if not suffix and suffix_at:
            suffix = clean_text(_cstring(info, suffix_at).decode("latin-1", errors="replace"))
        if out.get("network_share") and not base:
            base = out["network_share"]
        if base and suffix:
            out["target_path"] = clean_text(base.rstrip("\\") + "\\" + suffix, 1024)
        elif base or suffix:
            out["target_path"] = clean_text(base or suffix, 1024)
        position += max(info_size, 4)
    for bit, name in ((0x4, "description"), (0x8, "relative_path"), (0x10, "working_dir"), (0x20, "arguments"),
                      (0x40, "icon_location")):
        if not flags & bit:
            continue
        if position + 2 > len(data):
            break
        count = struct.unpack_from("<H", data, position)[0]
        width = 2 if flags & 0x80 else 1
        raw = data[position + 2:position + 2 + count * width]
        text = raw.decode("utf-16-le" if width == 2 else "latin-1", errors="replace")
        if name in ("relative_path", "working_dir", "arguments"):
            out[name] = clean_text(text, 1024)
        position += 2 + count * width
    while position + 4 <= len(data):  # extra data blocks
        block_size = struct.unpack_from("<I", data, position)[0]
        if block_size < 4:
            position += 4
            break
        if position + block_size > len(data):
            position = len(data)
            break
        signature = struct.unpack_from("<I", data, position + 4)[0] if block_size >= 8 else 0
        if signature == 0xA0000003 and block_size >= 0x60:  # tracker: the computer the target was on
            out["machine_id"] = clean_text(_cstring(data, position + 16, 16).decode("latin-1", errors="replace"), 32)
            out["mac_address"] = ":".join(f"{byte:02x}" for byte in data[position + 58:position + 64])
        position += block_size
    if "target_path" not in out and out.get("id_list_path"):
        out["target_path"] = out["id_list_path"]
    return out, min(position, len(data))


def _lnk_time(fields: dict[str, Any]) -> str | None:
    return fields.get("target_accessed") or fields.get("target_modified") or fields.get("target_created")


def parse_lnk(path: Path) -> list[Record]:
    data = path.read_bytes()[:MAX_SPAN_BYTES]
    fields, used = parse_lnk_bytes(data)
    fields["shortcut_name"] = clean_text(path.name, 255)
    return [Record("lnk", _lnk_time(fields), fields, f"bytes:0:{max(used, 76)}")]


# --------------------------------------------------------------------------
# Jump Lists
# --------------------------------------------------------------------------

_CFB_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_END_OF_CHAIN = 0xFFFFFFFE


class CompoundFile:
    """Just enough of the OLE compound file format to read the streams of a Jump List."""

    def __init__(self, data: bytes) -> None:
        if len(data) < 512 or data[:8] != _CFB_MAGIC:
            raise ParseError("not a compound file")
        self.data = data
        sector_shift, mini_shift = struct.unpack_from("<HH", data, 30)
        if sector_shift not in (9, 12) or mini_shift != 6:
            raise ParseError("compound file has an unusual sector size")
        self.sector = 1 << sector_shift
        self.mini = 1 << mini_shift
        fat_count, dir_start = struct.unpack_from("<II", data, 44)
        self.cutoff, minifat_start, _, difat_start, difat_count = struct.unpack_from("<5I", data, 56)
        max_sectors = len(data) // self.sector + 1
        fat_sectors = [s for s in struct.unpack_from("<109I", data, 76) if s < _END_OF_CHAIN][:fat_count]
        hops = 0
        while difat_start < _END_OF_CHAIN and hops < min(difat_count, max_sectors):
            block = self._sector(difat_start)
            entries = struct.unpack_from(f"<{self.sector // 4}I", block.ljust(self.sector, b"\xff"))
            fat_sectors.extend(s for s in entries[:-1] if s < _END_OF_CHAIN)
            difat_start = entries[-1]
            hops += 1
        fat_raw = b"".join(self._sector(s) for s in fat_sectors[:max_sectors])
        self.fat = struct.unpack_from(f"<{len(fat_raw) // 4}I", fat_raw)
        self.max_chain = max_sectors
        self.entries: list[tuple[str, int, int, int, int]] = []  # name, type, start, size, entry offset
        for number, offset in enumerate(self._chain_offsets(dir_start)):
            if number > 4096:
                break
            for slot in range(0, self.sector, 128):
                entry = data[offset + slot:offset + slot + 128]
                if len(entry) < 128:
                    continue
                name_length = struct.unpack_from("<H", entry, 64)[0]
                kind = entry[66]
                if kind not in (1, 2, 5) or not 2 <= name_length <= 64:
                    continue
                name = entry[:name_length - 2].decode("utf-16-le", errors="replace")
                start, size = struct.unpack_from("<IQ", entry, 116)
                if self.sector == 512:
                    size &= 0xFFFFFFFF
                self.entries.append((name, kind, start, size, offset + slot))
        root = next((e for e in self.entries if e[1] == 5), None)
        self._mini_stream = self._read_chain(root[2], min(root[3], MAX_STREAM_BYTES)) if root else b""
        minifat_raw = self._read_chain(minifat_start, MAX_STREAM_BYTES) if minifat_start < _END_OF_CHAIN else b""
        self.minifat = struct.unpack_from(f"<{len(minifat_raw) // 4}I", minifat_raw)

    def _sector(self, number: int) -> bytes:
        start = (number + 1) * self.sector
        return self.data[start:start + self.sector]

    def _chain_offsets(self, start: int) -> Iterator[int]:
        sector, hops = start, 0
        while sector < _END_OF_CHAIN and hops < self.max_chain:
            yield (sector + 1) * self.sector
            sector = self.fat[sector] if sector < len(self.fat) else _END_OF_CHAIN
            hops += 1

    def _read_chain(self, start: int, size: int) -> bytes:
        out = bytearray()
        for offset in self._chain_offsets(start):
            out += self.data[offset:offset + self.sector]
            if len(out) >= size:
                break
        return bytes(out[:size])

    def stream(self, entry: tuple[str, int, int, int, int]) -> bytes:
        _, _, start, size, _ = entry
        size = min(size, MAX_STREAM_BYTES)
        if size >= self.cutoff:
            return self._read_chain(start, size)
        out = bytearray()
        sector, hops = start, 0
        while sector < _END_OF_CHAIN and hops < len(self.minifat) + 1 and len(out) < size:
            out += self._mini_stream[sector * self.mini:(sector + 1) * self.mini]
            sector = self.minifat[sector] if sector < len(self.minifat) else _END_OF_CHAIN
            hops += 1
        return bytes(out[:size])


def _dest_list(data: bytes) -> dict[int, dict[str, Any]]:
    """Entries of a Jump List's DestList stream by entry number: path, last use, host name, use count."""
    if len(data) < 32:
        return {}
    version, count = struct.unpack_from("<II", data, 0)
    fixed = 114 if version == 1 else 130
    out: dict[int, dict[str, Any]] = {}
    position = 32
    for _ in range(min(count, 10_000)):
        if position + fixed > len(data):
            break
        number = struct.unpack_from("<I", data, position + 88)[0]
        stamp = struct.unpack_from("<Q", data, position + 100)[0]
        length = struct.unpack_from("<H", data, position + fixed - 2)[0]
        raw = data[position + fixed:position + fixed + length * 2]
        entry: dict[str, Any] = {
            "path": clean_text(raw.decode("utf-16-le", errors="replace"), 1024),
            "last_used": filetime_iso(stamp),
            "host": clean_text(_cstring(data, position + 72, 16).decode("latin-1", errors="replace"), 32),
        }
        if version != 1:
            entry["use_count"] = struct.unpack_from("<I", data, position + 116)[0]
        out[number] = entry
        position += fixed + length * 2 + (0 if version == 1 else 4)
    return out


def parse_automatic_destinations(path: Path) -> list[Record]:
    """Shortcuts stored in a ``.automaticDestinations-ms`` Jump List, joined with the DestList usage entries.

    Each record cites the 128-byte directory entry of its stream: the place
    in the compound file that names the stream and says where it starts.
    """
    data = path.read_bytes()
    if len(data) > 64 * 1024 * 1024:
        raise ParseBudget("Jump List is larger than 64 MB")
    cfb = CompoundFile(data)
    app_id = clean_text(path.name.split(".")[0], 32)
    dest: dict[int, dict[str, Any]] = {}
    for entry in cfb.entries:
        if entry[1] == 2 and entry[0] == "DestList":
            dest = _dest_list(cfb.stream(entry))
    records: list[Record] = []
    seen: set[int] = set()
    for entry in cfb.entries:
        name, kind, _, _, entry_offset = entry
        if kind != 2 or name == "DestList" or len(records) >= MAX_RECORDS_PER_FILE:
            continue
        try:
            fields, _ = parse_lnk_bytes(cfb.stream(entry))
        except (ParseError, struct.error):
            continue
        fields["app_id"] = app_id
        try:
            number = int(name, 16)
        except ValueError:
            number = -1
        used = dest.get(number)
        if used:
            seen.add(number)
            fields["dest_path"] = used["path"]
            fields["host"] = used["host"]
            if "use_count" in used:
                fields["use_count"] = used["use_count"]
            fields.setdefault("target_path", used["path"])
        # The shortcut's own times describe the target file; only the DestList entry says when it was used.
        records.append(Record("jump_list", (used or {}).get("last_used"), fields, f"bytes:{entry_offset}:128"))
    for number, used in dest.items():
        # A DestList entry whose shortcut stream is gone still says a file was used.
        if number not in seen and len(records) < MAX_RECORDS_PER_FILE and used["path"]:
            records.append(Record("jump_list", used["last_used"],
                                  {"app_id": app_id, "target_path": used["path"], "dest_path": used["path"],
                                   "host": used["host"], "from_dest_list_only": True}, "file"))
    return records


def parse_custom_destinations(path: Path) -> list[Record]:
    """Shortcuts stored one after another in a ``.customDestinations-ms`` Jump List."""
    data = path.read_bytes()[:16 * 1024 * 1024]
    app_id = clean_text(path.name.split(".")[0], 32)
    records: list[Record] = []
    position = data.find(LNK_MAGIC)
    while position >= 0 and len(records) < MAX_RECORDS_PER_FILE:
        following = data.find(LNK_MAGIC, position + 76)
        chunk = data[position:following if following >= 0 else len(data)]
        try:
            fields, used = parse_lnk_bytes(chunk[:MAX_SPAN_BYTES])
        except (ParseError, struct.error):
            position = following
            continue
        fields["app_id"] = app_id
        fields["pinned_or_task"] = True  # custom lists hold pinned items and tasks; they carry no time of use
        records.append(Record("jump_list", None, fields, f"bytes:{position}:{max(used, 76)}"))
        position = following
    return records


# --------------------------------------------------------------------------
# Prefetch
# --------------------------------------------------------------------------


def _decompress_prefetch(data: bytes) -> bytes:
    """Windows 10 stores Prefetch as ``MAM\\x04`` + size + XPRESS-Huffman data."""
    import inspect
    import io

    from dissect.util.compression import lzxpress_huffman

    size = struct.unpack_from("<I", data, 4)[0]
    if size > 32 * 1024 * 1024 or len(data) > 2 * 1024 * 1024:
        raise ParseBudget("compressed Prefetch file is larger than 2 MB or expands past 32 MB")
    # Newer dissect.util stops at the stated size; older versions read to the end of the (capped) input.
    bounded = "size" in inspect.signature(lzxpress_huffman.decompress).parameters
    try:
        stream = io.BytesIO(data[8:])
        out = lzxpress_huffman.decompress(stream, size) if bounded else lzxpress_huffman.decompress(stream)
    except Exception as exc:  # noqa: BLE001 - the decompressor raises many types on damaged input
        raise ParseError("compressed Prefetch data is damaged") from exc
    return bytes(out[:size])


def parse_prefetch(path: Path) -> list[Record]:
    raw = path.read_bytes()
    if len(raw) > 32 * 1024 * 1024:
        raise ParseBudget("Prefetch file is larger than 32 MB")
    compressed = raw[:3] == b"MAM"
    data = _decompress_prefetch(raw) if compressed else raw
    if len(data) < 0x9C or data[4:8] != b"SCCA":
        raise ParseError("not a Prefetch file (no SCCA signature)")
    version = struct.unpack_from("<I", data, 0)[0]
    name = utf16(data[0x10:0x10 + 60], 60)
    path_hash = struct.unpack_from("<I", data, 0x4C)[0]
    if version == 17:
        times_at, slots, count_at = 0x78, 1, 0x90
    elif version == 23:
        times_at, slots, count_at = 0x80, 1, 0x98
    elif version in (26, 30, 31):
        times_at, slots = 0x80, 8
        # Windows 10 1903+ dropped eight bytes of the file information block.
        count_at = 0xC8 if version >= 30 and struct.unpack_from("<I", data, 0x54)[0] == 0x128 else 0xD0
    else:
        raise ParseError(f"Prefetch version {version} is not supported")
    if len(data) < count_at + 4:
        raise ParseError("Prefetch file is cut short")
    runs = [stamp for stamp in (filetime_iso(value) for value in struct.unpack_from(f"<{slots}Q", data, times_at))
            if stamp]
    run_count = struct.unpack_from("<I", data, count_at)[0]
    volumes: list[dict[str, Any]] = []
    volume_at, volume_count = struct.unpack_from("<II", data, 0x6C)
    entry_size = 40 if version == 17 else 104 if version in (23, 26) else 96
    for index in range(min(volume_count, 16)):
        start = volume_at + index * entry_size
        if start + 20 > len(data):
            break
        path_at, path_chars, created, serial = struct.unpack_from("<IIQI", data, start)
        device = data[volume_at + path_at:volume_at + path_at + min(path_chars, 260) * 2]
        volumes.append({"device": clean_text(device.decode("utf-16-le", errors="replace"), 260),
                        "serial": f"{serial >> 16:04X}-{serial & 0xFFFF:04X}", "created": filetime_iso(created)})
    names_at, names_size = struct.unpack_from("<II", data, 0x64)
    names = data[names_at:names_at + min(names_size, 4 * 1024 * 1024)].decode("utf-16-le", errors="replace")
    fields = {"program": name, "path_hash": f"{path_hash:08X}", "run_count": run_count, "last_runs": runs,
              "format_version": version, "compressed": compressed, "volumes": volumes,
              "files_referenced": sum(1 for item in names.split("\0") if item)}
    # A compressed file has no stable offsets of its own, so it is cited as a whole.
    locator = "file" if compressed else f"bytes:0:{count_at + 4}"
    return [Record("prefetch", runs[0] if runs else None, fields, locator)]


# --------------------------------------------------------------------------
# Recycle Bin
# --------------------------------------------------------------------------


def parse_recycle_index(path: Path) -> list[Record]:
    """A ``$I`` file: the original path, size and deletion time of one deleted item."""
    data = path.read_bytes()[:4096]
    if len(data) < 28:
        raise ParseError("Recycle Bin index file is too small")
    version, size, deleted = struct.unpack_from("<QQQ", data, 0)
    if version == 1:
        original = utf16(data[24:24 + 520], 520)
    elif version == 2:
        chars = struct.unpack_from("<I", data, 24)[0]
        original = utf16(data[28:28 + min(chars, 1024) * 2], 1024)
    else:
        raise ParseError("Recycle Bin index file has an unknown version")
    fields = {"original_path": original, "size_bytes": size, "index_name": clean_text(path.name, 64),
              "user_sid": clean_text(path.parent.name, 80)}
    return [Record("recycle_bin", filetime_iso(deleted), fields, f"bytes:0:{len(data)}")]


# --------------------------------------------------------------------------
# setupapi.dev.log
# --------------------------------------------------------------------------

_SETUP_HEADER = re.compile(rb"^>>>\s+\[(?P<what>[^\]\r\n]{1,400})\]")
_SETUP_START = re.compile(rb"^>>>\s+Section start (\d{4})/(\d\d)/(\d\d) (\d\d):(\d\d):(\d\d)")
_XP_HEADER = re.compile(rb"^\[(\d{4})/(\d\d)/(\d\d) (\d\d):(\d\d):(\d\d) \d+\.\d+[^\]\r\n]{0,60}\]")
_DEVICE_ID = re.compile(r"(USBSTOR\\[^\s\]\"']{4,200}|USB\\VID_[0-9A-F]{4}&PID_[0-9A-F]{4}[^\s\]\"']{0,120}|"
                        r"WPDBUSENUMROOT\\[^\s\]\"']{4,300}|SCSI\\CDROM[^\s\]\"']{0,200}|IDE\\CDROM[^\s\]\"']{0,200})",
                        re.IGNORECASE)


def parse_setupapi(path: Path) -> list[Record]:
    """Device-install sections of ``setupapi.dev.log`` (and XP's ``setupapi.log``).

    The log's clock is the computer's local time with no zone, so records
    carry ``local_time`` and no UTC ``time``; the agent converts it when the
    registry gives the time zone. Every section start is also returned as a
    ``setup_section`` record so the caller can check the clock ran forwards.
    """
    with path.open("rb") as handle:
        data = handle.read(MAX_LOG_BYTES)
    if data[:2] == b"\xff\xfe":
        data = data[2:].decode("utf-16-le", errors="replace").encode("utf-8")
        wide = True
    else:
        wide = False
    records: list[Record] = []
    offset = 0
    pending: tuple[int, int, str] | None = None  # header offset, header length, text
    for line in data.split(b"\n"):
        length = len(line) + 1
        header = _SETUP_HEADER.match(line)
        start = _SETUP_START.match(line) if not header else None
        xp = _XP_HEADER.match(line) if not header and not start else None
        if header:
            pending = (offset, length, header["what"].decode("latin-1"))
        elif start and pending:
            head_offset, _, what = pending
            pending = None
            stamp = "{}-{}-{}T{}:{}:{}".format(*(part.decode() for part in start.groups()))
            # In a UTF-16 log the offsets are positions in the decoded text, so the record is cited file-level.
            locator = "file" if wide else f"bytes:{head_offset}:{min(offset + length - head_offset, 2048)}"
            device = _DEVICE_ID.search(what)
            records.append(Record("setup_section", None, {"local_time": stamp}, locator))
            if device and len(records) < MAX_RECORDS_PER_FILE:
                records.append(Record("device_install", None,
                                      {"local_time": stamp, "device_id": clean_text(device.group(1), 300),
                                       "section": clean_text(what, 300)}, locator))
        elif xp:
            stamp = "{}-{}-{}T{}:{}:{}".format(*(part.decode() for part in xp.groups()))
            locator = "file" if wide else f"bytes:{offset}:{min(length, 2048)}"
            records.append(Record("setup_section", None, {"local_time": stamp}, locator))
            pending = (offset, length, f"xp:{stamp}")
        elif pending and pending[2].startswith("xp:") and b"\\" in line:
            device = _DEVICE_ID.search(line.decode("latin-1"))
            if device and len(records) < MAX_RECORDS_PER_FILE:
                locator = "file" if wide else f"bytes:{offset}:{min(length, 2048)}"
                records.append(Record("device_install", None,
                                      {"local_time": pending[2][3:], "device_id": clean_text(device.group(1), 300),
                                       "section": "setupapi.log"}, locator))
                pending = None
        offset += length
        if len(records) >= MAX_RECORDS_PER_FILE * 2:
            break
    return records


# --------------------------------------------------------------------------
# Browser history (SQLite)
# --------------------------------------------------------------------------

SQLITE_TABLES = frozenset({"urls", "visits", "downloads", "downloads_url_chains", "keyword_search_terms",
                           "moz_places", "moz_historyvisits", "moz_annos", "moz_inputhistory", "sqlite_sequence",
                           "cloud_entry", "local_entry", "data"})
_SEARCH_PARAMS = ("q", "query", "p", "search_query", "text", "wd", "search", "k", "oq")
_SEARCH_HOSTS = re.compile(r"(^|\.)(google\.[a-z.]{2,6}|bing\.com|yahoo\.com|duckduckgo\.com|baidu\.com|yandex\.[a-z]{2,3}|"
                           r"ask\.com|aol\.com|youtube\.com|startpage\.com|ecosia\.org|naver\.com)$")


def _authorizer(action: int, *_: Any) -> int:
    allowed = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION}
    return sqlite3.SQLITE_OK if action in allowed else sqlite3.SQLITE_DENY


@contextmanager
def open_sqlite(path: Path) -> Iterator[sqlite3.Connection]:
    """Open a browser database for reading only.

    The copy in the run folder is copied once more to a temporary folder and
    opened there with ``mode=ro`` and ``immutable=1``, so SQLite cannot write
    a journal beside (or into) the copy whose hash the findings cite. Only
    SELECT statements are allowed, and a query is stopped after a fixed
    number of steps.
    """
    if path.stat().st_size > MAX_SQLITE_BYTES:
        raise ParseBudget("database is larger than the per-file limit")
    with path.open("rb") as handle:
        if handle.read(16) != b"SQLite format 3\0":
            raise ParseError("not an SQLite database")
    with tempfile.TemporaryDirectory(prefix="af-sqlite-") as folder:
        working = Path(folder) / "db"
        shutil.copyfile(path, working)
        connection = sqlite3.connect(f"{working.as_uri()}?mode=ro&immutable=1", uri=True, timeout=1)
        try:
            steps = [0]

            def progress() -> int:
                steps[0] += 1
                return 1 if steps[0] > MAX_SQLITE_STEPS // 10_000 else 0

            connection.set_progress_handler(progress, 10_000)
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            if hasattr(connection, "setlimit"):
                connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 4 * 1024 * 1024)
            connection.text_factory = lambda raw: raw.decode("utf-8", errors="replace")
            connection.set_authorizer(_authorizer)
            yield connection
        finally:
            connection.close()


def _tables(connection: sqlite3.Connection) -> set[str]:
    return {str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def _columns(connection: sqlite3.Connection, table: str) -> set[str]:
    cursor = connection.execute(f'SELECT * FROM "{table}" LIMIT 0')  # noqa: S608 - table names come from a fixed set
    return {item[0] for item in cursor.description}


def sqlite_row_digest(connection: sqlite3.Connection, table: str, rowid: int) -> str | None:
    """SHA-256 of one row in a fixed form, or None when the row is gone."""
    if table not in SQLITE_TABLES:
        return None
    row = connection.execute(f'SELECT * FROM "{table}" WHERE rowid = ?', (rowid,)).fetchone()  # noqa: S608
    if row is None:
        return None
    plain = [value.hex() if isinstance(value, bytes) else value for value in row]
    return sha256_bytes(json.dumps(plain, ensure_ascii=True, separators=(",", ":")).encode("utf-8"))


def search_terms_from_url(url: str) -> str:
    """The search words in a search-engine URL, or ''."""
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
    except ValueError:
        return ""
    if not _SEARCH_HOSTS.search(host):
        return ""
    try:
        query = parse_qs(parts.query, max_num_fields=64)
        query.update({k: v for k, v in parse_qs(parts.fragment, max_num_fields=64).items() if k not in query})
    except ValueError:
        return ""
    for name in _SEARCH_PARAMS:
        if query.get(name):
            return clean_text(query[name][0], 300)
    return ""


def url_host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()[:253]
    except ValueError:
        return ""


def _visit_record(browser: str, url: str, title: Any, when: str | None, locator: str, **extra: Any) -> Record:
    fields = {"browser": browser, "url": clean_text(url, 2048), "host": url_host(url),
              "title": clean_text(title or "", 300), **extra}
    return Record("browser_visit", when, fields, locator)


def parse_chromium_history(path: Path, browser: str = "chrome") -> list[Record]:
    """Visits, downloads and typed searches from a Chrome or Edge ``History`` database."""
    records: list[Record] = []
    with open_sqlite(path) as db:
        tables = _tables(db)
        if "urls" not in tables:
            raise ParseError("no urls table: not a Chromium History database")
        limit = MAX_RECORDS_PER_FILE
        if "visits" in tables:
            rows = db.execute(
                "SELECT visits.rowid, urls.url, urls.title, visits.visit_time, urls.visit_count, urls.typed_count "
                "FROM visits JOIN urls ON urls.id = visits.url ORDER BY visits.visit_time DESC LIMIT ?", (limit,))
            for rowid, url, title, when, visits, typed in rows:
                if not isinstance(url, str):
                    continue
                records.append(_visit_record(browser, url, title, webkit_iso(when), f"sqlite:visits:{rowid}",
                                             visit_count=visits if isinstance(visits, int) else 0,
                                             typed_count=typed if isinstance(typed, int) else 0))
                term = search_terms_from_url(url)
                if term:
                    records.append(Record("web_search", webkit_iso(when), {"browser": browser, "term": term,
                                          "host": url_host(url)}, f"sqlite:visits:{rowid}"))
        if "keyword_search_terms" in tables:
            rows = db.execute(
                "SELECT k.rowid, k.term, urls.url, urls.last_visit_time FROM keyword_search_terms k "
                "LEFT JOIN urls ON urls.id = k.url_id LIMIT ?", (limit,))
            for rowid, term, url, when in rows:
                if isinstance(term, str) and term.strip():
                    records.append(Record("web_search", webkit_iso(when),
                                          {"browser": browser, "term": clean_text(term, 300),
                                           "host": url_host(url) if isinstance(url, str) else ""},
                                          f"sqlite:keyword_search_terms:{rowid}"))
        if "downloads" in tables:
            columns = _columns(db, "downloads")
            target = "target_path" if "target_path" in columns else "full_path" if "full_path" in columns else "''"
            source = "tab_url" if "tab_url" in columns else "url" if "url" in columns else "''"
            total = "total_bytes" if "total_bytes" in columns else "0"
            rows = db.execute(f"SELECT rowid, {target}, {source}, start_time, {total} FROM downloads "  # noqa: S608
                              "ORDER BY start_time DESC LIMIT ?", (limit,))
            chains: dict[int, str] = {}
            if "downloads_url_chains" in tables:
                for download_id, url in db.execute("SELECT id, url FROM downloads_url_chains ORDER BY chain_index "
                                                   "LIMIT ?", (limit,)):
                    if isinstance(url, str):
                        chains[download_id] = url
            for rowid, target_path, url, when, size in rows:
                url = url if isinstance(url, str) and url else chains.get(rowid, "")
                # Old Chrome stored download times as Unix seconds; newer ones as microseconds since 1601.
                stamp = unix_iso(when) if isinstance(when, int) and when < 10_000_000_000 else webkit_iso(when)
                records.append(Record("browser_download", stamp,
                                      {"browser": browser, "target_path": clean_text(target_path or "", 1024),
                                       "url": clean_text(url, 2048), "host": url_host(url),
                                       "size_bytes": size if isinstance(size, int) else 0},
                                      f"sqlite:downloads:{rowid}"))
        if "sqlite_sequence" in tables:
            for rowid, name, seq in db.execute("SELECT rowid, name, seq FROM sqlite_sequence LIMIT 64"):
                if name in ("urls", "visits") and isinstance(seq, int):
                    kept = db.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0]  # noqa: S608
                    records.append(Record("browser_table_state", None,
                                          {"browser": browser, "table": name, "rows_ever": seq, "rows_now": kept},
                                          f"sqlite:sqlite_sequence:{rowid}"))
    return records


def parse_firefox_places(path: Path) -> list[Record]:
    """Visits and searches from a Firefox ``places.sqlite`` database."""
    records: list[Record] = []
    with open_sqlite(path) as db:
        tables = _tables(db)
        if "moz_places" not in tables:
            raise ParseError("no moz_places table: not a Firefox places database")
        if "moz_historyvisits" in tables:
            rows = db.execute(
                "SELECT v.rowid, p.url, p.title, v.visit_date, p.visit_count FROM moz_historyvisits v "
                "JOIN moz_places p ON p.id = v.place_id ORDER BY v.visit_date DESC LIMIT ?", (MAX_RECORDS_PER_FILE,))
            for rowid, url, title, when, visits in rows:
                if not isinstance(url, str):
                    continue
                stamp = unix_micro_iso(when)
                records.append(_visit_record("firefox", url, title, stamp, f"sqlite:moz_historyvisits:{rowid}",
                                             visit_count=visits if isinstance(visits, int) else 0))
                term = search_terms_from_url(url)
                if term:
                    records.append(Record("web_search", stamp, {"browser": "firefox", "term": term,
                                          "host": url_host(url)}, f"sqlite:moz_historyvisits:{rowid}"))
                if url.startswith("file:///"):
                    records.append(Record("browser_file_open", stamp,
                                          {"browser": "firefox", "target_path": clean_text(url[8:], 1024)},
                                          f"sqlite:moz_historyvisits:{rowid}"))
        if "moz_annos" in tables:
            rows = db.execute(
                "SELECT a.rowid, a.content, p.url, a.dateAdded FROM moz_annos a JOIN moz_places p ON p.id = a.place_id "
                "WHERE a.content LIKE 'file:///%' LIMIT ?", (MAX_RECORDS_PER_FILE,))
            for rowid, content, url, when in rows:
                if isinstance(content, str) and isinstance(url, str):
                    records.append(Record("browser_download", unix_micro_iso(when),
                                          {"browser": "firefox", "target_path": clean_text(content[8:], 1024),
                                           "url": clean_text(url, 2048), "host": url_host(url), "size_bytes": 0},
                                          f"sqlite:moz_annos:{rowid}"))
    return records


# --------------------------------------------------------------------------
# Google Drive sync client databases
# --------------------------------------------------------------------------


def parse_gdrive_snapshot(path: Path) -> list[Record]:
    """Files the Google Drive sync client knew about: ``snapshot.db`` lists the cloud side and the local side."""
    records: list[Record] = []
    with open_sqlite(path) as db:
        tables = _tables(db)
        if "cloud_entry" not in tables and "local_entry" not in tables:
            raise ParseError("no cloud_entry or local_entry table: not a Google Drive snapshot database")
        if "cloud_entry" in tables:
            columns = _columns(db, "cloud_entry")
            wanted = [name if name in columns else "NULL" for name in
                      ("filename", "modified", "created", "removed", "size", "shared", "doc_type")]
            rows = db.execute(f"SELECT rowid, {', '.join(wanted)} FROM cloud_entry LIMIT ?",  # noqa: S608
                              (MAX_RECORDS_PER_FILE,))
            for rowid, name, modified, created, removed, size, shared, doc_type in rows:
                if not isinstance(name, str) or name == "root":
                    continue
                records.append(Record("cloud_file", unix_iso(modified) or unix_iso(created),
                                      {"client": "Google Drive", "side": "cloud", "name": clean_text(name, 400),
                                       "created": unix_iso(created), "size_bytes": size if isinstance(size, int) else 0,
                                       "removed": bool(removed), "shared": bool(shared),
                                       "is_folder": doc_type == 0}, f"sqlite:cloud_entry:{rowid}"))
        if "local_entry" in tables:
            rows = db.execute("SELECT rowid, filename, modified, size FROM local_entry LIMIT ?",
                              (MAX_RECORDS_PER_FILE,))
            for rowid, name, modified, size in rows:
                if isinstance(name, str) and name:
                    records.append(Record("cloud_file", unix_iso(modified),
                                          {"client": "Google Drive", "side": "local", "name": clean_text(name, 400),
                                           "size_bytes": size if isinstance(size, int) else 0},
                                          f"sqlite:local_entry:{rowid}"))
    return records


def parse_gdrive_config(path: Path) -> list[Record]:
    """The account and sync folder from the Google Drive client's ``sync_config.db``."""
    records: list[Record] = []
    with open_sqlite(path) as db:
        if "data" not in _tables(db):
            raise ParseError("no data table: not a Google Drive sync_config database")
        for rowid, key, value in db.execute("SELECT rowid, entry_key, data_value FROM data LIMIT 500"):
            if key in ("user_email", "local_sync_root_path", "highest_app_version") and value is not None:
                text = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value)
                records.append(Record("cloud_account", None, {"client": "Google Drive", "setting": key,
                                                              "value": clean_text(text.lstrip("\\?"), 400)},
                                      f"sqlite:data:{rowid}"))
    return records


# --------------------------------------------------------------------------
# Internet Explorer: WebCacheV01.dat (ESE) and index.dat
# --------------------------------------------------------------------------


def parse_webcache(path: Path, deadline: Deadline | None = None, problems: list[str] | None = None) -> list[Record]:
    """Best-effort history from IE 10/11 and old Edge. Records are cited file-level.

    The database is usually copied while "dirty" (its log files not yet
    applied), so the newest visits can be missing. When the time limit is
    reached the records read so far are returned and ``problems`` says so.
    """
    records: list[Record] = []
    try:
        _read_webcache(path, deadline or Deadline(), records)
    except ParseBudget as exc:
        if problems is None or not records:
            raise
        problems.append(f"stopped early ({exc}); {len(records)} records were read")
    return records


def _read_webcache(path: Path, deadline: Deadline, records: list[Record]) -> None:
    from dissect.database.ese import ESE

    with path.open("rb") as handle:
        db = ESE(handle)
        wanted: dict[int, str] = {}
        for row in db.table("Containers").records():
            deadline.check()
            name = clean_text(str(row.get("Name") or "").rstrip("\0"), 64)
            if name.startswith(("History", "MSHist", "iedownload", "Content")):
                wanted[int(row.get("ContainerId"))] = name
            if len(wanted) > 256:
                break
        for container_id, name in wanted.items():
            try:
                table = db.table(f"Container_{container_id}")
            except Exception:  # noqa: BLE001 - a missing container table is normal
                continue
            is_history = name.startswith(("History", "MSHist"))
            for row in table.records():
                deadline.check()
                if len(records) >= MAX_RECORDS_PER_FILE:
                    return
                url = row.get("Url")
                if not isinstance(url, str) or not url:
                    continue
                url = url.rstrip("\0")
                stamp = filetime_iso(int(row.get("AccessedTime") or 0))
                # History URLs look like "Visited: user@http://site/" or "user@file:///C:/x".
                clean = url.split("@", 1)[1] if "@" in url[:80] and url[:8].lower() != "https://" else url
                if not is_history:
                    if name.startswith("iedownload"):
                        records.append(Record("browser_download", stamp,
                                              {"browser": "ie", "url": clean_text(clean, 2048),
                                               "host": url_host(clean), "target_path": "", "size_bytes": 0}, "file"))
                    continue
                if clean.lower().startswith("file:///"):
                    records.append(Record("browser_file_open", stamp,
                                          {"browser": "ie", "target_path": clean_text(clean[8:].replace("/", "\\"),
                                                                                     1024)}, "file"))
                    continue
                records.append(_visit_record("ie", clean, "", stamp, "file", container=name))
                term = search_terms_from_url(clean)
                if term:
                    records.append(Record("web_search", stamp, {"browser": "ie", "term": term,
                                                                "host": url_host(clean)}, "file"))


def parse_index_dat(path: Path) -> list[Record]:
    """URL records from an Internet Explorer ``index.dat`` (IE 5 to 9)."""
    with path.open("rb") as handle:
        data = handle.read(256 * 1024 * 1024)
    if not data.startswith(b"Client UrlCache MMF Ver"):
        raise ParseError("not an index.dat file")
    records: list[Record] = []
    position = data.find(b"URL ", 0x4000)
    while position >= 0 and len(records) < MAX_RECORDS_PER_FILE:
        if position % 0x80 == 0 and position + 0x68 <= len(data):
            blocks = struct.unpack_from("<I", data, position + 4)[0]
            length = min(max(blocks, 1) * 0x80, 0x2000)
            modified, accessed = struct.unpack_from("<QQ", data, position + 8)
            url_at = struct.unpack_from("<I", data, position + 0x34)[0]
            raw = _cstring(data[position:position + length], url_at, 2048).decode("latin-1", errors="replace")
            clean = raw.split("@", 1)[1] if "@" in raw[:80] else raw
            stamp = filetime_iso(accessed) or filetime_iso(modified)
            locator = f"bytes:{position}:{length}"
            if clean.lower().startswith("file:///"):
                records.append(Record("browser_file_open", stamp,
                                      {"browser": "ie", "target_path": clean_text(clean[8:].replace("/", "\\"), 1024)},
                                      locator))
            elif clean.lower().startswith(("http://", "https://", "ftp://")):
                records.append(_visit_record("ie", clean, "", stamp, locator))
                term = search_terms_from_url(clean)
                if term:
                    records.append(Record("web_search", stamp, {"browser": "ie", "term": term,
                                                                "host": url_host(clean)}, locator))
        position = data.find(b"URL ", position + 4)
    return records


# --------------------------------------------------------------------------
# Re-reading a located record
# --------------------------------------------------------------------------


class Rereader:
    """Re-read cited records and hash them, keeping whole-file hashes and open databases for one merge."""

    def __init__(self) -> None:
        self._file_hashes: dict[Path, str] = {}
        self._databases: dict[Path, tuple[Any, sqlite3.Connection]] = {}
        self._hives: dict[Path, Hive] = {}

    def close(self) -> None:
        for manager, _ in self._databases.values():
            try:
                manager.__exit__(None, None, None)
            except Exception:  # noqa: BLE001 - closing a temporary copy must not fail a run
                pass
        for hive in self._hives.values():
            hive.close()
        self._databases.clear()
        self._hives.clear()

    def __enter__(self) -> "Rereader":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def file_sha256(self, path: Path) -> str | None:
        if path not in self._file_hashes:
            digest = hashlib.sha256()
            try:
                with path.open("rb") as handle:
                    while chunk := handle.read(1024 * 1024):
                        digest.update(chunk)
            except OSError:
                return None
            self._file_hashes[path] = digest.hexdigest()
        return self._file_hashes[path]

    def digest(self, path: Path, locator: str) -> str | None:
        """SHA-256 of the record a locator names, or None when it cannot be read back."""
        try:
            return self._digest(path, locator)
        except (OSError, ParseError, struct.error, ValueError, sqlite3.Error, IndexError, KeyError, OverflowError,
                MemoryError):
            return None

    def _digest(self, path: Path, locator: str) -> str | None:
        kind, _, rest = locator.partition(":")
        if kind == "file":
            return self.file_sha256(path)
        if kind == "bytes":
            offset, _, length = rest.partition(":")
            data = read_span(path, int(offset), int(length))
            return sha256_bytes(data) if data is not None else None
        if kind in ("regk", "regv"):
            if path not in self._hives:
                self._hives[path] = Hive(path)
            hive = self._hives[path]
            hive.cells_left, hive.deadline = MAX_HIVE_CELLS, Deadline()
            data = hive.locator_bytes(locator)
            return sha256_bytes(data) if data is not None else None
        if kind == "sqlite":
            table, _, rowid = rest.partition(":")
            if path not in self._databases:
                manager = open_sqlite(path)
                self._databases[path] = (manager, manager.__enter__())
            return sqlite_row_digest(self._databases[path][1], table, int(rowid))
        return None


def locator_position(locator: str) -> tuple[int | None, int | None]:
    """(row, offset) for a Citation: a row id for database rows, a byte offset for everything else."""
    kind, _, rest = locator.partition(":")
    if kind == "sqlite":
        return max(1, int(rest.rpartition(":")[2])), None
    if kind in ("bytes", "regk", "regv"):
        return None, int(rest.partition(":")[0])
    return None, 0
