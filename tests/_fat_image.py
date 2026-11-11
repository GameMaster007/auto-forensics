"""Build a tiny MBR-partitioned FAT12 disk image in pure Python, for tests.

Only what the disk-image tests need: nested folders, long file names,
and file contents. Not a general FAT writer.
"""

from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import Union

Tree = dict[str, Union["Tree", bytes]]

SECTOR = 512
SECTORS_PER_CLUSTER = 4
CLUSTER = SECTOR * SECTORS_PER_CLUSTER
ROOT_ENTRIES = 224
PARTITION_LBA = 63


def _short_names(names: list[str]) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for index, name in enumerate(names, start=1):
        stem, _, ext = name.rpartition(".") if "." in name.lstrip(".") else (name, "", "")
        base = re.sub(r"[^A-Z0-9]", "", stem.upper())[:4] or "F"
        tail = f"~{index}"
        out[name] = (base + tail).ljust(8)[:8].encode() + re.sub(r"[^A-Z0-9]", "", ext.upper())[:3].ljust(3).encode()
    return out


def _lfn_checksum(short: bytes) -> int:
    total = 0
    for byte in short:
        total = (((total & 1) << 7) + (total >> 1) + byte) & 0xFF
    return total


def _lfn_entries(name: str, short: bytes) -> list[bytes]:
    units = list(name.encode("utf-16-le"))
    chars = [units[i] | (units[i + 1] << 8) for i in range(0, len(units), 2)]
    pieces = []
    for start in range(0, len(chars), 13):
        chunk = chars[start:start + 13]
        if len(chunk) < 13:
            chunk = chunk + [0x0000] + [0xFFFF] * (12 - len(chunk))
        pieces.append(chunk)
    checksum = _lfn_checksum(short)
    entries = []
    for seq, chunk in enumerate(pieces, start=1):
        order = seq | (0x40 if seq == len(pieces) else 0)
        raw = struct.pack("<B5HBBB6HH2H", order, *chunk[:5], 0x0F, 0, checksum, *chunk[5:11], 0, *chunk[11:13])
        entries.append(raw)
    return list(reversed(entries))


def _entry(short: bytes, attr: int, cluster: int, size: int) -> bytes:
    # 2024-03-01 12:00:00 for every timestamp.
    time, date = (12 << 11), ((2024 - 1980) << 9) | (3 << 5) | 1
    return struct.pack("<11sBBBHHHHHHHI", short, attr, 0, 0, time, date, date, 0, time, date, cluster, size)


class _Builder:
    def __init__(self, data_clusters: int) -> None:
        self.fat = [0xFF8, 0xFFF] + [0] * data_clusters
        self.clusters: dict[int, bytes] = {}
        self.next = 2

    def alloc(self, data: bytes) -> int:
        count = max(1, -(-len(data) // CLUSTER))
        first = self.next
        for offset in range(count):
            number = first + offset
            self.fat[number] = number + 1 if offset < count - 1 else 0xFFF
            self.clusters[number] = data[offset * CLUSTER:(offset + 1) * CLUSTER].ljust(CLUSTER, b"\0")
        self.next += count
        return first

    def directory(self, tree: Tree, self_cluster: int, parent_cluster: int, root: bool) -> bytes:
        entries: list[bytes] = []
        if not root:
            entries.append(_entry(b".          ", 0x10, self_cluster, 0))
            entries.append(_entry(b"..         ", 0x10, parent_cluster, 0))
        shorts = _short_names(list(tree))
        for name, value in tree.items():
            short = shorts[name]
            entries.extend(_lfn_entries(name, short))
            if isinstance(value, bytes):
                cluster = self.alloc(value) if value else 0
                entries.append(_entry(short, 0x20, cluster, len(value)))
            else:
                # Reserve the child's clusters first so "." is known, then fill them.
                size = (2 + sum(len(_lfn_entries(child, b"X" * 11)) + 1 for child in value)) * 32
                cluster = self.alloc(b"\0" * size)
                body = self.directory(value, cluster, 0 if root else self_cluster, root=False)
                count = max(1, -(-len(body) // CLUSTER))
                for offset in range(count):
                    self.clusters[cluster + offset] = body[offset * CLUSTER:(offset + 1) * CLUSTER].ljust(CLUSTER, b"\0")
                entries.append(_entry(short, 0x10, cluster, 0))
        return b"".join(entries)


def build_fat_image(path: Path, tree: Tree, *, size_mb: int = 6) -> Path:
    """Write ``tree`` (name -> bytes or sub-tree) to a partitioned FAT12 image at ``path``."""
    total = size_mb * 1024 * 1024 // SECTOR - PARTITION_LBA
    root_sectors = ROOT_ENTRIES * 32 // SECTOR
    fat_sectors = 12  # enough for ~3,000 clusters
    data_start = 1 + 2 * fat_sectors + root_sectors
    data_clusters = (total - data_start) // SECTORS_PER_CLUSTER
    if data_clusters >= 4085:
        raise ValueError("image too large for FAT12")
    builder = _Builder(data_clusters)
    root = builder.directory(tree, 0, 0, root=True)
    if len(root) > ROOT_ENTRIES * 32:
        raise ValueError("too many root entries")
    if builder.next - 2 > data_clusters:
        raise ValueError("image too small for the tree")

    boot = bytearray(SECTOR)
    boot[0:3] = b"\xeb\x3c\x90"
    boot[3:11] = b"MSDOS5.0"
    struct.pack_into("<HBHBHHBHHHII", boot, 11, SECTOR, SECTORS_PER_CLUSTER, 1, 2, ROOT_ENTRIES,
                     total if total < 0x10000 else 0, 0xF8, fat_sectors, 63, 255, PARTITION_LBA,
                     0 if total < 0x10000 else total)
    struct.pack_into("<BBBI11s8s", boot, 36, 0x80, 0, 0x29, 0x12345678, b"TESTVOL    ", b"FAT12   ")
    boot[510:512] = b"\x55\xaa"

    fat = bytearray(fat_sectors * SECTOR)
    for index in range(0, len(builder.fat), 2):
        low = builder.fat[index]
        high = builder.fat[index + 1] if index + 1 < len(builder.fat) else 0
        packed = low | (high << 12)
        fat[index * 3 // 2:index * 3 // 2 + 3] = packed.to_bytes(3, "little")
    fat[0] = 0xF8

    mbr = bytearray(SECTOR)
    struct.pack_into("<I", mbr, 440, 0xDEADBEEF)
    struct.pack_into("<B3sB3sII", mbr, 446, 0x00, b"\0\0\0", 0x01, b"\0\0\0", PARTITION_LBA, total)
    mbr[510:512] = b"\x55\xaa"

    with path.open("wb") as out:
        out.write(mbr)
        out.write(b"\0" * SECTOR * (PARTITION_LBA - 1))
        out.write(boot)
        out.write(fat)
        out.write(fat)
        out.write(root.ljust(root_sectors * SECTOR, b"\0"))
        for number in range(2, 2 + data_clusters):
            out.write(builder.clusters.get(number, b"\0" * CLUSTER))
    return path
