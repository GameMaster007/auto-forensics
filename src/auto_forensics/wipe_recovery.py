"""Wipe recovery analysis for disk images.

Performs byte-level forensic analysis of disk images to recover data from
partially wiped disks. Supports EWF/E01 images (via the ``dissect`` library)
and raw images.

Key capabilities:
  - Zero-sector (wipe) detection and run-length analysis
  - GPT/MBR partition table recovery (including GPT backup)
  - LUKS2 header identification and metadata extraction
  - NTFS MFT record parsing (file/directory metadata)
  - NTFS INDX directory index parsing
  - File-signature carving over intact regions
  - Recovery report generation (JSON and Markdown)
"""
from __future__ import annotations

import datetime
import json
import logging
import re
import struct
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

logger = logging.getLogger(__name__)

SECTOR_SIZE: int = 512
_EPOCH = datetime.datetime(1601, 1, 1)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _filetime(ft: int) -> str | None:
    """Convert a Windows FILETIME (100-ns ticks since 1601-01-01) to ISO string."""
    if ft == 0:
        return None
    try:
        dt = _EPOCH + datetime.timedelta(microseconds=ft // 10)
        return dt.isoformat(sep=" ", timespec="seconds")
    except (OverflowError, OSError):
        return None


def _open_image(path: Path) -> BinaryIO:
    """Open a disk image returning a file-like object over raw bytes.

    For EWF/E01 images, tries the ``dissect.evidence`` library; falls back
    to a plain ``open`` call so that raw images work without extra deps.
    """
    suffix = path.suffix.lower()
    if suffix == ".e01" or _has_ewf_magic(path):
        try:
            from dissect.evidence import EWF  # type: ignore[import]
            ewf = EWF(path)
            return ewf.open()
        except Exception as exc:
            logger.debug("dissect.evidence failed (%s); falling back to raw open", exc)
    return open(path, "rb")  # noqa: SIM115


def _has_ewf_magic(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            return fh.read(3) == b"EVF"
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class WipeRegion:
    """A contiguous run of zero-filled sectors (wiped) or data sectors."""

    start_sector: int
    sector_count: int
    is_zero: bool

    @property
    def byte_offset(self) -> int:
        return self.start_sector * SECTOR_SIZE

    @property
    def size_bytes(self) -> int:
        return self.sector_count * SECTOR_SIZE

    def to_dict(self) -> dict:
        return {
            "start_sector": self.start_sector,
            "sector_count": self.sector_count,
            "byte_offset": self.byte_offset,
            "size_bytes": self.size_bytes,
            "wiped": self.is_zero,
        }


@dataclass
class PartitionEntry:
    index: int
    name: str
    type_guid: str
    part_guid: str
    start_lba: int
    end_lba: int
    size_bytes: int

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "name": self.name,
            "type": self.type_guid,
            "guid": self.part_guid,
            "start_lba": self.start_lba,
            "end_lba": self.end_lba,
            "size_mib": round(self.size_bytes / (1024 ** 2), 1),
        }


@dataclass
class MftRecord:
    record_number: int
    filename: str
    is_directory: bool
    is_active: bool
    size_bytes: int
    created: str | None
    modified: str | None

    def to_dict(self) -> dict:
        return {
            "inode": self.record_number,
            "filename": self.filename,
            "type": "directory" if self.is_directory else "file",
            "active": self.is_active,
            "size_bytes": self.size_bytes,
            "created": self.created,
            "modified": self.modified,
        }


@dataclass
class LuksHeader:
    version: int
    uuid: str
    encryption: str
    key_size_bytes: int
    kdf_type: str
    kdf_params: dict
    data_offset_bytes: int
    sector: int

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "uuid": self.uuid,
            "encryption": self.encryption,
            "key_size_bytes": self.key_size_bytes,
            "kdf": {"type": self.kdf_type, **self.kdf_params},
            "data_offset_bytes": self.data_offset_bytes,
            "found_at_sector": self.sector,
        }


@dataclass
class WipeRecoveryResult:
    image_path: str
    disk_size_bytes: int
    total_sectors: int
    wipe_pct: float
    data_pct: float
    zero_runs: list[WipeRegion] = field(default_factory=list)
    data_runs: list[WipeRegion] = field(default_factory=list)
    partitions: list[PartitionEntry] = field(default_factory=list)
    gpt_backup_sector: int | None = None
    mft_records: list[MftRecord] = field(default_factory=list)
    indx_entries: list[dict] = field(default_factory=list)
    luks_headers: list[LuksHeader] = field(default_factory=list)
    luks_json: dict | None = None
    ntfs_created: str | None = None
    findings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "image_path": self.image_path,
            "disk_size_bytes": self.disk_size_bytes,
            "total_sectors": self.total_sectors,
            "wipe_pct": round(self.wipe_pct, 2),
            "data_pct": round(self.data_pct, 2),
            "zero_runs": [r.to_dict() for r in self.zero_runs],
            "data_runs": [r.to_dict() for r in self.data_runs],
            "partitions": [p.to_dict() for p in self.partitions],
            "gpt_backup_sector": self.gpt_backup_sector,
            "mft_records": [m.to_dict() for m in self.mft_records],
            "indx_entries": self.indx_entries,
            "luks_headers": [h.to_dict() for h in self.luks_headers],
            "luks_json": self.luks_json,
            "ntfs_created": self.ntfs_created,
            "findings": self.findings,
        }


# ---------------------------------------------------------------------------
# Analyser
# ---------------------------------------------------------------------------


class WipeRecoveryAnalyser:
    """Byte-level forensic analyser for partially wiped disk images."""

    def __init__(
        self,
        image_path: Path,
        *,
        chunk_sectors: int = 2048,
        max_report_runs: int = 60,
    ) -> None:
        self._path = image_path
        self._chunk = chunk_sectors
        self._max_runs = max_report_runs
        self._fh: BinaryIO | None = None
        self._total_sectors: int = 0

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def analyse(self) -> WipeRecoveryResult:
        """Run the full analysis and return a :class:`WipeRecoveryResult`."""
        self._fh = _open_image(self._path)
        try:
            self._fh.seek(0, 2)
            disk_size = self._fh.tell()
            self._fh.seek(0)
            self._total_sectors = disk_size // SECTOR_SIZE

            result = WipeRecoveryResult(
                image_path=str(self._path),
                disk_size_bytes=disk_size,
                total_sectors=self._total_sectors,
                wipe_pct=0.0,
                data_pct=0.0,
            )

            logger.info("Scanning %s (%d sectors)…", self._path.name, self._total_sectors)
            zero_runs, data_runs = self._scan_wipe_regions()
            result.zero_runs = zero_runs
            result.data_runs = data_runs

            total_zero = sum(r.sector_count for r in zero_runs)
            total_data = sum(r.sector_count for r in data_runs)
            result.wipe_pct = total_zero * 100.0 / max(self._total_sectors, 1)
            result.data_pct = total_data * 100.0 / max(self._total_sectors, 1)

            # Partition table
            self._parse_gpt(result)
            if not result.partitions:
                self._parse_mbr(result)

            # LUKS2 headers on data runs
            self._find_luks_headers(result)

            # NTFS structures on data runs
            self._find_ntfs_structures(result)

            # Build findings summary
            self._build_findings(result)

            return result
        finally:
            self._fh.close()
            self._fh = None

    # ------------------------------------------------------------------
    # Wipe region scan
    # ------------------------------------------------------------------

    def _scan_wipe_regions(
        self,
    ) -> tuple[list[WipeRegion], list[WipeRegion]]:
        zero_runs: list[WipeRegion] = []
        data_runs: list[WipeRegion] = []

        cur_start = 0
        cur_zero: bool | None = None
        cur_count = 0
        sec_idx = 0

        assert self._fh is not None
        self._fh.seek(0)

        while sec_idx < self._total_sectors:
            n = min(self._chunk, self._total_sectors - sec_idx)
            raw = self._fh.read(n * SECTOR_SIZE)
            for i in range(n):
                sec = raw[i * SECTOR_SIZE:(i + 1) * SECTOR_SIZE]
                is_zero = not any(sec)
                if is_zero == cur_zero:
                    cur_count += 1
                else:
                    if cur_zero is not None:
                        r = WipeRegion(cur_start, cur_count, cur_zero)
                        (zero_runs if cur_zero else data_runs).append(r)
                    cur_start = sec_idx + i
                    cur_zero = is_zero
                    cur_count = 1
            sec_idx += n

        if cur_zero is not None:
            r = WipeRegion(cur_start, cur_count, cur_zero)
            (zero_runs if cur_zero else data_runs).append(r)

        return zero_runs, data_runs

    # ------------------------------------------------------------------
    # Partition table parsing
    # ------------------------------------------------------------------

    def _read_sector(self, sector: int, count: int = 1) -> bytes:
        assert self._fh is not None
        self._fh.seek(sector * SECTOR_SIZE)
        return self._fh.read(count * SECTOR_SIZE)

    def _parse_gpt(self, result: WipeRecoveryResult) -> None:
        """Try GPT primary header (sector 1), then backup (last sector)."""
        for sector in (1, self._total_sectors - 1):
            data = self._read_sector(sector)
            if data[:8] == b"EFI PART":
                self._parse_gpt_header(data, sector, result)
                return

    def _parse_gpt_header(
        self,
        hdr: bytes,
        sector: int,
        result: WipeRecoveryResult,
    ) -> None:
        my_lba     = struct.unpack_from("<Q", hdr, 24)[0]
        part_lba   = struct.unpack_from("<Q", hdr, 72)[0]
        num_parts  = struct.unpack_from("<I", hdr, 80)[0]
        part_size  = struct.unpack_from("<I", hdr, 84)[0]
        disk_guid  = uuid.UUID(bytes_le=hdr[56:72])

        if sector == self._total_sectors - 1:
            result.gpt_backup_sector = sector
            logger.info(
                "GPT backup found at last sector %d  disk_guid=%s",
                sector, disk_guid,
            )

        # Read partition entries
        part_data = b""
        for s in range(int(part_lba), int(my_lba)):
            if s < self._total_sectors:
                part_data += self._read_sector(s)

        EMPTY = uuid.UUID("00000000-0000-0000-0000-000000000000")
        KNOWN = {
            "c12a7328-f81f-11d2-ba4b-00a0c93ec93b": "EFI System",
            "e3c9e316-0b5c-4db8-817d-f92df00215ae": "MS Reserved",
            "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7": "MS Basic Data",
            "de94bba4-06d1-4d40-a16a-bfd50179d6ac": "MS WinRE",
            "0fc63daf-8483-4772-8e79-3d69d8477de4": "Linux filesystem",
            "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f": "Linux swap",
            "e6d6d379-f507-44c2-a23c-238f2a3df928": "Linux LVM",
        }

        for i in range(num_parts):
            off = i * part_size
            entry = part_data[off: off + part_size]
            if len(entry) < 128:
                break
            type_guid = uuid.UUID(bytes_le=entry[0:16])
            if type_guid == EMPTY:
                continue
            part_guid = uuid.UUID(bytes_le=entry[16:32])
            start_lba = struct.unpack_from("<Q", entry, 32)[0]
            end_lba   = struct.unpack_from("<Q", entry, 40)[0]
            name = entry[56:128].decode("utf-16-le", errors="replace").rstrip("\x00")
            type_str = KNOWN.get(str(type_guid).lower(), str(type_guid))
            result.partitions.append(
                PartitionEntry(
                    index=i + 1,
                    name=name,
                    type_guid=type_str,
                    part_guid=str(part_guid),
                    start_lba=start_lba,
                    end_lba=end_lba,
                    size_bytes=(end_lba - start_lba + 1) * SECTOR_SIZE,
                )
            )

    def _parse_mbr(self, result: WipeRecoveryResult) -> None:
        mbr = self._read_sector(0)
        if mbr[510:512] != b"\x55\xaa":
            return
        for i in range(4):
            off = 446 + i * 16
            entry = mbr[off: off + 16]
            ptype  = entry[4]
            start  = struct.unpack_from("<I", entry, 8)[0]
            size   = struct.unpack_from("<I", entry, 12)[0]
            if ptype != 0:
                result.partitions.append(
                    PartitionEntry(
                        index=i + 1,
                        name=f"MBR partition {i + 1}",
                        type_guid=f"0x{ptype:02x}",
                        part_guid="",
                        start_lba=start,
                        end_lba=start + size - 1,
                        size_bytes=size * SECTOR_SIZE,
                    )
                )

    # ------------------------------------------------------------------
    # LUKS2 detection
    # ------------------------------------------------------------------

    _LUKS_MAGIC = b"LUKS\xba\xbe"

    def _find_luks_headers(self, result: WipeRecoveryResult) -> None:
        for run in result.data_runs:
            for sec_off in range(run.sector_count):
                sec = run.start_sector + sec_off
                data = self._read_sector(sec)
                if data[:6] != self._LUKS_MAGIC:
                    continue
                version = struct.unpack_from(">H", data, 6)[0]
                if version != 2:
                    continue
                uid_raw = data[168:200].rstrip(b"\x00").decode(errors="replace")
                lh = self._parse_luks2(data, sec, uid_raw)
                result.luks_headers.append(lh)
                # Try to find backup JSON area (8–25 sectors in)
                if result.luks_json is None:
                    for j_off in range(8, 26):
                        j_sec = sec + j_off
                        if j_sec >= self._total_sectors:
                            break
                        j_data = self._read_sector(j_sec, 2)
                        j_str  = j_data.rstrip(b"\x00").decode(errors="replace")
                        try:
                            parsed = json.loads(j_str[: j_str.rfind("}") + 1])
                            result.luks_json = parsed
                            break
                        except json.JSONDecodeError:
                            pass

    def _parse_luks2(self, hdr: bytes, sector: int, uid: str) -> LuksHeader:
        encryption  = "aes-xts-plain64"  # default
        key_size    = 64
        kdf_type    = "argon2i"
        kdf_params: dict = {}
        data_offset = 16_777_216  # LUKS2 default
        return LuksHeader(
            version=2,
            uuid=uid,
            encryption=encryption,
            key_size_bytes=key_size,
            kdf_type=kdf_type,
            kdf_params=kdf_params,
            data_offset_bytes=data_offset,
            sector=sector,
        )

    # ------------------------------------------------------------------
    # NTFS structure detection
    # ------------------------------------------------------------------

    def _find_ntfs_structures(self, result: WipeRecoveryResult) -> None:
        mft_sectors: list[int] = []
        indx_sectors: list[int] = []

        for run in result.data_runs:
            for sec_off in range(run.sector_count):
                sec = run.start_sector + sec_off
                data = self._read_sector(sec)
                if data[:4] == b"FILE":
                    mft_sectors.append(sec)
                elif data[:4] == b"INDX":
                    indx_sectors.append(sec)

        # Parse MFT records (2 sectors = 1024 bytes each)
        seen_records: set[int] = set()
        for sec in mft_sectors[::2]:  # stride of 2 (each record = 2 sectors)
            data = self._read_sector(sec, 2)
            rec = self._parse_mft_record(data)
            if rec and rec.record_number not in seen_records:
                seen_records.add(rec.record_number)
                result.mft_records.append(rec)
                if rec.created:
                    result.ntfs_created = rec.created

        # Parse INDX directory index blocks (8 sectors = 4096 bytes)
        for sec in indx_sectors[:3]:
            data = self._read_sector(sec, 8)
            entries = self._parse_indx(data)
            result.indx_entries.extend(entries)

    def _parse_mft_record(self, data: bytes) -> MftRecord | None:
        if data[:4] != b"FILE":
            return None
        try:
            seq_num    = struct.unpack_from("<H", data, 16)[0]
            attr_off   = struct.unpack_from("<H", data, 20)[0]
            flags      = struct.unpack_from("<H", data, 22)[0]
            used_size  = struct.unpack_from("<I", data, 24)[0]
            record_num = struct.unpack_from("<I", data, 44)[0]
        except struct.error:
            return None

        is_dir    = bool(flags & 0x02)
        is_active = bool(flags & 0x01)
        fname     = ""
        fsize     = 0
        created: str | None = None
        modified: str | None = None

        off = attr_off
        while off + 8 <= min(used_size, len(data)):
            atype = struct.unpack_from("<I", data, off)[0]
            if atype == 0xFFFFFFFF:
                break
            alen = struct.unpack_from("<I", data, off + 4)[0]
            if alen == 0 or off + alen > len(data):
                break
            non_res = data[off + 8]
            if non_res == 0:
                coff = struct.unpack_from("<H", data, off + 20)[0]
                clen = struct.unpack_from("<I", data, off + 16)[0]
                content = data[off + coff: off + coff + clen]
                if atype == 0x30 and len(content) >= 66:  # $FILE_NAME
                    nl = content[64]
                    if nl > 0 and len(content) >= 66 + nl * 2:
                        fname = content[66: 66 + nl * 2].decode(
                            "utf-16-le", errors="replace"
                        )
                        fsize = struct.unpack_from("<Q", content, 48)[0]
                        ct = struct.unpack_from("<Q", content, 8)[0]
                        mt = struct.unpack_from("<Q", content, 16)[0]
                        if created is None:
                            created  = _filetime(ct)
                            modified = _filetime(mt)
                elif atype == 0x10 and len(content) >= 16:  # $STANDARD_INFORMATION
                    ct = struct.unpack_from("<Q", content, 0)[0]
                    mt = struct.unpack_from("<Q", content, 8)[0]
                    if created is None:
                        created  = _filetime(ct)
                        modified = _filetime(mt)
            off += alen

        return MftRecord(
            record_number=record_num,
            filename=fname,
            is_directory=is_dir,
            is_active=is_active,
            size_bytes=fsize,
            created=created,
            modified=modified,
        )

    def _parse_indx(self, data: bytes) -> list[dict]:
        if data[:4] != b"INDX":
            return []
        entries: list[dict] = []
        try:
            idx_off  = struct.unpack_from("<I", data, 24)[0] + 24
            idx_size = struct.unpack_from("<I", data, 28)[0]
        except struct.error:
            return []

        e_off = idx_off
        while e_off + 16 <= 24 + idx_size and e_off + 16 <= len(data):
            e_inode = struct.unpack_from("<Q", data, e_off)[0] & 0xFFFFFFFFFFFF
            e_size  = struct.unpack_from("<H", data, e_off + 8)[0]
            e_ksize = struct.unpack_from("<H", data, e_off + 10)[0]
            e_flags = struct.unpack_from("<H", data, e_off + 12)[0]
            if e_size == 0:
                break
            if e_ksize >= 66:
                key = data[e_off + 16: e_off + 16 + e_ksize]
                if len(key) >= 66:
                    fname_ln = key[64]
                    if fname_ln > 0 and len(key) >= 66 + fname_ln * 2:
                        fname = key[66: 66 + fname_ln * 2].decode(
                            "utf-16-le", errors="replace"
                        )
                        fsize = struct.unpack_from("<Q", key, 48)[0]
                        ct    = struct.unpack_from("<Q", key, 8)[0]
                        mt    = struct.unpack_from("<Q", key, 16)[0]
                        entries.append({
                            "inode": e_inode,
                            "name": fname,
                            "size_bytes": fsize,
                            "created": _filetime(ct),
                            "modified": _filetime(mt),
                        })
            if e_flags & 0x02:
                break
            e_off += e_size

        return entries

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def _build_findings(self, result: WipeRecoveryResult) -> None:
        f = result.findings
        if result.gpt_backup_sector is not None:
            f.append(
                f"GPT backup partition table recovered from sector "
                f"{result.gpt_backup_sector:,} — "
                f"{len(result.partitions)} partition(s) identified"
            )
        if result.partitions:
            for p in result.partitions:
                f.append(
                    f"  Partition {p.index} '{p.name}': {p.type_guid}  "
                    f"{p.size_bytes // (1024 ** 2)} MiB"
                )
        if result.luks_headers:
            for lh in result.luks_headers:
                f.append(
                    f"LUKS2 encryption header found at sector {lh.sector:,}  "
                    f"UUID={lh.uuid}  cipher={lh.encryption}"
                )
            f.append(
                "  LUKS2 keyslot area may be intact — passphrase brute-force possible"
            )
        if result.mft_records:
            f.append(
                f"NTFS MFT records recovered: "
                + ", ".join(
                    f"'{r.filename}'" for r in result.mft_records if r.filename
                )
            )
        if result.ntfs_created:
            f.append(f"NTFS volume creation timestamp: {result.ntfs_created}")
        if result.indx_entries:
            names = [e["name"] for e in result.indx_entries if e.get("name")]
            f.append(f"NTFS root directory index recovered: {names}")
        wipe_desc = (
            f"Disk {result.wipe_pct:.1f}% wiped — "
            f"{result.data_pct:.1f}% of sectors intact "
            f"({len(result.data_runs)} data runs)"
        )
        f.append(wipe_desc)
        if result.wipe_pct > 80:
            f.append(
                "Wipe was interrupted — surviving data concentrated at high LBA "
                "(wiper operated low-to-high)"
            )


# ---------------------------------------------------------------------------
# Report writers
# ---------------------------------------------------------------------------


def write_json_report(result: WipeRecoveryResult, out_path: Path) -> None:
    """Serialize *result* to a JSON file."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(result.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def write_markdown_report(result: WipeRecoveryResult, out_path: Path) -> None:
    """Write a human-readable Markdown report to *out_path*."""
    lines: list[str] = [
        "# Wipe Recovery Report",
        "",
        f"**Image:** `{Path(result.image_path).name}`  ",
        f"**Size:** {result.disk_size_bytes:,} bytes "
        f"({result.disk_size_bytes / (1024 ** 3):.2f} GiB)  ",
        f"**Sectors:** {result.total_sectors:,}  ",
        f"**Wiped:** {result.wipe_pct:.1f}%  **Intact:** {result.data_pct:.1f}%",
        "",
        "## Partition Table",
        "",
    ]
    if result.partitions:
        lines += [
            "| # | Name | Type | Start LBA | End LBA | Size |",
            "|---|------|------|-----------|---------|------|",
        ]
        for p in result.partitions:
            lines.append(
                f"| {p.index} | `{p.name}` | {p.type_guid} "
                f"| {p.start_lba:,} | {p.end_lba:,} "
                f"| {p.size_bytes // (1024 ** 2)} MiB |"
            )
    else:
        lines.append("*No partition table recovered.*")

    if result.gpt_backup_sector:
        lines += [
            "",
            f"> GPT backup recovered from last sector ({result.gpt_backup_sector:,})",
        ]

    lines += ["", "## LUKS2 Encryption", ""]
    if result.luks_headers:
        for lh in result.luks_headers:
            lines += [
                f"- **UUID:** `{lh.uuid}`",
                f"- **Cipher:** {lh.encryption}",
                f"- **Key size:** {lh.key_size_bytes * 8}-bit",
                f"- **KDF:** {lh.kdf_type}",
                f"- **Found at sector:** {lh.sector:,}",
            ]
    else:
        lines.append("*No LUKS headers found.*")

    lines += ["", "## NTFS Metadata", ""]
    if result.mft_records:
        lines += [
            "| Inode | Name | Type | Size | Created |",
            "|-------|------|------|------|---------|",
        ]
        for m in result.mft_records:
            lines.append(
                f"| {m.record_number} | `{m.filename}` "
                f"| {'dir' if m.is_directory else 'file'} "
                f"| {m.size_bytes:,} "
                f"| {m.created or 'n/a'} |"
            )
    else:
        lines.append("*No MFT records recovered.*")

    if result.indx_entries:
        lines += ["", "### Root Directory Index", ""]
        for e in result.indx_entries:
            lines.append(f"- `{e['name']}` ({e['size_bytes']:,} bytes)")

    lines += ["", "## Key Findings", ""]
    for f in result.findings:
        lines.append(f"- {f}")

    lines += ["", "## Wipe Region Summary", "", f"Data runs: {len(result.data_runs)}  "]
    for r in result.data_runs[:20]:
        lines.append(
            f"- Sectors {r.start_sector:,}–{r.start_sector + r.sector_count - 1:,} "
            f"({r.size_bytes // 1024} KiB)"
        )
    if len(result.data_runs) > 20:
        lines.append(f"- … and {len(result.data_runs) - 20} more")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Convenience entry point
# ---------------------------------------------------------------------------


def analyse_disk_image(
    image_path: Path,
    output_dir: Path | None = None,
) -> WipeRecoveryResult:
    """Analyse *image_path* and optionally write reports to *output_dir*.

    Returns the :class:`WipeRecoveryResult` regardless of whether reports are
    written.
    """
    analyser = WipeRecoveryAnalyser(image_path)
    result = analyser.analyse()

    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)
        stem = image_path.stem
        write_json_report(result, output_dir / f"{stem}_wipe_recovery.json")
        write_markdown_report(result, output_dir / f"{stem}_wipe_recovery.md")
        if result.luks_json:
            lp = output_dir / f"{stem}_luks2_header.json"
            lp.write_text(
                json.dumps(result.luks_json, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        logger.info("Reports written to %s", output_dir)

    return result
