from __future__ import annotations

import hashlib
import logging
import math
import re
import stat
from collections import Counter
from pathlib import Path

from .models import BinaryFeature, BinaryStringMatch
from .security import SecurityError

logger = logging.getLogger(__name__)

SUSPICIOUS_KEYWORDS = [
    "powershell",
    "cmd.exe",
    "regsvr32",
    "rundll32",
    "mimikatz",
    "vssadmin",
    "wmic",
    "net user",
    "schtasks",
    "createprocess",
    "virtualalloc",
    "writeprocessmemory",
    "getprocaddress",
    "loadlibrary",
    "http://",
    "https://",
]

PE_IMPORT_KEYWORDS = {
    "VirtualAlloc",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "WinExec",
    "URLDownloadToFileA",
    "InternetOpenA",
    "RegSetValueExA",
}

_STRING_ENCODINGS = ("ascii", "utf-16le")
_STRING_PATTERNS = {
    encoding: re.compile(b"|".join(re.escape(keyword.encode(encoding)) for keyword in SUSPICIOUS_KEYWORDS), re.IGNORECASE)
    for encoding in _STRING_ENCODINGS
}
_STRING_OVERLAP = max(len(keyword.encode(encoding)) for encoding in _STRING_ENCODINGS for keyword in SUSPICIOUS_KEYWORDS) - 1
MAX_STRING_MATCHES = 256


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    length = len(data)
    buckets = [0] * 256
    for b in data:
        buckets[b] += 1
    entropy = 0.0
    for count in buckets:
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def _scan_binary(path: Path, chunk_size: int = 1024 * 1024) -> tuple[str, str, float, int, list[BinaryStringMatch], int]:
    """Hash, count entropy, and locate fixed ASCII/UTF-16LE keywords in one pass.

    Keep bounded locations, reserving space for the first occurrence of
    every keyword/encoding pair even when a different keyword is repeated
    many times earlier in the file. No binary code is executed.
    """
    if chunk_size < 1:
        raise ValueError("Binary scan chunk size must be positive")
    sha256 = hashlib.sha256()
    md5 = hashlib.md5(usedforsecurity=False)
    buckets: Counter[int] = Counter()
    total = 0
    first: dict[tuple[str, str], BinaryStringMatch] = {}
    samples: list[BinaryStringMatch] = []
    match_count = 0
    carry = b""
    sample_limit = MAX_STRING_MATCHES - len(SUSPICIOUS_KEYWORDS) * len(_STRING_ENCODINGS)
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            sha256.update(chunk)
            md5.update(chunk)
            buckets.update(chunk)
            window = carry + chunk
            base_offset = total - len(carry)
            for encoding, pattern in _STRING_PATTERNS.items():
                for match in pattern.finditer(window):
                    if match.end() <= len(carry):
                        continue
                    keyword = match.group().decode(encoding).lower()
                    location = BinaryStringMatch(keyword, base_offset + match.start(), encoding)
                    match_count += 1
                    first.setdefault((keyword, encoding), location)
                    if len(samples) < sample_limit:
                        samples.append(location)
            carry = window[-_STRING_OVERLAP:]
            total += len(chunk)
    entropy = 0.0
    for count in buckets.values():
        p = count / total
        entropy -= p * math.log2(p)
    unique = {(item.keyword, item.offset, item.encoding): item for item in [*samples, *first.values()]}
    matches = sorted(unique.values(), key=lambda item: (item.offset, item.encoding, item.keyword))
    return sha256.hexdigest(), md5.hexdigest(), round(entropy, 4), total, matches, match_count


def _extract_pe_import_hints(path: Path) -> list[str]:
    pe = None
    try:
        import pefile  # type: ignore
    except ImportError:
        return []
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
        hints: set[str] = set()
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            for imp in entry.imports:
                name = imp.name.decode(errors="ignore") if imp.name else ""
                if name in PE_IMPORT_KEYWORDS:
                    hints.add(name)
        return sorted(hints)
    except OSError as exc:
        logger.debug("Could not read PE file %s: %s", path, exc)
        return []
    except Exception as exc:
        logger.debug("PE import analysis failed for %s: %s", path, exc)
        return []
    finally:
        if pe is not None:
            pe.close()


def analyze_binary(path: Path) -> BinaryFeature:
    before = path.stat()
    if not stat.S_ISREG(before.st_mode):
        raise SecurityError("Binary analysis requires a regular file")
    sha256, md5, entropy, size_bytes, matches, match_count = _scan_binary(path)
    hits = sorted({match.keyword for match in matches})
    import_hints = _extract_pe_import_hints(path)
    after = path.stat()
    if size_bytes != after.st_size or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
    ):
        raise SecurityError("Binary changed during analysis; refusing inconsistent features")

    score = 0.0
    rationale: list[str] = []
    if entropy >= 7.2:
        score += 2.0
        rationale.append(f"High entropy ({entropy}) indicates packing or encryption.")
    elif entropy >= 6.8:
        score += 1.0
        rationale.append(f"Elevated entropy ({entropy}) may indicate obfuscation.")

    if hits:
        score += min(3.0, 0.25 * len(hits))
        rationale.append(f"Suspicious strings found: {', '.join(hits[:8])}.")

    if import_hints:
        score += min(3.0, 0.6 * len(import_hints))
        rationale.append(f"Risky PE imports found: {', '.join(import_hints[:8])}.")

    # Size is a modifier, not a signal: a small file with no other
    # indicator is usually a utility or a stub, not a dropper.
    if size_bytes < 20_000 and score > 0:
        score += 0.5
        rationale.append("Small executable size can indicate loader/dropper behavior.")

    return BinaryFeature(
        path=str(path),
        size_bytes=size_bytes,
        sha256=sha256,
        md5=md5,
        entropy=entropy,
        string_hits=hits,
        import_hints=import_hints,
        suspicious_score=round(score, 2),
        rationale=rationale,
        string_matches=matches,
        string_match_count=match_count,
        string_matches_truncated=match_count > len(matches),
        strings_scanned_bytes=size_bytes,
    )
