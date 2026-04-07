from __future__ import annotations

import hashlib
import logging
import math
import re
from pathlib import Path

from .models import BinaryFeature

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

ASCII_STRINGS_PATTERN = re.compile(rb"[ -~]{5,}")

# Maximum bytes to load into memory for string extraction. Keeps RSS bounded for large binaries.
_STRING_EXTRACT_CAP = 32 * 1024 * 1024  # 32 MB


def _streaming_analysis(path: Path, chunk_size: int = 1024 * 1024, string_cap: int = _STRING_EXTRACT_CAP) -> tuple[str, str, float, int, bytes]:
    """Compute sha256, md5, entropy, total bytes, and extract raw strings in a single pass."""
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    buckets = [0] * 256
    total = 0
    raw_buffer = bytearray()
    
    with path.open("rb") as f:
        while chunk := f.read(chunk_size):
            total += len(chunk)
            sha256.update(chunk)
            md5.update(chunk)
            for b in chunk:
                buckets[b] += 1
            if len(raw_buffer) < string_cap:
                raw_buffer.extend(chunk[:string_cap - len(raw_buffer)])

    if total == 0:
        return sha256.hexdigest(), md5.hexdigest(), 0.0, 0, b""

    entropy = 0.0
    for count in buckets:
        if count == 0:
            continue
        p = count / total
        entropy -= p * math.log2(p)

    return sha256.hexdigest(), md5.hexdigest(), round(entropy, 4), total, bytes(raw_buffer)


def _extract_strings(raw: bytes, limit: int = 4000) -> list[str]:
    values = [m.group().decode("ascii", errors="ignore") for m in ASCII_STRINGS_PATTERN.finditer(raw)]
    return values[:limit]


def _extract_pe_import_hints(path: Path) -> list[str]:
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


def analyze_binary(path: Path) -> BinaryFeature:
    sha256, md5, entropy, size_bytes, raw = _streaming_analysis(path)

    strings = _extract_strings(raw)
    lc = [s.lower() for s in strings]
    hits = sorted({k for k in SUSPICIOUS_KEYWORDS if any(k in s for s in lc)})
    import_hints = _extract_pe_import_hints(path)

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

    if size_bytes < 20_000:
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
    )
