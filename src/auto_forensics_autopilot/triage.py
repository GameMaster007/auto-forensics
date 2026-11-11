"""Profile an evidence directory and choose which agents run.

Triage reads file names, sizes, and the first bytes of each file. It
does not parse content and it never sends evidence to a model. The
plan it returns lists every agent with the reason it runs or is
skipped, so a skipped agent is visible in the draft rather than silent.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from auto_forensics.security import stays_in_tree

HEAD_BYTES = 4096
MAX_TRIAGE_FILES = 10_000
MAX_DEPTH = 20

BINARY_SUFFIXES = {".exe", ".dll", ".sys", ".bin", ".elf", ".so", ".scr", ".com", ".ps1", ".vbs", ".js", ".hta"}
MEMORY_SUFFIXES = {".raw", ".mem", ".vmem", ".lime", ".dmp", ".dump", ".core"}
TEXT_SUFFIXES = {".txt", ".log", ".md", ".csv", ".json", ".jsonl", ".xml", ".html", ".htm", ".ini", ".cfg", ".yml", ".yaml"}
ARCHIVE_SUFFIXES = {".zip", ".7z", ".rar", ".gz", ".tar", ".tgz"}
DISK_IMAGE_SUFFIXES = {".e01", ".ex01", ".dd", ".img", ".vmdk", ".vhd", ".vhdx", ".aff", ".aff4"}
# EnCase segments after the first (.E02 ... .EZZ) carry the same signature as .E01.
EWF_MAGIC = (b"EVF\x09\x0d\x0a\xff\x00", b"EVF2\x0d\x0a\x81\x00")

# Memory images are large. A small file named .dmp is usually a minidump
# or a test fixture, which the memory agent cannot use.
MIN_MEMORY_IMAGE_BYTES = 16 * 1024 * 1024


@dataclass(slots=True)
class EvidenceProfile:
    """Counts and paths by kind. Paths are relative to the evidence root."""

    root: str
    total_files: int = 0
    total_bytes: int = 0
    truncated: bool = False
    kinds: dict[str, list[str]] = field(default_factory=dict)
    skipped_links: int = 0

    def add(self, kind: str, rel: str) -> None:
        self.kinds.setdefault(kind, []).append(rel)

    def count(self, kind: str) -> int:
        return len(self.kinds.get(kind, []))

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["counts"] = {kind: len(paths) for kind, paths in sorted(self.kinds.items())}
        return data


@dataclass(slots=True)
class AgentPlan:
    name: str
    run: bool
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _head(path: Path) -> bytes:
    try:
        with path.open("rb") as handle:
            return handle.read(HEAD_BYTES)
    except OSError:
        return b""


def _boot_sector(head: bytes) -> bool:
    """An MBR, GPT, or volume boot record: what a raw disk or partition image starts with."""
    return len(head) >= 512 and (head[510:512] == b"\x55\xaa" or head[512:520] == b"EFI PART")


def _split_raw_segment(path: Path, suffix: str, head: bytes) -> bool:
    """``.001`` that starts like a disk, or ``.002``+ whose ``.001`` does (not a split 7z/RAR)."""
    if not re.fullmatch(r"\.\d{3}", suffix):
        return False
    if suffix == ".001":
        return _boot_sector(head)
    first = path.with_suffix(".001")
    return first.is_file() and not first.is_symlink() and _boot_sector(_head(first))


def classify(path: Path, size: int) -> str:
    """Return one kind for a file from its suffix, size, and magic bytes."""
    suffix = path.suffix.lower()
    head = _head(path)
    if head.startswith(b"MZ") or head.startswith(b"\x7fELF"):
        return "binary"
    if head.startswith(b"ElfFile\x00"):
        return "event_log"
    if suffix == ".evtx":
        return "event_log"
    if suffix in DISK_IMAGE_SUFFIXES or head.startswith(EWF_MAGIC) or _split_raw_segment(path, suffix, head):
        return "disk_image"
    if suffix == ".raw" and _boot_sector(head):
        return "disk_image"
    if suffix in MEMORY_SUFFIXES:
        return "memory_image" if size >= MIN_MEMORY_IMAGE_BYTES else "binary"
    if head.startswith(b"PK\x03\x04") or suffix in ARCHIVE_SUFFIXES:
        return "archive"
    if suffix in BINARY_SUFFIXES:
        return "binary"
    if suffix in {".csv", ".jsonl", ".json"} and _looks_like_timeline_export(head):
        return "timeline_export"
    if suffix in TEXT_SUFFIXES or _mostly_text(head):
        return "text"
    return "other"


def _looks_like_timeline_export(head: bytes) -> bool:
    text = head[:1024].decode("utf-8", errors="ignore").lower()
    markers = (
        "date,time,timezone,macb",  # psort l2tcsv
        "timestamp,computer,channel,eventid",  # hayabusa csv
        '"ruletitle"',  # hayabusa jsonl
        '"data_type"',  # psort json_line
        '"detections"',  # chainsaw
        '"group"',  # chainsaw
    )
    return any(marker in text for marker in markers)


def _mostly_text(head: bytes) -> bool:
    if not head:
        return True
    if b"\x00" in head:
        return False
    printable = sum(1 for byte in head if 32 <= byte < 127 or byte in (9, 10, 13))
    return printable / len(head) > 0.95


def profile_evidence(input_dir: Path, *, max_files: int = MAX_TRIAGE_FILES) -> EvidenceProfile:
    """Walk the tree without following links and classify each file."""
    root = input_dir.resolve()
    profile = EvidenceProfile(root=str(root))
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            profile.skipped_links += 1
            continue
        if not path.is_file() or not stays_in_tree(path, root):
            continue
        rel = path.relative_to(root)
        if len(rel.parts) > MAX_DEPTH:
            continue
        if profile.total_files >= max_files:
            profile.truncated = True
            break
        size = path.stat().st_size
        profile.total_files += 1
        profile.total_bytes += size
        profile.add(classify(path, size), rel.as_posix())
    return profile


def plan_agents(profile: EvidenceProfile, available: dict[str, tuple[bool, str]] | None = None) -> list[AgentPlan]:
    """Decide which agents run. ``available`` maps agent name to (installed, why not)."""
    available = available or {}

    def gated(name: str, wanted: bool, reason_yes: str, reason_no: str) -> AgentPlan:
        if not wanted:
            return AgentPlan(name, False, reason_no)
        ok, why = available.get(name, (True, ""))
        if not ok:
            return AgentPlan(name, False, why)
        return AgentPlan(name, True, reason_yes)

    has_text = profile.count("text") + profile.count("timeline_export") > 0
    plans = [
        AgentPlan("core_pipeline", profile.total_files > 0,
                  "always runs: parsers, YARA, detectors, verifier" if profile.total_files else "no evidence files"),
        gated("injection_sentinel", has_text or profile.count("binary") > 0,
              "text-bearing evidence present", "no text-bearing evidence"),
        gated("secrets_sweep", has_text,
              "text evidence present", "no text evidence"),
        gated("memory", profile.count("memory_image") > 0,
              f"{profile.count('memory_image')} memory image(s) found", "no memory image found"),
    ]
    if profile.count("disk_image"):
        plans.append(gated(
            "disk_image", True,
            f"{profile.count('disk_image')} disk image file(s): key artefacts are copied into the run folder "
            "and analysed", "",
        ))
    if profile.count("archive"):
        zips = [p for p in profile.kinds.get("archive", []) if p.lower().endswith(".zip")]
        others = profile.count("archive") - len(zips)
        reason = f"{profile.count('archive')} archive(s): ZIPs are extracted into the run folder and analysed"
        if others:
            reason += f"; {others} non-ZIP archive(s) are hashed only (extract them by hand)"
        plans.append(AgentPlan("archive", True, reason))
    return plans
