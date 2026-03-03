"""Disk image mounting and artifact extraction utilities.

Supports E01, DD/RAW, VMDK, VHD/VHDX, and AFF images.

Windows:  VHD/VHDX via PowerShell Mount-VHD;
          E01/RAW via Arsenal Image Mounter (aim_cli.exe) if on PATH.
Linux:    E01 via ewfmount+losetup; AFF via affuse+losetup;
          RAW/VMDK via losetup/qemu-nbd+mount.

All mount errors are caught and logged; callers should check the return
value of ``extract_image_to_staging`` for the ``mounted`` flag.
"""
from __future__ import annotations

import logging
import platform
import shlex
import shutil
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DISK_IMAGE_EXTENSIONS: frozenset[str] = frozenset(
    {".e01", ".dd", ".img", ".raw", ".vmdk", ".vhd", ".vhdx", ".aff"}
)

# Artifact glob patterns to copy from a mounted volume
_WINDOWS_ARTIFACT_GLOBS: list[str] = [
    # Windows Event Logs
    "**/*.evtx",
    # Registry hives
    "**/SYSTEM",
    "**/SOFTWARE",
    "**/SAM",
    "**/SECURITY",
    "**/NTUSER.DAT",
    "**/UsrClass.dat",
    # Prefetch
    "**/Prefetch/*.pf",
    # Chrome / Edge history (no extension on macOS/Linux copies, .sqlite on disk)
    "**/History",
    "**/History.db",
    "**/*.sqlite",
    # Firefox places
    "**/places.sqlite",
    # PST / OST email archives
    "**/*.pst",
    "**/*.ost",
    # Master File Table
    "**/$MFT",
    # LNK shell links (renamed to .bin during copy)
    "**/*.lnk",
]

_IS_WINDOWS = sys.platform == "win32"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def is_disk_image(path: Path) -> bool:
    """Return True if *path* looks like a supported disk image."""
    if path.suffix.lower() in DISK_IMAGE_EXTENSIONS:
        return True
    # Check magic bytes for raw/EWF images without a recognised extension
    try:
        with path.open("rb") as fh:
            magic = fh.read(8)
        if magic[:3] == b"EVF":  # EWF/E01
            return True
        if magic[:4] == b"KDMV":  # VMDK sparse
            return True
    except OSError:
        pass
    return False


def detect_image_format(path: Path) -> str:
    """Return a short string describing the image format."""
    suffix = path.suffix.lower()
    if suffix == ".e01":
        return "ewf"
    if suffix == ".vhd":
        return "vhd"
    if suffix == ".vhdx":
        return "vhdx"
    if suffix == ".vmdk":
        return "vmdk"
    if suffix == ".aff":
        return "aff"
    if suffix in {".dd", ".img", ".raw"}:
        return "raw"
    # Check magic bytes
    try:
        with path.open("rb") as fh:
            magic = fh.read(8)
        if magic[:3] == b"EVF":
            return "ewf"
        if magic[:4] == b"KDMV":
            return "vmdk"
    except OSError:
        pass
    return "unknown"


def _run(cmd: list[str], timeout: int = 60) -> bool:
    """Run *cmd*, return True on success (exit code 0)."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if result.returncode != 0:
            logger.debug("Command %s exited %d: %s", cmd[0], result.returncode, result.stderr[:200])
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.debug("Command %s failed: %s", cmd[0], exc)
        return False


# ---------------------------------------------------------------------------
# ImageMounter context manager
# ---------------------------------------------------------------------------


class ImageMounter:
    """Context manager that mounts a disk image and yields the mount point path.

    Usage::

        with ImageMounter(image_path) as mount_point:
            if mount_point is not None:
                # walk mount_point…

    ``__enter__`` returns ``None`` if mounting fails (error is logged).
    ``__exit__`` always attempts to unmount.
    """

    def __init__(self, image_path: Path) -> None:
        self._image_path = image_path.resolve()
        self._mount_point: Path | None = None
        self._loop_dev: str | None = None
        self._aim_drive: str | None = None
        self._tmp_mount_root: Path | None = None

    # ------------------------------------------------------------------
    # Public context-manager interface
    # ------------------------------------------------------------------

    def __enter__(self) -> Path | None:
        try:
            self._mount_point = self._mount()
        except Exception as exc:
            logger.warning(
                "Image mounting failed for %s: %s  "
                "(Install Arsenal Image Mounter on Windows, or ewfmount/losetup on Linux)",
                self._image_path.name,
                exc,
            )
            self._mount_point = None
        return self._mount_point

    def __exit__(self, *_: object) -> None:
        try:
            self._unmount()
        except Exception as exc:
            logger.debug("Unmount error for %s: %s", self._image_path.name, exc)

    # ------------------------------------------------------------------
    # Platform-specific mounting
    # ------------------------------------------------------------------

    def _mount(self) -> Path | None:
        fmt = detect_image_format(self._image_path)
        if _IS_WINDOWS:
            return self._mount_windows(fmt)
        return self._mount_linux(fmt)

    # --- Windows ---

    def _mount_windows(self, fmt: str) -> Path | None:
        if fmt in ("vhd", "vhdx"):
            return self._mount_vhd_windows()
        # Try Arsenal Image Mounter for EWF / raw
        aim = shutil.which("aim_cli.exe") or shutil.which("aim_cli")
        if aim:
            return self._mount_aim_windows(aim)
        logger.warning(
            "Arsenal Image Mounter (aim_cli.exe) not found on PATH. "
            "Download from https://arsenalrecon.com/downloads to mount %s images.",
            fmt.upper(),
        )
        return None

    def _mount_vhd_windows(self) -> Path | None:
        ps_cmd = (
            f"Mount-VHD -Path '{self._image_path}' -NoDriveLetter -ReadOnly -PassThru"
            " | Get-Disk | Get-Partition | Get-Volume | Select-Object -ExpandProperty DriveLetter"
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=120, check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Mount-VHD failed: {result.stderr[:200]}")
        drive_letter = result.stdout.strip().splitlines()[-1].strip() if result.stdout.strip() else ""
        if not drive_letter:
            # mount succeeded but no drive letter — use a known temp path
            tmp = Path(f"Z:")  # fallback; user should set letter
            self._aim_drive = str(self._image_path)
            return tmp
        mount = Path(f"{drive_letter}:\\")
        self._aim_drive = str(self._image_path)  # used to identify VHD for unmount
        return mount

    def _mount_aim_windows(self, aim: str) -> Path | None:
        import tempfile
        tmp = Path(tempfile.mkdtemp(prefix="af_mount_"))
        self._tmp_mount_root = tmp
        cmd = [aim, f"--filename={self._image_path}", f"--mount={tmp}"]
        if not _run(cmd, timeout=120):
            tmp.rmdir()
            self._tmp_mount_root = None
            raise RuntimeError(f"aim_cli failed to mount {self._image_path.name}")
        return tmp

    # --- Linux ---

    def _mount_linux(self, fmt: str) -> Path | None:
        import tempfile
        if fmt == "ewf":
            return self._mount_ewf_linux()
        if fmt == "aff":
            return self._mount_aff_linux()
        # RAW, VMDK, IMG, DD
        return self._mount_raw_linux()

    def _mount_ewf_linux(self) -> Path | None:
        import tempfile
        ewfmount = shutil.which("ewfmount")
        if not ewfmount:
            raise RuntimeError(
                "ewfmount not found. Install libewf-tools: apt install libewf-dev"
            )
        ewf_dir = Path(tempfile.mkdtemp(prefix="af_ewf_"))
        if not _run([ewfmount, str(self._image_path), str(ewf_dir)], timeout=120):
            ewf_dir.rmdir()
            raise RuntimeError(f"ewfmount failed for {self._image_path.name}")
        ewf_raw = ewf_dir / "ewf1"
        mount_dir = Path(tempfile.mkdtemp(prefix="af_mount_"))
        self._tmp_mount_root = ewf_dir  # so we unmount ewf_dir too
        loop_result = subprocess.run(
            ["losetup", "--find", "--show", "--read-only", str(ewf_raw)],
            capture_output=True, text=True, timeout=30, check=False,
        )
        if loop_result.returncode != 0:
            raise RuntimeError(f"losetup failed: {loop_result.stderr[:200]}")
        self._loop_dev = loop_result.stdout.strip()
        if not _run(["mount", "-o", "ro", self._loop_dev, str(mount_dir)], timeout=30):
            raise RuntimeError(f"mount failed for {self._loop_dev}")
        return mount_dir

    def _mount_aff_linux(self) -> Path | None:
        import tempfile
        affuse = shutil.which("affuse")
        if not affuse:
            raise RuntimeError("affuse not found. Install afflib-tools.")
        aff_dir = Path(tempfile.mkdtemp(prefix="af_aff_"))
        if not _run([affuse, str(self._image_path), str(aff_dir)], timeout=120):
            aff_dir.rmdir()
            raise RuntimeError(f"affuse failed for {self._image_path.name}")
        aff_raw = aff_dir / (self._image_path.stem + ".raw")
        mount_dir = Path(tempfile.mkdtemp(prefix="af_mount_"))
        self._tmp_mount_root = aff_dir
        loop_result = subprocess.run(
            ["losetup", "--find", "--show", "--read-only", str(aff_raw)],
            capture_output=True, text=True, timeout=30, check=False,
        )
        if loop_result.returncode != 0:
            raise RuntimeError(f"losetup failed: {loop_result.stderr[:200]}")
        self._loop_dev = loop_result.stdout.strip()
        if not _run(["mount", "-o", "ro", self._loop_dev, str(mount_dir)], timeout=30):
            raise RuntimeError(f"mount failed for {self._loop_dev}")
        return mount_dir

    def _mount_raw_linux(self) -> Path | None:
        import tempfile
        mount_dir = Path(tempfile.mkdtemp(prefix="af_mount_"))
        loop_result = subprocess.run(
            ["losetup", "--find", "--show", "--read-only", str(self._image_path)],
            capture_output=True, text=True, timeout=30, check=False,
        )
        if loop_result.returncode != 0:
            mount_dir.rmdir()
            raise RuntimeError(f"losetup failed: {loop_result.stderr[:200]}")
        self._loop_dev = loop_result.stdout.strip()
        if not _run(["mount", "-o", "ro", self._loop_dev, str(mount_dir)], timeout=30):
            _run(["losetup", "-d", self._loop_dev])
            self._loop_dev = None
            mount_dir.rmdir()
            raise RuntimeError(f"mount failed for {self._loop_dev}")
        return mount_dir

    # ------------------------------------------------------------------
    # Unmounting
    # ------------------------------------------------------------------

    def _unmount(self) -> None:
        if self._mount_point is not None:
            if _IS_WINDOWS:
                self._unmount_windows()
            else:
                self._unmount_linux()
        self._mount_point = None

    def _unmount_windows(self) -> None:
        # VHD/VHDX: Dismount-VHD
        if self._aim_drive and (
            str(self._image_path).lower().endswith(".vhd")
            or str(self._image_path).lower().endswith(".vhdx")
        ):
            ps_cmd = f"Dismount-VHD -Path '{self._image_path}'"
            subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True, timeout=60, check=False,
            )
        # AIM CLI: just remove temp dir; aim_cli handles cleanup on its own
        if self._tmp_mount_root and self._tmp_mount_root.exists():
            aim = shutil.which("aim_cli.exe") or shutil.which("aim_cli")
            if aim:
                _run([aim, f"--unmount={self._tmp_mount_root}"], timeout=60)
            try:
                shutil.rmtree(self._tmp_mount_root, ignore_errors=True)
            except OSError:
                pass
            self._tmp_mount_root = None

    def _unmount_linux(self) -> None:
        if self._mount_point and self._mount_point.exists():
            _run(["umount", str(self._mount_point)], timeout=30)
            try:
                self._mount_point.rmdir()
            except OSError:
                pass
        if self._loop_dev:
            _run(["losetup", "-d", self._loop_dev], timeout=15)
            self._loop_dev = None
        # EWF/AFF fuse mount
        if self._tmp_mount_root and self._tmp_mount_root.exists():
            _run(["fusermount", "-u", str(self._tmp_mount_root)], timeout=30)
            try:
                shutil.rmtree(self._tmp_mount_root, ignore_errors=True)
            except OSError:
                pass
            self._tmp_mount_root = None


# ---------------------------------------------------------------------------
# Artifact extraction
# ---------------------------------------------------------------------------


def copy_artifacts_from_volume(
    volume_root: Path,
    staging_dir: Path,
    *,
    max_file_size_bytes: int = 200 * 1024 * 1024,
) -> list[Path]:
    """Walk *volume_root*, copy matching artifacts to *staging_dir*.

    LNK files are renamed to ``.bin`` so the binary analyser picks them up.
    Returns the list of copied destination paths.
    """
    staging_dir.mkdir(parents=True, exist_ok=True)
    copied: list[Path] = []

    seen: set[Path] = set()
    for pattern in _WINDOWS_ARTIFACT_GLOBS:
        try:
            matches = list(volume_root.rglob(pattern.lstrip("**/").lstrip("*")))
        except Exception:
            matches = []
        # Also try the full glob
        try:
            matches += list(volume_root.glob(pattern))
        except Exception:
            pass

        for src in matches:
            if not src.is_file() or src in seen:
                continue
            seen.add(src)
            try:
                stat = src.stat()
                if stat.st_size > max_file_size_bytes:
                    logger.debug("Skipping oversized artifact %s (%d bytes)", src.name, stat.st_size)
                    continue
            except OSError:
                continue

            # Derive destination name; rename .lnk → .bin
            dest_name = src.name
            if dest_name.lower().endswith(".lnk"):
                dest_name = src.stem + ".bin"

            # Preserve relative path structure to avoid name collisions
            try:
                rel = src.relative_to(volume_root)
            except ValueError:
                rel = Path(src.name)
            dest = staging_dir / rel.parent / dest_name
            dest.parent.mkdir(parents=True, exist_ok=True)

            # Avoid overwrite by appending counter
            if dest.exists():
                dest = dest.parent / f"{dest.stem}_1{dest.suffix}"

            try:
                shutil.copy2(src, dest)
                copied.append(dest)
                logger.debug("Copied artifact %s → %s", src.name, dest)
            except OSError as exc:
                logger.warning("Failed to copy %s: %s", src, exc)

    return copied


def _export_browser_history_to_json(
    copied_paths: list[Path],
    staging_dir: Path,
) -> None:
    """For each SQLite browser history file, write a JSON sidecar.

    The sidecar is named ``<original_stem>_browser_events.json`` and placed
    alongside the source file so ``JsonArtifactParser`` picks it up.
    """
    import json

    browser_names = {"history", "places.sqlite", "history.db"}
    for path in copied_paths:
        name_lower = path.name.lower()
        suffix_lower = path.suffix.lower()
        if suffix_lower not in (".sqlite", ".db") and name_lower not in {"history"}:
            continue
        if name_lower not in browser_names and suffix_lower not in (".sqlite",):
            continue

        from .artifacts import load_browser_history_artifacts
        events = load_browser_history_artifacts(path)
        if not events:
            continue

        sidecar = path.parent / f"{path.stem}_browser_events.json"
        try:
            payload = [
                {
                    "artifact_id": e.artifact_id,
                    "timestamp": e.timestamp,
                    "event_type": e.event_type,
                    "description": e.description,
                    "source": e.source,
                    **e.metadata,
                }
                for e in events
            ]
            sidecar.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            logger.debug("Wrote browser sidecar %s (%d events)", sidecar.name, len(events))
        except OSError as exc:
            logger.warning("Failed to write browser sidecar %s: %s", sidecar, exc)


def extract_image_to_staging(
    image_path: Path,
    staging_dir: Path,
    *,
    max_file_size_bytes: int = 200 * 1024 * 1024,
) -> dict:
    """Mount *image_path*, copy artifacts to *staging_dir*, unmount.

    Returns a dict with keys:
    - ``mounted`` (bool)
    - ``artifacts_copied`` (int)
    - ``staging_dir`` (str)
    - ``error`` (str | None)
    """
    staging_dir = staging_dir.resolve()
    staging_dir.mkdir(parents=True, exist_ok=True)

    with ImageMounter(image_path) as mount_point:
        if mount_point is None:
            return {
                "mounted": False,
                "artifacts_copied": 0,
                "staging_dir": str(staging_dir),
                "error": (
                    f"Could not mount {image_path.name}. "
                    "Install Arsenal Image Mounter (Windows) or ewfmount/losetup (Linux)."
                ),
            }

        try:
            copied = copy_artifacts_from_volume(
                mount_point, staging_dir, max_file_size_bytes=max_file_size_bytes
            )
        except Exception as exc:
            logger.warning("Artifact copy failed from %s: %s", image_path.name, exc)
            return {
                "mounted": True,
                "artifacts_copied": 0,
                "staging_dir": str(staging_dir),
                "error": str(exc),
            }

        _export_browser_history_to_json(copied, staging_dir)

        return {
            "mounted": True,
            "artifacts_copied": len(copied),
            "staging_dir": str(staging_dir),
            "error": None,
        }
