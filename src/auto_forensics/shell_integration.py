"""Windows shell integration — Explorer context menu and file
associations.

Usage (requires elevation)::

    auto-forensics shell --install      # register context menus
    auto-forensics shell --uninstall    # remove context menus
    auto-forensics shell --status       # show current registration

This module is also called by the Inno Setup installer during
post-install and pre-uninstall steps.
"""

from __future__ import annotations

import sys

if sys.platform != "win32":
    raise SystemExit("Shell integration is only supported on Windows.")

import logging
import winreg
from pathlib import Path

_log = logging.getLogger(__name__)

_FROZEN = getattr(sys, "frozen", False)

# Context menu verb keys
_FILE_VERB_KEY = r"*\shell\AutoForensicsScan"
_DIR_VERB_KEY = r"Directory\shell\AutoForensicsScanDir"
_DIR_BG_VERB_KEY = (
    r"Directory\Background\shell\AutoForensicsScanDir"
)

# File association
_AFCASE_EXT_KEY = r".afcase"
_AFCASE_PROG_ID = "AutoForensics.CaseArchive"
_AFCASE_PROG_KEY = rf"SOFTWARE\Classes\{_AFCASE_PROG_ID}"


def _exe_path() -> str:
    """Return the path to the CLI executable."""
    if _FROZEN:
        base = Path(sys.executable).parent
        cli = base / "auto-forensics.exe"
        if cli.exists():
            return str(cli)
        return str(base / "AutoForensics.exe")
    return sys.executable


def _icon_path() -> str:
    """Return the path to the icon file."""
    candidates = [
        Path(sys.executable).parent / "assets" / "icon.ico",
        Path(__file__).parent.parent.parent / "assets" / "icon.ico",
    ]
    for c in candidates:
        if c.exists():
            return str(c)
    return ""


def install() -> None:
    """Register context-menu entries and file associations.

    Requires the process to be running with administrator privileges.
    """
    exe = _exe_path()
    ico = _icon_path()
    _log.info("Registering shell integration (exe=%s)", exe)

    # ── Right-click any file → "Scan with Auto Forensics" ─────────
    _set_key(
        winreg.HKEY_CLASSES_ROOT,
        _FILE_VERB_KEY,
        "Scan with Auto Forensics",
    )
    if ico:
        _set_key(
            winreg.HKEY_CLASSES_ROOT,
            _FILE_VERB_KEY,
            ico,
            value_name="Icon",
        )
    _set_key(
        winreg.HKEY_CLASSES_ROOT,
        rf"{_FILE_VERB_KEY}\command",
        f'"{exe}" scan --path "%1"',
    )

    # ── Right-click a directory → "Scan directory with AF" ────────
    _set_key(
        winreg.HKEY_CLASSES_ROOT,
        _DIR_VERB_KEY,
        "Scan directory with Auto Forensics",
    )
    if ico:
        _set_key(
            winreg.HKEY_CLASSES_ROOT,
            _DIR_VERB_KEY,
            ico,
            value_name="Icon",
        )
    _set_key(
        winreg.HKEY_CLASSES_ROOT,
        rf"{_DIR_VERB_KEY}\command",
        f'"{exe}" scan-dir --path "%1"',
    )

    # ── Right-click directory background ──────────────────────────
    _set_key(
        winreg.HKEY_CLASSES_ROOT,
        _DIR_BG_VERB_KEY,
        "Scan directory with Auto Forensics",
    )
    if ico:
        _set_key(
            winreg.HKEY_CLASSES_ROOT,
            _DIR_BG_VERB_KEY,
            ico,
            value_name="Icon",
        )
    _set_key(
        winreg.HKEY_CLASSES_ROOT,
        rf"{_DIR_BG_VERB_KEY}\command",
        f'"{exe}" scan-dir --path "%V"',
    )

    # ── .afcase file association ──────────────────────────────────
    _set_key(
        winreg.HKEY_CLASSES_ROOT,
        _AFCASE_EXT_KEY,
        _AFCASE_PROG_ID,
    )
    _set_key(
        winreg.HKEY_CLASSES_ROOT,
        rf"SOFTWARE\Classes\{_AFCASE_PROG_ID}",
        "Auto Forensics Case Archive",
    )
    if ico:
        _set_key(
            winreg.HKEY_CLASSES_ROOT,
            rf"SOFTWARE\Classes\{_AFCASE_PROG_ID}\DefaultIcon",
            ico,
        )
    _set_key(
        winreg.HKEY_CLASSES_ROOT,
        rf"SOFTWARE\Classes\{_AFCASE_PROG_ID}\shell\open\command",
        f'"{exe}" import --archive "%1"',
    )

    _log.info("Shell integration installed successfully")
    print("Shell integration installed.")


def uninstall() -> None:
    """Remove context-menu entries and file associations."""
    _log.info("Removing shell integration")
    for key_path in (
        rf"{_FILE_VERB_KEY}\command",
        _FILE_VERB_KEY,
        rf"{_DIR_VERB_KEY}\command",
        _DIR_VERB_KEY,
        rf"{_DIR_BG_VERB_KEY}\command",
        _DIR_BG_VERB_KEY,
        rf"SOFTWARE\Classes\{_AFCASE_PROG_ID}\shell\open\command",
        rf"SOFTWARE\Classes\{_AFCASE_PROG_ID}\shell\open",
        rf"SOFTWARE\Classes\{_AFCASE_PROG_ID}\shell",
        rf"SOFTWARE\Classes\{_AFCASE_PROG_ID}\DefaultIcon",
        rf"SOFTWARE\Classes\{_AFCASE_PROG_ID}",
        _AFCASE_EXT_KEY,
    ):
        _del_key(winreg.HKEY_CLASSES_ROOT, key_path)
    _log.info("Shell integration removed")
    print("Shell integration removed.")


def status() -> None:
    """Print current registration status."""
    entries = {
        "Scan file context menu": _FILE_VERB_KEY,
        "Scan directory context menu": _DIR_VERB_KEY,
        ".afcase file association": _AFCASE_EXT_KEY,
    }
    for label, key_path in entries.items():
        try:
            winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, key_path)
            print(f"  [registered]    {label}")
        except FileNotFoundError:
            print(f"  [not registered] {label}")


# ── registry helpers ──────────────────────────────────────────────────────
def _set_key(
    root: int,
    subkey: str,
    value: str,
    value_name: str = "",
) -> None:
    try:
        with winreg.CreateKeyEx(
            root, subkey, 0, winreg.KEY_SET_VALUE
        ) as key:
            winreg.SetValueEx(
                key, value_name, 0, winreg.REG_SZ, value,
            )
    except PermissionError:
        _log.error(
            "Permission denied writing %s — run as administrator",
            subkey,
        )
        raise SystemExit(
            "Permission denied. Run as administrator."
        )


def _del_key(root: int, subkey: str) -> None:
    try:
        winreg.DeleteKey(root, subkey)
    except FileNotFoundError:
        pass
    except PermissionError:
        _log.warning("Could not delete %s (permission denied)", subkey)
