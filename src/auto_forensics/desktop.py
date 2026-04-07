"""Standalone desktop launcher for Auto Forensics.

This entry point opens the redesigned investigation workspace in a native
desktop window instead of launching an external browser.
"""

from __future__ import annotations

import argparse
import atexit
import os
import sys
from pathlib import Path
from typing import Any

from . import launcher as _legacy_launcher

try:
    import webview

    _WEBVIEW_AVAILABLE = True
except Exception:  # pragma: no cover - optional desktop dependency
    webview = None  # type: ignore[assignment]
    _WEBVIEW_AVAILABLE = False


_APP_VERSION = _legacy_launcher._APP_VERSION
_DEFAULT_HOST = _legacy_launcher._DEFAULT_HOST
_DEFAULT_PORT = _legacy_launcher._DEFAULT_PORT


def _bundle_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[2]


def _configure_portable_mode() -> bool:
    if os.getenv("AUTO_FORENSICS_HOME"):
        return False

    portable_root = _bundle_root()
    markers = [
        portable_root / "portable.mode",
        portable_root / "portable.flag",
    ]
    if not any(marker.exists() for marker in markers):
        return False

    data_root = portable_root / "data"
    logs_root = data_root / "logs"
    os.environ["AUTO_FORENSICS_HOME"] = str(data_root)
    os.environ["AUTO_FORENSICS_APPDATA"] = str(data_root)
    os.environ.setdefault("AUTO_FORENSICS_ENV", "prod")
    data_root.mkdir(parents=True, exist_ok=True)
    logs_root.mkdir(parents=True, exist_ok=True)
    return True


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="auto-forensics-app",
        description="Auto Forensics — standalone desktop workspace.",
    )
    parser.add_argument("--host", default=_DEFAULT_HOST, help="Bind address")
    parser.add_argument("--port", type=int, default=_DEFAULT_PORT, help="Bind port")
    parser.add_argument(
        "--no-splash",
        action="store_true",
        help="Skip the startup splash screen",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable webview debug tools",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"Auto Forensics {_APP_VERSION}",
    )
    return parser.parse_args(argv)


def _open_window(url: str, debug: bool) -> None:
    if not _WEBVIEW_AVAILABLE:
        raise RuntimeError(
            "pywebview is not installed. Install with: pip install -e .[desktop]"
        )
    webview.create_window(
        "Auto Forensics",
        url,
        width=1600,
        height=1000,
        min_size=(1200, 800),
        confirm_close=True,
    )
    webview.start(debug=debug)


def main(argv: list[str] | None = None) -> None:
    _legacy_launcher._install_crash_handler()
    args = _parse_args(argv)

    _configure_portable_mode()

    _legacy_launcher._setup_logging()

    if not _WEBVIEW_AVAILABLE:
        raise RuntimeError(
            "pywebview is not installed. Install with: pip install -e .[desktop]"
        )

    if not _legacy_launcher._acquire_single_instance():
        if sys.platform == "win32" and getattr(sys, "frozen", False):
            import ctypes

            ctypes.windll.user32.MessageBoxW(  # type: ignore[attr-defined]
                0,
                "Auto Forensics is already running.\n\n"
                "Close the existing window before starting another.",
                "Auto Forensics",
                0x40,
            )
        else:
            print("Auto Forensics is already running.", file=sys.stderr)
        raise SystemExit(0)

    atexit.register(_legacy_launcher._release_single_instance)

    splash: Any | None = None
    if not args.no_splash:
        splash = _legacy_launcher._SplashScreen()
        splash.show()

    server = _legacy_launcher._ServerThread(args.host, args.port)
    server.start()

    ready = _legacy_launcher._wait_for_server(args.host, args.port)
    if splash is not None:
        splash.dismiss()

    if server._error:
        raise RuntimeError(f"Server failed to start: {server._error}")
    if not ready:
        raise RuntimeError("Server did not respond in time.")

    try:
        _open_window(f"http://{args.host}:{args.port}/", debug=args.debug)
    finally:
        server.stop()


if __name__ == "__main__":
    main()
