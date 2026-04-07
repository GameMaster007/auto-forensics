"""Auto Forensics — full-featured Windows application launcher.

Entry point: ``auto-forensics-launcher``

Features
--------
- **Single-instance enforcement** via a Windows named mutex (or a
  lockfile on Linux) — prevents launching duplicates.
- **Splash screen** shown on startup using ``tkinter`` (bundled with
  CPython) while the server boots.
- **System-tray icon** (``pystray`` + ``Pillow``) with a rich menu:
    - Status indicator (Starting / Running / Error)
    - Open Dashboard
    - Open Data Directory
    - Open Log File
    - Start with Windows (toggle)
    - About
    - Quit
- **Auto browser-open** when the server becomes ready.
- **Log-to-file** with automatic rotation (5 MB, 3 backups) in
  ``%APPDATA%/Auto Forensics/logs/``.
- **Windows toast notifications** for key events (server ready, analysis
  done) via ``win10toast_click`` or plain ``ctypes`` fallback.
- **Crash handler** that shows a ``ctypes.MessageBoxW`` dialog on
  unhandled exceptions instead of silently dying.

If ``pystray`` / ``Pillow`` are not installed the launcher degrades
gracefully to a headless console mode.
"""

from __future__ import annotations

import argparse
import atexit
import ctypes
import logging
import logging.handlers
import os
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

_log = logging.getLogger("auto_forensics.launcher")

# ───────────────────────────────────────────────────────────────────────────
# Constants
# ───────────────────────────────────────────────────────────────────────────
_APP_NAME = "Auto Forensics"
_APP_VERSION = "1.0.0"
_MUTEX_NAME = "AutoForensics_SingleInstance_Mutex"
_DEFAULT_HOST = "127.0.0.1"
_DEFAULT_PORT = 8765
_POLL_INTERVAL = 0.25
_READY_TIMEOUT = 30.0

_AUTOSTART_REG_KEY = (
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
)
_AUTOSTART_VALUE_NAME = "AutoForensics"

# ───────────────────────────────────────────────────────────────────────────
# Optional dependency probes
# ───────────────────────────────────────────────────────────────────────────
try:
    import pystray
    from PIL import Image as _PILImage
    _TRAY_AVAILABLE = True
except ImportError:
    pystray = None  # type: ignore[assignment]
    _PILImage = None  # type: ignore[assignment]
    _TRAY_AVAILABLE = False

try:
    import uvicorn as _uvicorn
    _UVICORN_AVAILABLE = True
except ImportError:
    _uvicorn = None  # type: ignore[assignment]
    _UVICORN_AVAILABLE = False

# ───────────────────────────────────────────────────────────────────────────
# Path helpers
# ───────────────────────────────────────────────────────────────────────────
_FROZEN = getattr(sys, "frozen", False)

def _app_data_dir() -> Path:
    """Application data directory for logs / settings."""
    override = os.environ.get("AUTO_FORENSICS_APPDATA")
    if override:
        d = Path(override).expanduser().resolve()
        d.mkdir(parents=True, exist_ok=True)
        return d
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", "~"))
    else:
        base = Path.home() / ".config"
    d = base / "Auto Forensics"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _log_dir() -> Path:
    d = _app_data_dir() / "logs"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _data_dir() -> Path:
    """The forensics data directory (cases, db, rules)."""
    from auto_forensics.config import AppConfig
    cfg = AppConfig.from_env()
    return cfg.data_dir


def _resolve_icon_path() -> Path | None:
    candidates = [
        Path(__file__).parent.parent.parent / "assets" / "icon.png",
    ]
    if _FROZEN:
        candidates.insert(
            0, Path(sys.executable).parent / "assets" / "icon.png"
        )
    for c in candidates:
        if c.exists():
            return c
    return None


def _resolve_ico_path() -> Path | None:
    candidates = [
        Path(__file__).parent.parent.parent / "assets" / "icon.ico",
    ]
    if _FROZEN:
        candidates.insert(
            0, Path(sys.executable).parent / "assets" / "icon.ico"
        )
    for c in candidates:
        if c.exists():
            return c
    return None


# ───────────────────────────────────────────────────────────────────────────
# Logging setup (file + console)
# ───────────────────────────────────────────────────────────────────────────
def _setup_logging() -> Path:
    log_file = _log_dir() / "auto_forensics.log"
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    # File handler — rotate at 5 MB, keep 3 backups
    fh = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    root.addHandler(fh)

    # Stderr handler — only warnings+ to keep console clean
    sh = logging.StreamHandler(sys.stderr)
    sh.setLevel(logging.WARNING)
    sh.setFormatter(logging.Formatter("%(levelname)s  %(message)s"))
    root.addHandler(sh)

    _log.info(
        "Auto Forensics launcher v%s  (Python %s, frozen=%s)",
        _APP_VERSION,
        sys.version.split()[0],
        _FROZEN,
    )
    return log_file


# ───────────────────────────────────────────────────────────────────────────
# Single-instance enforcement
# ───────────────────────────────────────────────────────────────────────────
_mutex_handle = None  # prevent GC


def _acquire_single_instance() -> bool:
    """Return True if we are the sole instance, False otherwise."""
    global _mutex_handle
    if sys.platform != "win32":
        # POSIX: use a lockfile
        lock_path = _app_data_dir() / ".launcher.lock"
        try:
            import fcntl
            _mutex_handle = open(lock_path, "w")
            fcntl.flock(_mutex_handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except (ImportError, OSError):
            return False

    # Windows: named mutex
    try:
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.CreateMutexW(None, True, _MUTEX_NAME)
        last_err = kernel32.GetLastError()
        if last_err == 183:  # ERROR_ALREADY_EXISTS
            kernel32.CloseHandle(handle)
            return False
        _mutex_handle = handle  # prevent GC / release
        return True
    except Exception:
        return True  # if ctypes fails, allow launch


def _release_single_instance() -> None:
    global _mutex_handle
    if _mutex_handle is None:
        return
    if sys.platform == "win32":
        try:
            ctypes.windll.kernel32.ReleaseMutex(_mutex_handle)  # type: ignore
            ctypes.windll.kernel32.CloseHandle(_mutex_handle)  # type: ignore
        except Exception:
            pass
    else:
        try:
            import fcntl
            fcntl.flock(_mutex_handle, fcntl.LOCK_UN)
            _mutex_handle.close()
        except Exception:
            pass
    _mutex_handle = None


# ───────────────────────────────────────────────────────────────────────────
# Crash handler — show a proper error dialog
# ───────────────────────────────────────────────────────────────────────────
def _install_crash_handler() -> None:
    def _handler(exc_type, exc_value, exc_tb):  # type: ignore[no-untyped-def]
        import traceback
        tb = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
        _log.critical("Unhandled exception:\n%s", tb)
        if sys.platform == "win32" and _FROZEN:
            ctypes.windll.user32.MessageBoxW(  # type: ignore
                0,
                f"Auto Forensics encountered a fatal error:\n\n{exc_value}\n\n"
                f"Details have been written to the log file.",
                "Auto Forensics — Error",
                0x10,  # MB_ICONERROR
            )
        sys.__excepthook__(exc_type, exc_value, exc_tb)
    sys.excepthook = _handler


# ───────────────────────────────────────────────────────────────────────────
# Splash screen (tkinter — always available with CPython on Windows)
# ───────────────────────────────────────────────────────────────────────────
class _SplashScreen:
    """Non-blocking splash window shown during server startup."""

    def __init__(self) -> None:
        self._root = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._dismiss = threading.Event()

    def show(self) -> None:
        self._thread = threading.Thread(
            target=self._run, name="splash", daemon=True
        )
        self._thread.start()
        self._ready.wait(timeout=3)

    def dismiss(self) -> None:
        self._dismiss.set()

    def _run(self) -> None:
        try:
            import tkinter as tk
        except ImportError:
            self._ready.set()
            return

        root = tk.Tk()
        self._root = root
        root.overrideredirect(True)
        root.attributes("-topmost", True)
        root.configure(bg="#0f172a")

        sw, sh = 420, 240
        x = (root.winfo_screenwidth() - sw) // 2
        y = (root.winfo_screenheight() - sh) // 2
        root.geometry(f"{sw}x{sh}+{x}+{y}")

        # Rounded appearance hint (Windows 11)
        try:
            root.attributes("-transparentcolor", "#010101")
        except tk.TclError:
            pass

        # Content
        frame = tk.Frame(root, bg="#0f172a")
        frame.pack(expand=True, fill="both", padx=2, pady=2)

        tk.Label(
            frame,
            text="Auto Forensics",
            font=("Segoe UI", 22, "bold"),
            fg="#00d2be",
            bg="#0f172a",
        ).pack(pady=(36, 4))

        tk.Label(
            frame,
            text="Autonomous Digital Forensics Platform",
            font=("Segoe UI", 10),
            fg="#8b949e",
            bg="#0f172a",
        ).pack()

        tk.Label(
            frame,
            text=f"v{_APP_VERSION}",
            font=("Segoe UI", 9),
            fg="#484f58",
            bg="#0f172a",
        ).pack(pady=(2, 0))

        self._status_var = tk.StringVar(value="Starting server...")
        tk.Label(
            frame,
            textvariable=self._status_var,
            font=("Segoe UI", 9),
            fg="#58a6ff",
            bg="#0f172a",
        ).pack(pady=(24, 0))

        # Progress dots animation
        self._dots = 0

        def _animate() -> None:
            if self._dismiss.is_set():
                root.destroy()
                return
            self._dots = (self._dots + 1) % 4
            dot_str = "." * self._dots
            self._status_var.set(f"Starting server{dot_str}")
            root.after(400, _animate)

        root.after(400, _animate)
        self._ready.set()

        # Poll for dismiss
        def _check_dismiss() -> None:
            if self._dismiss.is_set():
                root.destroy()
            else:
                root.after(100, _check_dismiss)

        root.after(100, _check_dismiss)
        root.mainloop()


# ───────────────────────────────────────────────────────────────────────────
# Windows notifications (best-effort)
# ───────────────────────────────────────────────────────────────────────────
def _notify(title: str, message: str) -> None:
    """Show a Windows toast notification (non-blocking, best-effort)."""
    if sys.platform != "win32":
        return
    try:
        # Windows 10+ balloon tip via shell
        from ctypes import wintypes
        _show_balloon_tip(title, message)
    except Exception:
        _log.debug("Toast notification failed", exc_info=True)


def _show_balloon_tip(title: str, message: str) -> None:
    """Show a system tray balloon notification via PowerShell."""
    ps_script = (
        "[void][System.Reflection.Assembly]"
        "::LoadWithPartialName('System.Windows.Forms');"
        "$n=New-Object System.Windows.Forms.NotifyIcon;"
        "$n.Icon=[System.Drawing.SystemIcons]::Information;"
        "$n.BalloonTipTitle='"
        + title.replace("'", "''")
        + "';"
        "$n.BalloonTipText='"
        + message.replace("'", "''")
        + "';"
        "$n.Visible=$true;"
        "$n.ShowBalloonTip(5000);"
        "Start-Sleep -Seconds 6;"
        "$n.Dispose()"
    )
    subprocess.Popen(
        ["powershell", "-WindowStyle", "Hidden", "-Command", ps_script],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=0x08000000,  # CREATE_NO_WINDOW
    )


# ───────────────────────────────────────────────────────────────────────────
# Auto-start with Windows (registry)
# ───────────────────────────────────────────────────────────────────────────
def _get_autostart_enabled() -> bool:
    if sys.platform != "win32":
        return False
    try:
        import winreg
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, _AUTOSTART_REG_KEY
        ) as key:
            winreg.QueryValueEx(key, _AUTOSTART_VALUE_NAME)
            return True
    except (FileNotFoundError, OSError):
        return False


def _set_autostart(enabled: bool) -> None:
    if sys.platform != "win32":
        return
    try:
        import winreg
        if enabled:
            exe = sys.executable
            if _FROZEN:
                cmd = f'"{exe}"'
            else:
                cmd = f'"{exe}" -m auto_forensics.launcher'
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                _AUTOSTART_REG_KEY,
                0,
                winreg.KEY_SET_VALUE,
            ) as key:
                winreg.SetValueEx(
                    key, _AUTOSTART_VALUE_NAME, 0,
                    winreg.REG_SZ, cmd,
                )
            _log.info("Auto-start enabled: %s", cmd)
        else:
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                _AUTOSTART_REG_KEY,
                0,
                winreg.KEY_SET_VALUE,
            ) as key:
                try:
                    winreg.DeleteValue(key, _AUTOSTART_VALUE_NAME)
                except FileNotFoundError:
                    pass
            _log.info("Auto-start disabled")
    except OSError as exc:
        _log.warning("Could not change auto-start: %s", exc)


# ───────────────────────────────────────────────────────────────────────────
# Server thread
# ───────────────────────────────────────────────────────────────────────────
def _is_port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


def _wait_for_server(host: str, port: int) -> bool:
    deadline = time.monotonic() + _READY_TIMEOUT
    while time.monotonic() < deadline:
        if _is_port_open(host, port):
            return True
        time.sleep(_POLL_INTERVAL)
    return False


class _ServerThread(threading.Thread):
    """Runs uvicorn in a daemon thread."""

    def __init__(self, host: str, port: int) -> None:
        super().__init__(name="uvicorn-server", daemon=True)
        self.host = host
        self.port = port
        self._server: object | None = None
        self._started = threading.Event()
        self._error: Exception | None = None

    def run(self) -> None:
        if not _UVICORN_AVAILABLE:
            self._error = ImportError(
                "uvicorn is not installed. "
                "Run: pip install auto-forensics-framework[server]"
            )
            self._started.set()
            return
        try:
            from auto_forensics.api import create_app
            from auto_forensics.config import AppConfig
            cfg = AppConfig.from_env()
            app = create_app(cfg)

            # In frozen (PyInstaller) builds uvicorn's default
            # logging config references its own formatter class
            # via a dotted path that importlib cannot resolve,
            # causing "Unable to configure formatter 'default'".
            # Pass log_config=None so uvicorn skips
            # dictConfig entirely — the launcher already
            # configures the root logger with file + console
            # handlers.
            ucfg = _uvicorn.Config(
                app=app,
                host=self.host,
                port=self.port,
                log_level="warning",
                log_config=None,
                access_log=False,
            )
            server = _uvicorn.Server(ucfg)
            self._server = server
            self._started.set()
            server.run()
        except Exception as exc:
            self._error = exc
            self._started.set()

    def stop(self) -> None:
        if self._server:
            self._server.should_exit = True  # type: ignore[attr-defined]


def _open_browser(url: str) -> None:
    try:
        webbrowser.open(url)
    except Exception as exc:
        _log.warning("Could not open browser: %s", exc)


# ───────────────────────────────────────────────────────────────────────────
# PIL image loader
# ───────────────────────────────────────────────────────────────────────────
def _load_pil_image():  # type: ignore[no-untyped-def]
    if not _TRAY_AVAILABLE:
        return None
    icon_path = _resolve_icon_path()
    if icon_path:
        try:
            return _PILImage.open(icon_path).convert("RGBA")
        except Exception:
            pass
    # Fallback: generate a minimal icon
    try:
        img = _PILImage.new("RGBA", (64, 64), (15, 23, 42, 255))
        from PIL import ImageDraw
        draw = ImageDraw.Draw(img)
        draw.ellipse([4, 4, 60, 60], outline=(0, 210, 190), width=4)
        draw.ellipse([18, 18, 44, 44], outline=(0, 210, 190), width=3)
        draw.line([(40, 40), (58, 58)], fill=(0, 210, 190), width=5)
        return img
    except Exception:
        return None


# ───────────────────────────────────────────────────────────────────────────
# System-tray application
# ───────────────────────────────────────────────────────────────────────────
class _TrayApp:
    """Full-featured system tray application."""

    def __init__(
        self,
        host: str,
        port: int,
        open_browser: bool,
        server_thread: _ServerThread,
        log_file: Path,
    ) -> None:
        self._host = host
        self._port = port
        self._open_browser = open_browser
        self._server = server_thread
        self._url = f"http://{host}:{port}/"
        self._log_file = log_file
        self._icon_obj = None
        self._status = "Starting"

    # ── menu actions ──────────────────────────────────────────────────
    def _on_open_dashboard(self, icon, item) -> None:  # type: ignore
        _open_browser(self._url)

    def _on_open_data_dir(self, icon, item) -> None:  # type: ignore
        try:
            data = _data_dir()
            if sys.platform == "win32":
                os.startfile(str(data))  # type: ignore[attr-defined]
            else:
                subprocess.Popen(["xdg-open", str(data)])
        except Exception as exc:
            _log.warning("Could not open data dir: %s", exc)

    def _on_open_log(self, icon, item) -> None:  # type: ignore
        try:
            if sys.platform == "win32":
                os.startfile(str(self._log_file))  # type: ignore[attr-defined]
            else:
                subprocess.Popen(["xdg-open", str(self._log_file)])
        except Exception as exc:
            _log.warning("Could not open log: %s", exc)

    def _on_toggle_autostart(self, icon, item) -> None:  # type: ignore
        current = _get_autostart_enabled()
        _set_autostart(not current)
        icon.update_menu()

    def _on_about(self, icon, item) -> None:  # type: ignore
        if sys.platform == "win32":
            ctypes.windll.user32.MessageBoxW(  # type: ignore
                0,
                (
                    f"Auto Forensics v{_APP_VERSION}\n\n"
                    "Autonomous Digital Forensics Platform\n\n"
                    f"Server: {self._url}\n"
                    f"Data: {_data_dir()}\n"
                    f"Log: {self._log_file}\n\n"
                    "MIT License"
                ),
                "About Auto Forensics",
                0x40,  # MB_ICONINFORMATION
            )

    def _on_quit(self, icon, item) -> None:  # type: ignore
        _log.info("Quit requested — stopping server")
        self._server.stop()
        icon.stop()

    # ── menu builder ──────────────────────────────────────────────────
    def _build_menu(self):  # type: ignore
        MI = pystray.MenuItem
        SEP = pystray.Menu.SEPARATOR
        return pystray.Menu(
            MI(
                lambda _: f"Auto Forensics — {self._status}",
                None,
                enabled=False,
            ),
            SEP,
            MI("Open Dashboard", self._on_open_dashboard, default=True),
            MI("Open Data Directory", self._on_open_data_dir),
            MI("Open Log File", self._on_open_log),
            SEP,
            MI(
                "Start with Windows",
                self._on_toggle_autostart,
                checked=lambda _: _get_autostart_enabled(),
            ),
            SEP,
            MI("About", self._on_about),
            MI("Quit", self._on_quit),
        )

    # ── lifecycle ─────────────────────────────────────────────────────
    def _startup(self, icon) -> None:  # type: ignore
        icon.visible = True
        _log.info(
            "Waiting for server on %s:%d", self._host, self._port
        )
        ready = _wait_for_server(self._host, self._port)
        if self._server._error:
            self._status = "Error"
            icon.update_menu()
            _log.error(
                "Server failed to start: %s", self._server._error
            )
            _notify(
                "Auto Forensics",
                f"Server failed to start: {self._server._error}",
            )
            return
        if ready:
            self._status = "Running"
            icon.update_menu()
            _log.info("Server is ready at %s", self._url)
            _notify(
                "Auto Forensics",
                f"Server running at {self._url}",
            )
            if self._open_browser:
                _open_browser(self._url)
        else:
            self._status = "Timeout"
            icon.update_menu()
            _log.warning("Server did not respond within %ss", _READY_TIMEOUT)

    def run(self) -> None:
        img = _load_pil_image()
        if img is None:
            _log.error(
                "Could not load tray icon; falling back to headless."
            )
            _run_headless(
                self._host, self._port,
                self._open_browser, self._server,
            )
            return
        self._icon_obj = pystray.Icon(
            "auto_forensics",
            img,
            "Auto Forensics",
            menu=self._build_menu(),
        )
        self._icon_obj.run(setup=self._startup)


# ───────────────────────────────────────────────────────────────────────────
# Headless fallback
# ───────────────────────────────────────────────────────────────────────────
def _run_headless(
    host: str,
    port: int,
    open_browser: bool,
    server_thread: _ServerThread,
) -> None:
    url = f"http://{host}:{port}/"
    print(f"\n  Auto Forensics v{_APP_VERSION}")
    print(f"  Server starting on {url}")
    print("  Press Ctrl-C to quit.\n")
    ready = _wait_for_server(host, port)
    if server_thread._error:
        print(
            f"  ERROR: {server_thread._error}",
            file=sys.stderr,
        )
        sys.exit(1)
    if ready:
        print(f"  Server ready — {url}")
        if open_browser:
            _open_browser(url)
    else:
        print("  WARNING: server did not respond in time.", file=sys.stderr)
    try:
        server_thread.join()
    except KeyboardInterrupt:
        print("\n  Shutting down...")
        server_thread.stop()


# ───────────────────────────────────────────────────────────────────────────
# CLI
# ───────────────────────────────────────────────────────────────────────────
def _parse_args(
    argv: list[str] | None = None,
) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="auto-forensics-launcher",
        description=(
            "Auto Forensics — GUI launcher with system-tray "
            "support."
        ),
    )
    p.add_argument(
        "--host", default=_DEFAULT_HOST, help="Bind address",
    )
    p.add_argument(
        "--port", type=int, default=_DEFAULT_PORT, help="Bind port",
    )
    p.add_argument(
        "--no-browser",
        action="store_true",
        help="Do not auto-open browser",
    )
    p.add_argument(
        "--no-tray",
        action="store_true",
        help="Run without system-tray icon (headless)",
    )
    p.add_argument(
        "--no-splash",
        action="store_true",
        help="Skip the splash screen",
    )
    p.add_argument(
        "--version",
        action="version",
        version=f"Auto Forensics {_APP_VERSION}",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    _install_crash_handler()
    log_file = _setup_logging()
    args = _parse_args(argv)

    # ── single-instance check ─────────────────────────────────────
    if not _acquire_single_instance():
        _log.warning("Another instance is already running.")
        if sys.platform == "win32" and _FROZEN:
            ctypes.windll.user32.MessageBoxW(  # type: ignore
                0,
                "Auto Forensics is already running.\n\n"
                "Check the system tray for the icon.",
                "Auto Forensics",
                0x40,  # MB_ICONINFORMATION
            )
        else:
            print(
                "Auto Forensics is already running.",
                file=sys.stderr,
            )
        sys.exit(0)
    atexit.register(_release_single_instance)

    # ── splash screen ─────────────────────────────────────────────
    splash: _SplashScreen | None = None
    use_tray = _TRAY_AVAILABLE and not args.no_tray
    if not args.no_splash and use_tray:
        splash = _SplashScreen()
        splash.show()

    # ── start server ──────────────────────────────────────────────
    srv = _ServerThread(args.host, args.port)
    srv.start()

    # Wait for server, then dismiss splash
    ready = _wait_for_server(args.host, args.port)
    if splash:
        splash.dismiss()

    # ── tray or headless ──────────────────────────────────────────
    if use_tray:
        tray = _TrayApp(
            args.host,
            args.port,
            not args.no_browser,
            srv,
            log_file,
        )
        tray._status = "Running" if ready else "Error"
        if ready and not args.no_browser:
            _open_browser(f"http://{args.host}:{args.port}/")
        tray.run()
    else:
        if not _TRAY_AVAILABLE and not args.no_tray:
            _log.info(
                "pystray / Pillow not installed — headless mode. "
                "Install: pip install pystray Pillow"
            )
        _run_headless(
            args.host, args.port, not args.no_browser, srv,
        )


if __name__ == "__main__":
    main()
