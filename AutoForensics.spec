# -*- mode: python ; coding: utf-8 -*-
# ╔═══════════════════════════════════════════════════════════════════════╗
# ║  Auto Forensics — PyInstaller spec                                  ║
# ╠═══════════════════════════════════════════════════════════════════════╣
# ║  Build:  pyinstaller AutoForensics.spec --noconfirm --clean         ║
# ║  Output: dist/AutoForensics/                                        ║
# ║          ├── AutoForensics.exe    (GUI, no console)                 ║
# ║          ├── auto-forensics.exe   (CLI, with console)               ║
# ║          └── assets/              (icon files)                      ║
# ╚═══════════════════════════════════════════════════════════════════════╝

import sys
from pathlib import Path

ROOT = Path(SPECPATH)
SRC  = ROOT / "src"

# ── data files to bundle ──────────────────────────────────────────────────
web_datas = [
    (str(ROOT / "src" / "auto_forensics" / "web"), "auto_forensics/web"),
    (str(ROOT / "assets"), "assets"),
    (str(ROOT / "LICENSE"), "."),
]

# ── hidden imports (all app modules + server stack) ───────────────────────
hiddenimports = [
    # server
    "uvicorn",
    "uvicorn.lifespan.on",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.http.httptools_impl",
    "uvicorn.protocols.http.h11_impl",
    "uvicorn.logging",
    "fastapi",
    "fastapi.routing",
    "fastapi.middleware",
    "pydantic",
    "pydantic.deprecated.class_validators",
    "pydantic._internal._generate_schema",
    "anyio",
    "anyio._backends._asyncio",
    "starlette",
    "starlette.routing",
    "starlette.responses",
    "starlette.staticfiles",
    "httptools",
    # tray / splash
    "pystray",
    "pystray._win32",
    "PIL",
    "PIL.Image",
    "PIL.ImageDraw",
    "tkinter",
    "webview",
    # app modules
    "auto_forensics",
    "auto_forensics.desktop",
    "auto_forensics.api",
    "auto_forensics.cli",
    "auto_forensics.launcher",
    "auto_forensics.shell_integration",
    "auto_forensics.service",
    "auto_forensics.pipeline",
    "auto_forensics.config",
    "auto_forensics.security",
    "auto_forensics.db",
    "auto_forensics.db_backend",
    "auto_forensics.models",
    "auto_forensics.plugins",
    "auto_forensics.artifacts",
    "auto_forensics.binary_analysis",
    "auto_forensics.timeline",
    "auto_forensics.ioc_pipeline",
    "auto_forensics.ioc_enrichment",
    "auto_forensics.llama_workflow",
    "auto_forensics.builtin_detectors",
    "auto_forensics.event_detectors",
    "auto_forensics.case_manager",
    "auto_forensics.migrations",
    "auto_forensics.pdf_report",
    "auto_forensics.sigma_rules",
    "auto_forensics.yara_detector",
    "auto_forensics.attack_mapper",
    "auto_forensics.stix_export",
    "auto_forensics.agent",
    "auto_forensics.watcher",
    "auto_forensics.disk_image",
    # stdlib
    "sqlite3",
    "email",
    "html",
    "http",
    "urllib",
    "xml",
    "json",
    "csv",
    "logging.handlers",
    "concurrent.futures",
    "multiprocessing",
    "threading",
    "socket",
    "ssl",
    "webbrowser",
    "ctypes",
    "winreg",
    "hashlib",
    "hmac",
    "zipfile",
    "io",
    "pathlib",
    "argparse",
    "textwrap",
    "shutil",
    "tempfile",
    "datetime",
    "re",
    "struct",
    "zlib",
    "functools",
    "itertools",
    "collections",
    "dataclasses",
    "typing",
    "math",
    "time",
    "os",
    "sys",
    "atexit",
    "signal",
    # rich (terminal styling for CLI)
    "rich",
    "rich.console",
    "rich.table",
    "rich.panel",
    "rich.text",
    "rich.progress",
    "rich.markup",
    "rich.tree",
]

block_cipher = None

# manifest path
_manifest = str(ROOT / "assets" / "AutoForensics.manifest")

# ─────────────────────────────────────────────────────────────────────────
# GUI launcher — AutoForensics.exe  (windowed, no console)
# ─────────────────────────────────────────────────────────────────────────
launcher_a = Analysis(
    [str(SRC / "auto_forensics" / "desktop.py")],
    pathex=[str(SRC)],
    binaries=[],
    datas=web_datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["matplotlib", "scipy", "numpy", "pandas"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

launcher_pyz = PYZ(
    launcher_a.pure,
    launcher_a.zipped_data,
    cipher=block_cipher,
)

launcher_exe = EXE(
    launcher_pyz,
    launcher_a.scripts,
    [],
    exclude_binaries=True,
    name="AutoForensics",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    windowed=True,
    icon=str(ROOT / "assets" / "icon.ico"),
    version=str(ROOT / "assets" / "version_info.txt"),
    manifest=_manifest,
    uac_admin=False,
)

# ─────────────────────────────────────────────────────────────────────────
# CLI executable — auto-forensics.exe  (console)
# ─────────────────────────────────────────────────────────────────────────
cli_a = Analysis(
    [str(SRC / "auto_forensics" / "cli.py")],
    pathex=[str(SRC)],
    binaries=[],
    datas=web_datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["matplotlib", "scipy", "numpy", "pandas"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

cli_pyz = PYZ(
    cli_a.pure,
    cli_a.zipped_data,
    cipher=block_cipher,
)

cli_exe = EXE(
    cli_pyz,
    cli_a.scripts,
    [],
    exclude_binaries=True,
    name="auto-forensics",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    icon=str(ROOT / "assets" / "icon.ico"),
    version=str(ROOT / "assets" / "version_info.txt"),
    manifest=_manifest,
)

# ─────────────────────────────────────────────────────────────────────────
# Merged one-directory output
# ─────────────────────────────────────────────────────────────────────────
coll = COLLECT(
    launcher_exe,
    launcher_a.binaries,
    launcher_a.zipfiles,
    launcher_a.datas,
    cli_exe,
    cli_a.binaries,
    cli_a.zipfiles,
    cli_a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="AutoForensics",
)
