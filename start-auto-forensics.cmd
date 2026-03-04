@echo off
setlocal EnableDelayedExpansion
title Auto Forensics

cd /d "%~dp0"

echo.
echo   Auto Forensics  ^|  Autonomous Forensic AI
echo   ─────────────────────────────────────────
echo.

:: ── Prefer the PyInstaller-built GUI launcher ─────────────────────────────
if exist "dist\AutoForensics\AutoForensics.exe" (
    echo [*] Launching installed application...
    start "" "dist\AutoForensics\AutoForensics.exe" %*
    exit /b 0
)

:: ── Fall back to the Python source launcher ───────────────────────────────
if not exist ".venv\Scripts\python.exe" (
    echo [*] Creating virtual environment...
    py -3 -m venv .venv
    if errorlevel 1 goto :error
)

call ".venv\Scripts\activate.bat"
if errorlevel 1 goto :error

python -c "import auto_forensics, fastapi, uvicorn" >nul 2>&1
if errorlevel 1 (
    echo [*] Installing runtime dependencies...  (first run only)
    python -m pip install -q -e ".[server]"
    if errorlevel 1 goto :error
)

:: Check for pystray (tray icon support) — install silently if absent
python -c "import pystray, PIL" >nul 2>&1
if errorlevel 1 (
    echo [*] Installing system-tray support...
    python -m pip install -q pystray Pillow
)

:: ─── Agent mode: if a Case folder exists, solve it autonomously ──────────
if exist "Case\" (
    echo [*] Case folder detected — launching autonomous agent...
    echo.
    auto-forensics solve
    goto :done
)
for /d %%D in (Case*) do (
    echo [*] Case folder detected: %%D
    echo [*] Launching autonomous agent...
    echo.
    auto-forensics solve --case-dir "%%D"
    goto :done
)

:: ─── GUI launcher: server + tray icon + auto browser ─────────────────────
echo [*] Starting server with system-tray launcher...
echo [*] Dashboard: http://127.0.0.1:8765/
echo.
python -m auto_forensics.launcher %*
goto :done

:done
echo.
echo [*] Done.  Press any key to close...
pause >nul
exit /b 0

:error
echo.
echo [!] Startup failed.  See error above.
pause
exit /b 1
