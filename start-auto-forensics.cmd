@echo off
setlocal EnableDelayedExpansion
title Auto Forensics

:: UTF-8 output so Unicode doesn't corrupt
chcp 65001 >nul 2>&1
set PYTHONUTF8=1

cd /d "%~dp0"

echo.
echo  +--------------------------------------------------+
echo  ^|   Auto Forensics  --  Autonomous Forensic AI    ^|
echo  +--------------------------------------------------+
echo.

:: ─── Virtual environment ────────────────────────────────────────────────────
if not exist ".venv\Scripts\python.exe" (
    echo [*] Creating virtual environment...
    py -3 -m venv .venv
    if errorlevel 1 (
        echo [!] Failed to create virtual environment. Is Python 3 installed?
        goto :error
    )
    echo [*] Virtual environment created.
)

call ".venv\Scripts\activate.bat"
if errorlevel 1 goto :error

:: ─── Dependencies ───────────────────────────────────────────────────────────
python -c "import auto_forensics, fastapi, uvicorn, rich" >nul 2>&1
if errorlevel 1 (
    echo [*] Installing dependencies...
    python -m pip install -e ".[server]" --quiet
    if errorlevel 1 goto :error
    echo [*] Dependencies installed.
)

:: ─── Agent mode: Case folder present ─────────────────────────────────────
if exist "Case\" (
    echo [*] Case folder detected: Case\
    echo [*] Running autonomous forensic agent...
    echo.
    auto-forensics solve --disable-llama
    goto :done
)

:: Named case folders (Case-M57, Case-Jean, etc.)
for /d %%D in (Case*) do (
    echo [*] Case folder detected: %%D
    echo [*] Running autonomous forensic agent...
    echo.
    auto-forensics solve --case-dir "%%D" --disable-llama
    goto :done
)

:: ─── Server mode ─────────────────────────────────────────────────────────
echo [*] Starting API server on http://127.0.0.1:8765
echo [*] Dashboard : http://127.0.0.1:8765
echo [*] API docs  : http://127.0.0.1:8765/docs
echo.

:: Open browser after a short delay
start "" cmd /c "timeout /t 2 >nul && start http://127.0.0.1:8765"

auto-forensics serve --host 127.0.0.1 --port 8765
goto :done

:done
echo.
echo [*] Done. Press any key to close...
pause >nul
exit /b 0

:error
echo.
echo [!] Startup failed. See error above.
pause
exit /b 1
