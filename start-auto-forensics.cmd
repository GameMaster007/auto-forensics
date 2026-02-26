@echo off
setlocal
title Auto Forensics — AI Agent

cd /d "%~dp0"

echo.
echo  ██████████╗  Auto Forensics
echo  ██╔═══════╝  Autonomous Forensic AI
echo  ██████╗      v1.0
echo  ██╔══╝
echo  ██║
echo  ╚═╝
echo.

if not exist ".venv\Scripts\python.exe" (
  echo [*] Creating local virtual environment...
  py -3 -m venv .venv
  if errorlevel 1 goto :error
)

call ".venv\Scripts\activate.bat"
if errorlevel 1 goto :error

python -c "import auto_forensics, fastapi, uvicorn, rich" >nul 2>&1
if errorlevel 1 (
  echo [*] Installing runtime dependencies...  (first run only)
  python -m pip install -e ".[server]" --quiet
  if errorlevel 1 goto :error
)

:: ─── Agent mode: if a Case folder exists, solve it autonomously ───────────
if exist "Case\" (
  echo [*] Case folder detected: Case\
  echo [*] Launching autonomous forensic agent...
  echo.
  auto-forensics solve
  goto :done
)

:: Named Case folders: Case-M57, CaseJean, etc.
for /d %%D in (Case*) do (
  echo [*] Case folder detected: %%D
  echo [*] Launching autonomous forensic agent...
  echo.
  auto-forensics solve --case-dir "%%D"
  goto :done
)

:: ─── Server mode: no Case folder found ───────────────────────────────────
echo [*] No Case folder found — starting API server on http://127.0.0.1:8765
echo [*] Docs: http://127.0.0.1:8765/docs
echo.
auto-forensics serve --host 127.0.0.1 --port 8765
goto :done

:done
echo.
echo [*] Done.  Press any key to close...
pause >nul
exit /b 0

:error
echo.
echo [!] Auto Forensics startup failed.  See error above.
pause
exit /b 1
