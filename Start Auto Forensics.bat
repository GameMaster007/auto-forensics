@echo off
rem Double-click to set up (first time only) and open the Auto Forensics review page.
setlocal
cd /d "%~dp0"
title Auto Forensics

set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY (where python >nul 2>nul && set "PY=python")
if not defined PY (
  echo Python 3.10 or newer is needed. Install it from https://www.python.org/downloads/
  echo and tick "Add python.exe to PATH" during setup, then double-click this file again.
  pause
  exit /b 1
)

%PY% -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)"
if errorlevel 1 (
  echo Your Python is older than 3.10. Install a newer one from https://www.python.org/downloads/
  pause
  exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
  echo First run: setting up. This takes a few minutes and needs the internet once.
  %PY% -m venv .venv || (echo Could not create the .venv folder. & pause & exit /b 1)
)

set "VPY=.venv\Scripts\python.exe"
fc /b pyproject.toml .venv\installed-pyproject.toml >nul 2>nul
if errorlevel 1 (
  "%VPY%" -m pip install --upgrade pip >nul
  "%VPY%" -m pip install -e ".[evtx,server,disk,yara]"
  if errorlevel 1 (
    echo YARA support could not be installed; continuing without it.
    "%VPY%" -m pip install -e ".[evtx,server,disk]" || (echo Setup failed. Read the messages above. & pause & exit /b 1)
  )
  copy /y pyproject.toml .venv\installed-pyproject.toml >nul
)

echo.
echo Starting the review page. Your browser will open. Keep this window open while you work.
"%VPY%" -m auto_forensics_autopilot.cli serve %*
pause
