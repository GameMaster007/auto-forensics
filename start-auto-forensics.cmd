@echo off
setlocal

cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
  echo [Auto Forensics] Creating local virtual environment...
  py -3 -m venv .venv
  if errorlevel 1 goto :error
)

call ".venv\Scripts\activate.bat"
if errorlevel 1 goto :error

python -c "import auto_forensics, fastapi, uvicorn" >nul 2>&1
if errorlevel 1 (
  echo [Auto Forensics] Installing runtime dependencies...
  python -m pip install -e ".[server]"
  if errorlevel 1 goto :error
)

echo [Auto Forensics] Starting dashboard at http://127.0.0.1:8765/
python -m auto_forensics.cli start --host 127.0.0.1 --port 8765
exit /b 0

:error
echo [Auto Forensics] Startup failed.
pause
exit /b 1
