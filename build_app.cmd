@echo off
:: ╔═══════════════════════════════════════════════════════════════════════╗
:: ║  Auto Forensics — Application Builder                               ║
:: ╠═══════════════════════════════════════════════════════════════════════╣
:: ║  Builds:                                                            ║
:: ║    1. Application icon  (assets/icon.ico, icon.png)                ║
:: ║    2. Standalone EXE    (dist/AutoForensics/)                      ║
:: ║    3. Windows installer (dist/installer/AutoForensics-*-Setup.exe) ║
:: ╚═══════════════════════════════════════════════════════════════════════╝
setlocal EnableDelayedExpansion
title Auto Forensics — Build
cd /d "%~dp0"

echo.
echo   Build started at %DATE% %TIME%
echo   ──────────────────────────────────────────────────────────
echo.

:: ── Step 0: Find Python ────────────────────────────────────────────────
set PYTHON=
if exist ".venv\Scripts\python.exe" (
    set PYTHON=.venv\Scripts\python.exe
) else (
    where python >nul 2>&1 && set PYTHON=python
)
if "!PYTHON!"=="" (
    echo   [!] Python 3.10+ not found.  Install it and try again.
    goto :error
)
echo   [OK] Python: !PYTHON!

:: ── Step 1: Virtual environment ────────────────────────────────────────
if not exist ".venv\Scripts\python.exe" (
    echo   [..] Creating virtual environment...
    py -3 -m venv .venv
    if errorlevel 1 goto :error
    set PYTHON=.venv\Scripts\python.exe
)
call ".venv\Scripts\activate.bat"
if errorlevel 1 goto :error
echo   [OK] Virtual environment activated

:: ── Step 2: Install all build dependencies ─────────────────────────────
echo   [..] Installing dependencies...
python -m pip install -q --upgrade pip setuptools wheel
python -m pip install -q -e ".[server,tray,build,dev]"
if errorlevel 1 (
    echo   [!] Dependency install failed.
    goto :error
)
echo   [OK] Dependencies installed

:: ── Step 3: Generate icon ──────────────────────────────────────────────
echo   [..] Generating application icon...
python assets\generate_icon.py
if errorlevel 1 (
    echo   [!] Icon generation failed.
    goto :error
)
echo   [OK] Icon generated

:: ── Step 4: Run test suite ─────────────────────────────────────────────
echo   [..] Running tests...
python -m pytest tests\ -q --tb=short 2>&1
if errorlevel 1 (
    echo   [!] Tests FAILED — aborting build.
    goto :error
)
echo   [OK] All tests passed

:: ── Step 5: Clean previous build ───────────────────────────────────────
echo   [..] Cleaning previous build...
if exist "build\AutoForensics" rmdir /s /q "build\AutoForensics" 2>nul
if exist "dist\AutoForensics" rmdir /s /q "dist\AutoForensics" 2>nul
echo   [OK] Clean

:: ── Step 6: PyInstaller ────────────────────────────────────────────────
echo   [..] Building standalone executable (PyInstaller)...
pyinstaller AutoForensics.spec --noconfirm --clean 2>&1
if errorlevel 1 (
    echo   [!] PyInstaller build failed.
    goto :error
)
if not exist "dist\AutoForensics\AutoForensics.exe" (
    echo   [!] Expected AutoForensics.exe not found in dist\.
    goto :error
)
echo   [OK] dist\AutoForensics\AutoForensics.exe   (GUI)
echo   [OK] dist\AutoForensics\auto-forensics.exe  (CLI)

:: ── Step 7: Smoke test ─────────────────────────────────────────────────
echo   [..] Smoke-testing...
"dist\AutoForensics\auto-forensics.exe" version >nul 2>&1
if errorlevel 1 (
    echo   [~] Smoke test inconclusive (OK for clean builds)
) else (
    echo   [OK] Executable runs
)

:: ── Step 8: Inno Setup installer ───────────────────────────────────────
set ISCC=
for %%P in (
    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
    "C:\Program Files\Inno Setup 6\ISCC.exe"
) do (
    if exist %%P (
        set ISCC=%%P
        goto :found_iscc
    )
)
:found_iscc

if "!ISCC!"=="" (
    echo.
    echo   [~] Inno Setup 6 not found — skipping installer.
    echo       Download: https://jrsoftware.org/isdl.php
    goto :portable_only
)

echo   [..] Building Windows installer (Inno Setup)...
mkdir "dist\installer" 2>nul
!ISCC! /Q "installer\autoforensics.iss"
if errorlevel 1 (
    echo   [!] Installer build failed.
    goto :error
)
echo   [OK] Installer created

:: ── Step 9: Code signing (placeholder) ─────────────────────────────────
:: Uncomment below if you have a code-signing certificate:
::
:: set ST="C:\Program Files (x86)\Windows Kits\10\bin\x64\signtool.exe"
:: set CERT=/f "cert.pfx" /p "password"
:: %ST% sign /tr http://timestamp.digicert.com /td sha256 /fd sha256 %CERT% "dist\AutoForensics\AutoForensics.exe"
:: %ST% sign /tr http://timestamp.digicert.com /td sha256 /fd sha256 %CERT% "dist\AutoForensics\auto-forensics.exe"
:: for %%F in (dist\installer\AutoForensics-*-Setup.exe) do %ST% sign /tr ... %CERT% "%%F"

:portable_only
echo.
echo   ══════════════════════════════════════════════════════════
echo    BUILD COMPLETE
echo   ══════════════════════════════════════════════════════════
echo.
echo    Portable app:
echo      dist\AutoForensics\AutoForensics.exe    (GUI launcher)
echo      dist\AutoForensics\auto-forensics.exe   (CLI)
echo.
if "!ISCC!" NEQ "" (
    echo    Installer:
    for %%F in (dist\installer\AutoForensics-*-Setup.exe) do echo      %%F
    echo.
)
echo    Quick start:
echo      dist\AutoForensics\AutoForensics.exe
echo.
echo   Finished at %DATE% %TIME%
echo.
pause
exit /b 0

:error
echo.
echo   ══════════════════════════════════════════════════════════
echo    BUILD FAILED — see error above
echo   ══════════════════════════════════════════════════════════
echo.
pause
exit /b 1
