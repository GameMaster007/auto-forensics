#!/usr/bin/env bash
# Set up (first time only) and open the Auto Forensics review page.
# Linux: run ./start-auto-forensics.sh   macOS: double-click "Start Auto Forensics.command"
set -euo pipefail
cd "$(dirname "$0")"

PY=""
for candidate in python3.13 python3.12 python3.11 python3.10 python3 python; do
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
    PY="$candidate"; break
  fi
done
if [ -z "$PY" ]; then
  echo "Python 3.10 or newer is needed. Install it (https://www.python.org/downloads/ or your package manager) and run this again."
  exit 1
fi

if [ ! -x .venv/bin/python ]; then
  echo "First run: setting up. This takes a few minutes and needs the internet once."
  "$PY" -m venv .venv || { echo "Could not create .venv (on Debian/Ubuntu: sudo apt install python3-venv)."; exit 1; }
fi

if ! cmp -s pyproject.toml .venv/installed-pyproject.toml; then
  .venv/bin/python -m pip install --upgrade pip >/dev/null
  if ! .venv/bin/python -m pip install -e ".[evtx,server,yara]"; then
    echo "YARA support could not be installed; continuing without it."
    .venv/bin/python -m pip install -e ".[evtx,server]"
  fi
  cp pyproject.toml .venv/installed-pyproject.toml
fi

echo
echo "Starting the review page. Your browser will open. Keep this window open while you work."
exec .venv/bin/python -m auto_forensics_autopilot.cli serve "$@"
