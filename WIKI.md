# Auto Forensics — Project Wiki

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Installation](#installation)
4. [Building the Desktop App](#building-the-desktop-app)
5. [Using the Desktop App](#using-the-desktop-app)
6. [Configuration](#configuration)
7. [CLI Reference](#cli-reference)
8. [API Reference](#api-reference)
9. [Web Dashboard](#web-dashboard)
10. [Architecture](#architecture)
11. [Pipeline Internals](#pipeline-internals)
12. [Artifact Parsers](#artifact-parsers)
13. [Detection & Analysis](#detection--analysis)
14. [IOC Extraction & Enrichment](#ioc-extraction--enrichment)
15. [Database](#database)
16. [Security Model](#security-model)
17. [Plugin System](#plugin-system)
18. [Reports & Exports](#reports--exports)
19. [Shell Integration](#shell-integration)
20. [Deployment](#deployment)
21. [Testing](#testing)
22. [Troubleshooting](#troubleshooting)
23. [Changelog](#changelog)

---

## Overview

Auto Forensics is a Python-based, forensic analysis platform designed for incident response and malware investigation. It ingests evidence (Windows Event Logs, PCAPs, prefetch files, registry hives, memory images, MFT records, and binary executables), runs a multi-stage analysis pipeline, and produces structured findings, MITRE ATT&CK-mapped timeline events, and IOC lists — all available via a CLI, REST API, and web dashboard.

**Key capabilities:**

- Parses 10+ forensic artifact types out of the box
- Detects indicators via YARA rules, Sigma rules, and heuristic event detectors
- Maps findings to MITRE ATT&CK techniques automatically
- Extracts IPs, domains, URLs, file hashes as IOCs
- Optionally enriches IOCs through VirusTotal, MalwareBazaar, AbuseIPDB, and WHOIS
- Generates HTML, Markdown, PDF, ATT&CK Navigator JSON, and STIX 2.1 bundle reports
- Exposes a RESTful API (FastAPI) and browser dashboard
- Supports SQLite (default) and PostgreSQL backends
- Extensible via a plugin registry
- Runs as a proper Windows desktop app with system tray, installer, and Explorer integration

**No mandatory runtime dependencies** — all integrations (YARA, Sigma, EVTX parsing, LLM, enrichment) are optional and gracefully skipped if the library is absent.

---

## Quick Start

### Option A — Windows Installer (recommended)

1. Download `AutoForensics-1.0.0-Setup.exe` from the Releases page.
2. Run the installer. Choose your options (desktop shortcut, context menus, PATH).
3. Launch **Auto Forensics** from the Start Menu or desktop.
4. The dashboard opens automatically at `http://127.0.0.1:8765/`.

### Option B — Portable EXE (no install)

1. Download and extract `AutoForensics-1.0.0-Portable.zip`.
2. Double-click `AutoForensics.exe`.
3. The splash screen appears, server starts, and the dashboard opens.

### Option C — From source (developers)

```bash
git clone https://github.com/auto-forensics/auto-forensics.git
cd auto-forensics
python -m venv .venv
.venv/Scripts/activate        # Windows
# source .venv/bin/activate   # Linux
pip install -e ".[server,dev]"
auto-forensics serve
```

### Option D — One-click script

Double-click `start-auto-forensics.cmd` in the project root. It creates a venv, installs dependencies, and launches the app with a system-tray icon.

---

## Installation

### Requirements

- Python 3.10 – 3.12 (if running from source)
- Windows 10/11 (for desktop app features; CLI and server work on Linux too)

### Install from source

```bash
# Core (CLI only — no server, no GUI)
pip install -e .

# CLI + API server + web dashboard
pip install -e ".[server]"

# Full development setup
pip install -e ".[server,dev]"

# Desktop GUI with system-tray support
pip install -e ".[server,tray]"
```

### Optional extras

| Extra | What it enables | Packages |
|---|---|---|
| `server` | API server + web dashboard | fastapi, uvicorn |
| `tray` | System-tray launcher, splash screen | pystray, Pillow |
| `build` | Building standalone executables | pyinstaller |
| `dev` | Running tests | pytest |
| `pe` | PE binary analysis | pefile |
| `evtx` | Windows Event Log parsing | python-evtx |
| `pcap` | PCAP parsing | dpkt |
| `registry` | Registry hive parsing | python-registry |
| `yara` | YARA rule scanning | yara-python |
| `sigma` | Sigma rule evaluation | pyyaml |
| `memory` | Memory dump analysis | volatility3 |
| `pdf` | PDF report export | reportlab |
| `db` | PostgreSQL + SQLAlchemy backend | sqlalchemy, psycopg |
| `mount` | Disk image mounting | pyewf, pytsk3 |

Install multiple extras at once:

```bash
pip install -e ".[server,tray,pe,evtx,yara,sigma]"
```

### Verify installation

```bash
auto-forensics version          # prints version
auto-forensics config           # shows all data paths
auto-forensics serve            # starts the server
```

---

## Building the Desktop App

The build system produces two outputs:

| Output | Description |
|---|---|
| `dist/AutoForensics/AutoForensics.exe` | GUI launcher (no console window) |
| `dist/AutoForensics/auto-forensics.exe` | CLI tool (console window) |
| `dist/installer/AutoForensics-1.0.0-Setup.exe` | Full Windows installer |

### Prerequisites

| Tool | Required? | Download |
|---|---|---|
| Python 3.10+ | Yes | https://python.org |
| Inno Setup 6 | Optional (for installer) | https://jrsoftware.org/isdl.php |
| UPX | Optional (smaller binaries) | https://upx.github.io |

### One-command build

```cmd
build_app.cmd
```

This script runs the full pipeline:

1. Creates/activates a virtual environment
2. Installs all build dependencies (`.[server,tray,build,dev]`)
3. Generates the application icon (`assets/icon.ico`, `icon.png`)
4. Runs the full test suite (aborts on failure)
5. Cleans previous build artifacts
6. Runs PyInstaller to create standalone executables
7. Smoke-tests the built exe
8. Runs Inno Setup to create the installer (if installed)
9. Reports output paths

### Manual build steps

If you prefer to run each step individually:

```cmd
:: 1. Activate venv
.venv\Scripts\activate

:: 2. Install deps
pip install -e ".[server,tray,build,dev]"

:: 3. Generate icon
python assets\generate_icon.py

:: 4. Run tests
python -m pytest tests/ -q

:: 5. Build with PyInstaller
pyinstaller AutoForensics.spec --noconfirm --clean

:: 6. Build installer (optional)
"C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer\autoforensics.iss
```

### Build outputs

```
dist/
├── AutoForensics/            ← Portable app (self-contained)
│   ├── AutoForensics.exe     ← GUI launcher (double-click to run)
│   ├── auto-forensics.exe    ← CLI tool
│   ├── assets/
│   │   ├── icon.ico
│   │   └── icon.png
│   ├── auto_forensics/
│   │   └── web/              ← Dashboard HTML/CSS/JS
│   └── (Python runtime + all dependencies bundled)
│
└── installer/
    └── AutoForensics-1.0.0-Setup.exe  ← Windows installer
```

### Code signing (optional)

To sign the executables and installer, uncomment the signing section in `build_app.cmd` and provide your certificate path and password:

```cmd
set ST="C:\Program Files (x86)\Windows Kits\10\bin\x64\signtool.exe"
set CERT=/f "your-cert.pfx" /p "password"
%ST% sign /tr http://timestamp.digicert.com /td sha256 /fd sha256 %CERT% "dist\AutoForensics\AutoForensics.exe"
```

### Customising the build

| File | What to edit |
|---|---|
| `assets/version_info.txt` | Windows VERSIONINFO (shown in Properties → Details) |
| `assets/AutoForensics.manifest` | DPI awareness, UAC settings, Windows version support |
| `assets/generate_icon.py` | Icon design (colours, shapes) |
| `AutoForensics.spec` | PyInstaller configuration (hidden imports, excludes, etc.) |
| `installer/autoforensics.iss` | Installer pages, tasks, registry entries |

---

## Using the Desktop App

### Launching

| Method | What happens |
|---|---|
| Double-click `AutoForensics.exe` | Splash screen → server starts → browser opens → tray icon appears |
| Start Menu → Auto Forensics | Same as above (installed version) |
| `auto-forensics-launcher` | Same (if installed via pip) |
| `start-auto-forensics.cmd` | Prefers built exe, falls back to Python source |

### System tray

When running, Auto Forensics appears in the Windows system tray (notification area). Right-click the icon to see:

| Menu item | Action |
|---|---|
| **Auto Forensics — Running** | Status indicator (Starting / Running / Error) |
| **Open Dashboard** | Opens `http://127.0.0.1:8765/` in your browser (also triggered by double-clicking the tray icon) |
| **Open Data Directory** | Opens `~/.auto_forensics/` in Explorer — where cases, rules, and the database live |
| **Open Log File** | Opens the log file in your default text editor |
| **Start with Windows** | Toggle — adds/removes the app from Windows startup (HKCU Run key) |
| **About** | Shows version, server URL, data paths |
| **Quit** | Gracefully stops the server and exits |

### Command-line options

```
auto-forensics-launcher [options]

Options:
  --host HOST       Bind address (default: 127.0.0.1)
  --port PORT       Bind port (default: 8765)
  --no-browser      Don't auto-open the browser
  --no-tray         Run without system tray (headless/console mode)
  --no-splash       Skip the splash screen
  --version         Show version and exit
```

### Single-instance enforcement

Only one instance of Auto Forensics can run at a time. If you try to launch a second copy:
- **GUI mode**: a dialog says "Auto Forensics is already running. Check the system tray."
- **Console mode**: prints the same message to stderr and exits.

### Logging

All activity is logged to a rotating log file:

```
%APPDATA%\Auto Forensics\logs\auto_forensics.log
```

- Maximum 5 MB per file, 3 backup files kept (`auto_forensics.log.1`, `.2`, `.3`)
- Accessible from the tray menu → "Open Log File"
- Includes server requests, analysis progress, errors, and startup diagnostics

### Crash handling

If the app hits an unhandled exception:
- The error is logged to the log file
- A Windows error dialog shows the exception message
- The app exits cleanly

### Notifications

Auto Forensics shows Windows balloon-tip notifications for:
- Server ready (with the dashboard URL)
- Server errors

---

## Configuration

All settings are read from environment variables via `AppConfig.from_env()`. The defaults are sensible for local development.

| Environment Variable | Default | Description |
|---|---|---|
| `AUTO_FORENSICS_HOME` | `~/.auto_forensics` | Root data directory |
| `AUTO_FORENSICS_HOST` | `127.0.0.1` | API bind host |
| `AUTO_FORENSICS_PORT` | `8765` | API bind port |
| `AUTO_FORENSICS_ENV` | `dev` | Set to `prod` to enable production hardening |
| `AUTO_FORENSICS_API_KEY` | *(none)* | API key; SHA-256 hash stored internally |
| `AUTO_FORENSICS_ALLOWED_ORIGINS` | *(none)* | Comma-separated CORS origins |
| `AUTO_FORENSICS_TRUSTED_HOSTS` | `127.0.0.1,localhost` | Trusted Host middleware |
| `AUTO_FORENSICS_ALLOWED_INGEST_ROOTS` | `~` | Paths from which evidence may be ingested |
| `AUTO_FORENSICS_RATE_LIMIT_PER_MINUTE` | `240` | Per-IP rate limit |
| `AUTO_FORENSICS_LLAMA_ENDPOINT` | `http://localhost:11434` | Ollama endpoint |
| `AUTO_FORENSICS_LLAMA_MODEL` | `llama3.1:8b` | Ollama model name |
| `AUTO_FORENSICS_OPENAI_ENDPOINT` | *(none)* | OpenAI-compatible endpoint base URL |
| `AUTO_FORENSICS_OPENAI_API_KEY` | *(none)* | API key for OpenAI-compatible endpoint |
| `AUTO_FORENSICS_DATABASE_URL` | *(SQLite)* | PostgreSQL URL, e.g. `postgresql://user:pw@host/db` |
| `AUTO_FORENSICS_RULES_DIR` | `$HOME/rules` | YARA rules directory |
| `AUTO_FORENSICS_SIGMA_RULES_DIR` | `$RULES_DIR/sigma` | Sigma rules directory |
| `AUTO_FORENSICS_ATTACK_STIX_PATH` | `$HOME/attack/enterprise-attack.json` | ATT&CK STIX bundle |
| `AUTO_FORENSICS_VIRUSTOTAL_API_KEY` | *(none)* | VirusTotal v3 API key |
| `AUTO_FORENSICS_MALWAREBAZAAR_API_KEY` | *(none)* | MalwareBazaar API key |
| `AUTO_FORENSICS_ABUSEIPDB_API_KEY` | *(none)* | AbuseIPDB v2 API key |
| `AUTO_FORENSICS_ENABLE_WHOIS` | `false` | Enable WHOIS lookups for domains |
| `AUTO_FORENSICS_ENRICHMENT_CACHE_TTL_MINUTES` | `1440` (24 h) | IOC enrichment cache TTL |
| `AUTO_FORENSICS_MAX_FILE_SIZE_BYTES` | `104857600` (100 MB) | Maximum single file size |
| `AUTO_FORENSICS_MAX_TOTAL_FILES` | `200000` | Maximum files per case |
| `AUTO_FORENSICS_MAX_TEXT_BYTES` | `4194304` (4 MB) | Maximum text bytes read per file |
| `AUTO_FORENSICS_JOB_RETENTION_DAYS` | `30` | Job history retention window |
| `AUTO_FORENSICS_PLUGIN_DIRS` | `$HOME/plugins` | Plugin directories |

### Setting environment variables

#### Windows PowerShell

```powershell
$env:AUTO_FORENSICS_ENV = "prod"
$env:AUTO_FORENSICS_API_KEY = "your-secret-key"
$env:AUTO_FORENSICS_VIRUSTOTAL_API_KEY = "your-vt-key"
auto-forensics serve
```

#### Windows permanently (System Properties)

1. Press `Win + R`, type `sysdm.cpl`, press Enter.
2. Go to **Advanced** → **Environment Variables**.
3. Under **User variables**, click **New**.
4. Enter the variable name (e.g. `AUTO_FORENSICS_API_KEY`) and value.

#### Linux

```bash
export AUTO_FORENSICS_ENV=prod
export AUTO_FORENSICS_API_KEY='your-secret-key'
auto-forensics serve
```

### OpenAI-compatible endpoint

The `AUTO_FORENSICS_OPENAI_ENDPOINT` must be the base URL **including** any version path up to (but not including) `/chat/completions`:

| Provider | Endpoint value |
|---|---|
| OpenAI | `https://api.openai.com/v1` |
| Gemini | `https://generativelanguage.googleapis.com/v1beta/openai` |
| LM Studio | `http://localhost:1234/v1` |
| Ollama (OpenAI mode) | `http://localhost:11434/v1` |

---

## CLI Reference

```
auto-forensics <command> [options]
```

### Case lifecycle

| Command | Description | Example |
|---|---|---|
| `init` | Create a new case workspace | `auto-forensics init --case-id case-001` |
| `ingest` | Copy and hash evidence into a case | `auto-forensics ingest --case-id case-001 --source-dir ./evidence` |
| `analyze` | Run analysis pipeline | `auto-forensics analyze --case-id case-001 [--disable-llama]` |
| `overview` | Print full case data as JSON | `auto-forensics overview --case-id case-001` |
| `report` | Export a report | `auto-forensics report --case-id case-001 --format md` |
| `enrich` | Trigger or check IOC enrichment | `auto-forensics enrich --case-id case-001 [--status]` |
| `list` | List all cases | `auto-forensics list [--json]` |
| `stats` | Show case count summary | `auto-forensics stats` |
| `delete` | Permanently delete a case | `auto-forensics delete --case-id case-001` |

### Standalone scanning

| Command | Description | Example |
|---|---|---|
| `scan` | Scan a single file | `auto-forensics scan --path suspicious.exe [--json]` |
| `scan-dir` | Scan all files in a directory | `auto-forensics scan-dir --path ./evidence [--json] [--no-recursive]` |

### Advanced analysis

| Command | Description | Example |
|---|---|---|
| `conclusions` | Generate forensic conclusions and risk verdicts | `auto-forensics conclusions --case-id case-001 [--json]` |
| `timeline-filter` | Filter timeline events | `auto-forensics timeline-filter --case-id case-001 --min-risk 50` |
| `iocs` | List and export IOCs | `auto-forensics iocs --case-id case-001 --export csv > iocs.csv` |

### Notes and audit

| Command | Description | Example |
|---|---|---|
| `notes` | List analyst notes | `auto-forensics notes --case-id case-001` |
| `add-note` | Add a note | `auto-forensics add-note --case-id case-001 --content "Checked AV logs"` |
| `audit` | View audit trail | `auto-forensics audit [--case-id case-001] [--json]` |

### File operations

| Command | Description | Example |
|---|---|---|
| `hash` | Compute file hashes | `auto-forensics hash --path file.exe --algo all` |
| `export` | Export case as signed zip archive | `auto-forensics export --case-id case-001 --dest ./archive.zip` |
| `import` | Import case from archive | `auto-forensics import --archive ./archive.zip` |

### Server and system

| Command | Description | Example |
|---|---|---|
| `serve` | Start API server and dashboard | `auto-forensics serve [--host 0.0.0.0] [--port 8765]` |
| `start` | Alias for `serve` | `auto-forensics start` |
| `config` | Show current configuration | `auto-forensics config` |
| `version` | Display version | `auto-forensics version` |
| `migrate` | Run or inspect DB migrations | `auto-forensics migrate [--status]` |
| `jobs` | List job history | `auto-forensics jobs --case-id case-001 [--type analysis]` |
| `cleanup-jobs` | Prune old job records | `auto-forensics cleanup-jobs [--retention-days 14]` |

### Autonomous agent

| Command | Description | Example |
|---|---|---|
| `solve` | Run the AI agent end-to-end | `auto-forensics solve [--case-dir ./Case]` |
| `watch` | Watch a drop directory for new evidence | `auto-forensics watch [--dir ./drop] [--interval 30]` |
| `extract` | Mount and extract a disk image | `auto-forensics extract --image disk.e01 [--output staging/]` |

### Shell integration (Windows)

| Command | Description | Example |
|---|---|---|
| `shell --install` | Register Explorer context menus | `auto-forensics shell --install` (needs admin) |
| `shell --uninstall` | Remove Explorer context menus | `auto-forensics shell --uninstall` (needs admin) |
| `shell --status` | Check registration status | `auto-forensics shell --status` |

### Full workflow example

```bash
# 1. Create case
auto-forensics init --case-id incident-2026-03

# 2. Ingest evidence
auto-forensics ingest --case-id incident-2026-03 --source-dir C:\Evidence\Server01

# 3. Analyse (without LLM — fast, offline)
auto-forensics analyze --case-id incident-2026-03 --disable-llama

# 4. View summary
auto-forensics overview --case-id incident-2026-03

# 5. Check conclusions
auto-forensics conclusions --case-id incident-2026-03

# 6. Filter high-risk timeline events
auto-forensics timeline-filter --case-id incident-2026-03 --min-risk 70

# 7. Export IOCs as CSV
auto-forensics iocs --case-id incident-2026-03 --export csv > iocs.csv

# 8. Generate reports (JSON + Markdown + HTML)
auto-forensics report --case-id incident-2026-03 --format md
auto-forensics report --case-id incident-2026-03 --format html

# 9. Archive the case
auto-forensics export --case-id incident-2026-03 --dest ./incident-2026-03.zip
```

---

## API Reference

Base URL: `http://127.0.0.1:8765`

All endpoints return JSON. If `AUTO_FORENSICS_API_KEY` is set, include the header:
```
X-API-Key: <your-api-key>
```

### Error format

```json
{"error": "error_type", "detail": "human-readable message", "status_code": 422}
```

### Health and admin

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/health` | Health check (`{"status": "ok"}`) |
| `GET` | `/api/stats` | Case counts by status |
| `GET` | `/api/admin/migrations` | Migration status |
| `POST` | `/api/admin/migrations` | Apply pending migrations |
| `POST` | `/api/admin/jobs/cleanup` | Prune old job records |

### Cases

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/cases` | Create a new case (`{"case_id": "..."}`) |
| `GET` | `/api/cases` | List cases (`?q=search&status=complete&limit=50`) |
| `GET` | `/api/cases/{id}` | Full case overview |
| `DELETE` | `/api/cases/{id}` | Delete a case permanently |
| `GET` | `/api/cases/{id}/search` | Full-text search (`?q=query&limit=20`) |
| `GET` | `/api/cases/{id}/jobs` | Job history (`?job_type=analysis&limit=50`) |

### Case workflow

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/cases/{id}/ingest` | Ingest evidence (`{"source_dir": "..."}`) |
| `POST` | `/api/cases/{id}/analyze` | Synchronous analysis |
| `POST` | `/api/cases/{id}/analyze/async` | Async analysis (returns job ID) |
| `GET` | `/api/cases/{id}/status` | Poll analysis status (`?stream=true` for SSE) |
| `POST` | `/api/cases/{id}/enrich/async` | Async IOC enrichment |
| `GET` | `/api/cases/{id}/enrich/status` | Poll enrichment status (`?stream=true` for SSE) |

### Reports and export

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/cases/{id}/report` | Get report (`?fmt=json\|md\|html\|navigator\|stix`) |
| `POST` | `/api/cases/{id}/export` | Export case as signed ZIP |
| `POST` | `/api/cases/import` | Import case from signed ZIP |

### Notes

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/cases/{id}/notes` | List analyst notes |
| `POST` | `/api/cases/{id}/notes` | Add analyst note (`{"content": "...", "author": "..."}`) |

---

## Web Dashboard

The dashboard is served at `http://127.0.0.1:8765/` and provides:

- **Health indicator** — green dot when connected, red when unreachable
- **Stats cards** — total cases, complete, analysing, failed, ready
- **Case list** — searchable and filterable by status
- **Case detail drawer** — click a row to see:
  - Overview (status, timestamps, counts)
  - Findings (sorted by severity, colour-coded)
  - IOCs (IPs, domains, hashes, URLs)
  - Artifacts list
- **Auto-refresh** — polls every 30 seconds

The dashboard is a single HTML page with no build step — edit `src/auto_forensics/web/dashboard.html`, `.css`, `.js` directly.

---

## Architecture

```
src/auto_forensics/
├── api.py              # FastAPI application, all HTTP endpoints
├── cli.py              # argparse CLI (entry point: auto-forensics)
├── launcher.py         # GUI launcher with system tray, splash, notifications
├── shell_integration.py# Windows Explorer context menus and file associations
├── config.py           # AppConfig dataclass, env var loading
├── service.py          # AutoForensicsService — orchestration layer
├── pipeline.py         # run_case() — single-pass analysis pipeline
├── plugins.py          # Plugin registries (parsers, detectors, enrichers)
├── artifacts.py        # All artifact loaders (CSV, JSON, TXT, EVTX, PCAP, ...)
├── binary_analysis.py  # PE/ELF heuristics, entropy, string extraction
├── event_detectors.py  # Windows event ID -> Finding mappings
├── yara_detector.py    # YARA rule loading and scanning
├── sigma_rules.py      # Sigma YAML rule evaluation against timeline
├── attack_mapper.py    # STIX ATT&CK technique lookup + keyword fallback
├── ioc_pipeline.py     # IOC extraction from findings, timeline, binaries
├── ioc_enrichment.py   # HTTP enrichment clients (VT, MBAZAAR, ABUSEIPDB)
├── case_manager.py     # Filesystem case directory management
├── agent.py            # Autonomous AI forensic agent
├── watcher.py          # Drop-directory watcher
├── disk_image.py       # Disk image mounting and extraction
├── db.py               # SQLite database backend
├── db_sqlalchemy.py    # PostgreSQL / SQLAlchemy backend
├── db_backend.py       # Abstract DatabaseBackend protocol
├── models.py           # Dataclasses: Finding, TimelineEvent, IOC, ...
├── security.py         # SecurityPolicy, confine_path, validate_case_id
├── stix_export.py      # STIX 2.1 bundle generation
├── pdf_report.py       # PDF report generation (reportlab optional)
├── llama_workflow.py   # Ollama/OpenAI-compatible LLM analysis workflow
├── migrations.py       # Database schema migrations
└── web/                # Static dashboard assets (HTML, CSS, JS)

assets/                 # Application icon and build metadata
├── generate_icon.py    # Icon generator (pure Python, no deps)
├── icon.ico            # Windows icon (generated)
├── icon.png            # PNG icon (generated)
├── version_info.txt    # VERSIONINFO resource for the exe
└── AutoForensics.manifest  # DPI awareness + UAC manifest

installer/
└── autoforensics.iss   # Inno Setup 6 installer script

AutoForensics.spec      # PyInstaller build spec
build_app.cmd           # One-click build script
start-auto-forensics.cmd# One-click launcher script
```

### Entry points

| Entry point | Module | Description |
|---|---|---|
| `auto-forensics` | `auto_forensics.cli:main` | CLI (30+ subcommands) |
| `auto-forensics-api` | `auto_forensics.api:main` | API server (same as `serve`) |
| `auto-forensics-launcher` | `auto_forensics.launcher:main` | GUI launcher with tray |

### Data flow

```
CLI / API / Launcher
      |
      v
AutoForensicsService
      |  uses
      +-> CaseManager        -> filesystem dirs
      +-> Database           -> SQLite / PostgreSQL
      +-> run_case()         -> PipelineConfig
               |
               +-> discover_artifacts()   -> ArtifactEvent list
               +-> binary_analysis()      -> BinaryFeature list
               +-> findings_from_events() -> Finding list
               +-> YARA scan             -> Finding list
               +-> Sigma evaluation      -> Finding list
               +-> ATT&CK mapping        -> enriched findings
               +-> normalize_timeline()  -> TimelineEvent list
               +-> extract_iocs()        -> IOC list
               +-> enrich_iocs()         -> IOCEnrichment list
               +-> write reports         -> JSON / MD / HTML / PDF / STIX
```

### Concurrency

- **Analysis jobs**: `ThreadPoolExecutor(max_workers=4)`, guarded by `_analysis_lock`
- **Enrichment jobs**: `ThreadPoolExecutor(max_workers=2)`, guarded by `_enrichment_lock`
- Both job types persist state to the database and in-memory dicts for fast polling

### Case directory layout

```
~/.auto_forensics/
├── cases/
│   └── {case_id}/
│       ├── evidence/              <- ingested files
│       └── output/                <- generated reports
│           ├── case_report.json
│           ├── case_report.md
│           ├── case_report.html
│           ├── case_report.pdf
│           ├── attack_navigator_layer.json
│           └── case_stix_bundle.json
├── plugins/                       <- external plugins
├── rules/                         <- YARA rules
│   └── sigma/                     <- Sigma rules
├── attack/
│   └── enterprise-attack.json     <- MITRE ATT&CK bundle
└── app.db                         <- SQLite database
```

---

## Pipeline Internals

`run_case(config: PipelineConfig) -> CaseReport`

1. **Artifact discovery** — walks the evidence directory, dispatches each file to the matching parser, collects `ArtifactEvent` list and binary paths.
2. **Binary analysis** — computes entropy, extracts strings, checks PE/ELF magic, scores suspicious indicators (0-10).
3. **YARA scan** — applies compiled rules from `rules_dir`.
4. **Event detection** — maps Windows event IDs to ATT&CK techniques (30 event IDs covered).
5. **Sigma evaluation** — loads YAML rules, counts keyword matches against timeline events.
6. **ATT&CK mapping** — resolves technique IDs against the STIX bundle.
7. **LLM workflow** (optional) — sends binary summaries to Ollama/OpenAI for AI triage.
8. **Timeline normalisation** — merges events, assigns risk scores, deduplicates, sorts.
9. **IOC extraction** — finds IPs, domains, URLs, hashes across all data.
10. **IOC enrichment** — queries VirusTotal, MalwareBazaar, AbuseIPDB, WHOIS.
11. **Report generation** — writes JSON, Markdown, HTML, PDF, ATT&CK Navigator, STIX.

---

## Artifact Parsers

| Parser | File types | Library |
|---|---|---|
| `JsonArtifactParser` | `.json` | — |
| `CsvArtifactParser` | `.csv` | — |
| `TextArtifactParser` | `.txt`, `.log` | — |
| `EvtxArtifactParser` | `.evtx` | `python-evtx` |
| `PcapArtifactParser` | `.pcap`, `.pcapng` | `dpkt` |
| `PrefetchArtifactParser` | `.pf` | `PECmd` (optional) |
| `RegistryArtifactParser` | `.hiv`, `SAM`, `SYSTEM`, etc. | `python-registry` |
| `MftArtifactParser` | `.mft`, `$MFT` | `analyzeMFT` (optional) |
| `MemoryDumpArtifactParser` | `.raw`, `.dmp`, `.mem` | `volatility3` |

### Text format

Lines matching `TIMESTAMP|EVENT_TYPE|DESCRIPTION` (pipe-delimited) are parsed as structured events. All other lines become `text_note` events.

### PCAP analysis

- DNS queries, HTTP requests, TLS SNI values extracted per packet
- Beaconing detection: flags connections with 5+ packets and CV < 0.2

---

## Detection & Analysis

### Windows Event IDs

| Event ID | Meaning | Tactic | Technique |
|---|---|---|---|
| 4624 | Successful logon | initial-access | T1078 |
| 4625 | Failed logon | credential-access | T1110 |
| 4648 | Explicit credential logon | lateral-movement | T1550.002 |
| 4688 | Process creation | execution | T1059 |
| 4698 | Scheduled task created | persistence | T1053.005 |
| 4720 | User account created | persistence | T1136 |
| 4732 | Added to security group | privilege-escalation | T1078 |
| 5145 | Network share access | lateral-movement | T1021.002 |
| 7045 | Service installed | persistence | T1543.003 |
| ... | (30 total) | | |

### YARA rules

Place `.yar` / `.yara` files in `$RULES_DIR`. Path traversal is prevented via `confine_path()`.

### Sigma rules

Place `.yml` / `.yaml` files in `$SIGMA_RULES_DIR`. Supported fields: `title`, `level`, `tags` (ATT&CK IDs as `attack.TXXXX`), `detection.keywords`.

### Binary scoring (0-10)

- Shannon entropy > 7.0 = likely packed/encrypted
- Suspicious strings: `VirtualAlloc`, `CreateRemoteThread`, Base64 blobs, C2-like URLs
- PE import hints
- File magic (MZ / ELF)

---

## IOC Extraction & Enrichment

### IOC types

| Type | Pattern |
|---|---|
| `ip` | IPv4 addresses (non-RFC1918) |
| `domain` | FQDNs with known TLDs |
| `url` | HTTP/HTTPS URLs |
| `sha256` | 64-char hex strings |
| `md5` | 32-char hex strings |

### Enrichment providers

| Provider | IOC types | Env var |
|---|---|---|
| VirusTotal | all | `AUTO_FORENSICS_VIRUSTOTAL_API_KEY` |
| MalwareBazaar | sha256, md5 | `AUTO_FORENSICS_MALWAREBAZAAR_API_KEY` |
| AbuseIPDB | ip | `AUTO_FORENSICS_ABUSEIPDB_API_KEY` |
| WHOIS | domain | `AUTO_FORENSICS_ENABLE_WHOIS=true` |

Results are cached in the database with a configurable TTL (default 24 hours).

---

## Database

### Backends

| Backend | Config | Dependencies |
|---|---|---|
| SQLite (default) | No config needed | — |
| PostgreSQL | `AUTO_FORENSICS_DATABASE_URL=postgresql://...` | sqlalchemy, psycopg |

### Schema tables

| Table | Description |
|---|---|
| `cases` | Case metadata, status, paths |
| `artifacts` | Ingested file manifest |
| `findings` | Analysis findings with MITRE mappings |
| `timeline` | Normalised timeline events |
| `case_iocs` | Extracted IOCs |
| `ioc_enrichment_cache` | Shared enrichment cache |
| `case_ioc_enrichments` | Per-case enrichment view |
| `analyst_notes` | Investigator notes |
| `evidence_hash_log` | SHA-256 chain-of-custody log |
| `audit_log` | Immutable action audit trail |
| `analysis_jobs` | Job state and history |
| `schema_migrations` | Migration tracking |

### Migrations

Migrations run automatically at service startup. To run or inspect manually:

```bash
auto-forensics migrate          # apply
auto-forensics migrate --status # inspect
```

---

## Security Model

### Path confinement

`confine_path(root, candidate)` resolves and asserts the candidate is inside the root. Applied during ingestion, YARA/Sigma rule loading, web asset serving, and archive extraction.

### Case ID validation

Case IDs must match `^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$`. Anything else raises `SecurityError`.

### LLM prompt injection defence

Evidence strings are sanitised before prompt construction (strips `ignore previous instructions`, `system:`, etc.). Values truncated to 512 characters.

### API authentication

If `AUTO_FORENSICS_API_KEY` is set, every request must include `X-API-Key: <key>`. The key is stored as a SHA-256 hash.

### Rate limiting

Per-IP rate limiting (default 240/min). Counter resets every 60 seconds.

### Security policy limits

| Setting | Default | Env var |
|---|---|---|
| Max file size | 100 MB | `AUTO_FORENSICS_MAX_FILE_SIZE_BYTES` |
| Max total files | 200,000 | `AUTO_FORENSICS_MAX_TOTAL_FILES` |
| Max text bytes/file | 4 MB | `AUTO_FORENSICS_MAX_TEXT_BYTES` |
| Follow symlinks | false | `AUTO_FORENSICS_FOLLOW_SYMLINKS` |

---

## Plugin System

### Plugin registries

| Registry | Interface | Purpose |
|---|---|---|
| `ArtifactParserRegistry` | `parse(path, max_text_bytes)` | Custom file parsers |
| `DetectorRegistry` | `detect(events)` | Custom finding generators |
| `EnricherRegistry` | `enrich(ioc)` | Custom IOC enrichers |
| `ReporterRegistry` | `report(case_report)` | Custom report formats |

### Writing a plugin

Create a `.py` file in `$AUTO_FORENSICS_PLUGIN_DIRS` (default `~/.auto_forensics/plugins/`):

```python
from pathlib import Path
from auto_forensics.models import ArtifactEvent


class SysmonTextParser:
    name = "sysmon-text-parser"
    supported_suffixes = (".sysmon",)
    supported_names = ()

    def parse(self, path: Path, max_text_bytes: int = 4 * 1024 * 1024) -> list[ArtifactEvent]:
        return []


def register(registry):
    registry.artifact_parsers.register(SysmonTextParser())
```

---

## Reports & Exports

### Output files per case

| File | Format | Description |
|---|---|---|
| `case_report.json` | JSON | Complete machine-readable report |
| `case_report.md` | Markdown | Human-readable summary |
| `case_report.html` | HTML | Browser-viewable styled report |
| `case_report.pdf` | PDF | Printable report (needs `reportlab`) |
| `attack_navigator_layer.json` | JSON | ATT&CK Navigator v4.x layer |
| `case_stix_bundle.json` | STIX 2.1 | STIX bundle for threat intel sharing |

### Case archives

`export` / `import` creates signed ZIP archives with a manifest containing SHA-256 hashes. Signature is `SHA-256(json(manifest) + api_key_hash)`. Import verifies the signature before extraction.

---

## Shell Integration

### What it registers

When you run `auto-forensics shell --install` (or check the box during installation):

| Feature | Registry key | What it does |
|---|---|---|
| **Scan file** | `HKCR\*\shell\AutoForensicsScan` | Right-click any file → "Scan with Auto Forensics" |
| **Scan directory** | `HKCR\Directory\shell\AutoForensicsScanDir` | Right-click a folder → "Scan directory with Auto Forensics" |
| **Scan directory background** | `HKCR\Directory\Background\shell\...` | Right-click empty space in a folder → "Scan directory..." |
| **.afcase association** | `HKCR\.afcase` | Double-click `.afcase` files → import into Auto Forensics |

### Managing

```bash
# Check current status
auto-forensics shell --status

# Install (requires admin/elevated prompt)
auto-forensics shell --install

# Uninstall
auto-forensics shell --uninstall
```

The installer handles this automatically if you select the "Add to right-click menu" option. Context menus are automatically removed on uninstall.

---

## Deployment

### Deployment options

| Option | Best for | How |
|---|---|---|
| **Installed app** | End users | Run the `.exe` installer |
| **Portable app** | USB drives, air-gapped systems | Copy `dist/AutoForensics/` folder |
| **Python package** | Developers, CI/CD | `pip install -e ".[server]"` |
| **Docker** | Servers, team deployments | See Dockerfile section below |

### Production hardening

```bash
# Set production mode
export AUTO_FORENSICS_ENV=prod

# Set a strong API key
export AUTO_FORENSICS_API_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(48))")

# Restrict ingest paths
export AUTO_FORENSICS_ALLOWED_INGEST_ROOTS=/mnt/evidence,/srv/cases

# Use PostgreSQL for multi-user deployments
export AUTO_FORENSICS_DATABASE_URL=postgresql+psycopg://user:pass@db:5432/auto_forensics

# Start
auto-forensics serve --host 0.0.0.0 --port 443
```

### Network access

By default the server binds to `127.0.0.1` (localhost only). To allow network access:

```bash
auto-forensics serve --host 0.0.0.0 --port 8765
```

When exposed on a network, always set `AUTO_FORENSICS_API_KEY` and `AUTO_FORENSICS_ENV=prod`.

### Data location

| Platform | Default path |
|---|---|
| Windows | `C:\Users\<user>\.auto_forensics` |
| Linux | `/home/<user>/.auto_forensics` |
| Custom | Set `AUTO_FORENSICS_HOME=/your/path` |

### Backup

To back up all data:

```bash
# Individual case
auto-forensics export --case-id case-001 --dest backup-case-001.zip

# Full backup (database + all cases)
cp -r ~/.auto_forensics /backup/auto_forensics_$(date +%Y%m%d)
```

---

## Testing

```bash
# Run all tests
python -m pytest tests/ -q

# Run a specific test file
python -m pytest tests/test_security_and_service.py -q

# Run a specific test by name
python -m pytest tests/ -q -k "test_validate_case_id"
```

### Test files

| File | Coverage |
|---|---|
| `test_api_endpoints.py` | FastAPI routes, auth, rate limiting |
| `test_attack_mapper.py` | ATT&CK technique resolution |
| `test_cli_jobs.py` | CLI job management |
| `test_event_detectors.py` | Windows event ID mapping |
| `test_improvements.py` | Bug fixes, edge cases |
| `test_ioc_pipeline_and_db.py` | IOC extraction, DB cache |
| `test_migrations.py` | Schema migration idempotency |
| `test_plugin_and_artifact_registry.py` | Plugin system |
| `test_security_and_service.py` | End-to-end case lifecycle |
| `test_sigma_rules.py` | Sigma rule evaluation |
| `test_stix_export.py` | STIX bundle generation |
| `test_timeline.py` | Timeline normalisation |
| `test_yara_detector.py` | YARA scanning |

Tests for optional dependencies are automatically skipped with `pytest.importorskip()`.

---

## Troubleshooting

### "Auto Forensics is already running"

Another instance is open. Check the system tray for the icon, or kill the process:

```cmd
taskkill /IM AutoForensics.exe /F
```

### Server won't start (port in use)

```cmd
auto-forensics-launcher --port 9000
```

Or find what's using port 8765:

```cmd
netstat -ano | findstr 8765
```

### "uvicorn is not installed"

Install server dependencies:

```bash
pip install auto-forensics-framework[server]
```

### No tray icon (runs in console mode)

Install tray dependencies:

```bash
pip install pystray Pillow
```

### Context menu not showing

Run `auto-forensics shell --install` from an **elevated** (admin) command prompt.

### Tests failing

Make sure dev dependencies are installed:

```bash
pip install -e ".[server,dev]"
python -m pytest tests/ -q
```

### Log file location

```
Windows:  %APPDATA%\Auto Forensics\logs\auto_forensics.log
Linux:    ~/.config/Auto Forensics/logs/auto_forensics.log
```

### Data directory location

```bash
auto-forensics config    # shows all paths
```

### Database issues

```bash
# Check migration status
auto-forensics migrate --status

# Force re-apply migrations
auto-forensics migrate
```

---

## Changelog

### v1.0.0 (2026-03)

**Desktop application:**
- System-tray launcher with splash screen, single-instance enforcement, auto browser-open
- Windows toast notifications for server events
- Crash handler with error dialog and log-to-file with rotation
- Auto-start with Windows toggle (registry HKCU Run key)
- DPI-aware manifest (Per-Monitor V2)
- Explorer context menus: right-click "Scan with Auto Forensics" for files and directories
- `.afcase` file association for case archive import
- PyInstaller standalone exe (GUI + CLI)
- Inno Setup Windows installer with Start Menu, Desktop shortcut, PATH, context menus
- `build_app.cmd` one-click build pipeline with test gate and code-signing placeholder
- MIT LICENSE file

### v0.9.0 (2026-02)

**Autonomous agent:**
- `solve` command — AI agent auto-detects Case folder, ingests, analyses, and reports
- `watch` command — drop-directory watcher for continuous monitoring
- `extract` command — disk image mounting and artifact extraction

### v0.8.0 (2026-02)

**Bug fixes:**
- Dedicated `_enrichment_lock` prevents race conditions
- Bounds-safe Sigma tag parsing
- JSON decode safety in database reads
- URL-safe IOC values in enrichment API calls

**Improvements:**
- Generator-based scan candidate discovery (lower memory)
- 20+ new tests
- Event detector coverage expanded to 30 Windows event IDs
