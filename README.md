# Auto Forensics Framework

Automated malware-oriented binary analysis and incident timeline generation with:
- case management (persistent SQLite backend)
- secure evidence ingestion workflow
- Llama-assisted malware triage
- API + web dashboard
- cross-platform operation for Windows and Linux

## Capabilities

- Case lifecycle:
  - create cases
  - ingest evidence directories
  - analyze and produce findings/timeline
  - persist artifacts/findings/timeline in a database
- Malware analysis:
  - SHA256/MD5, entropy scoring, suspicious string detection
  - optional PE import signal extraction (`pefile`)
  - plugin-based binary analyzer extension point
- AI workflow:
  - Ollama-compatible endpoint for Llama findings, timeline hints, and case summaries
  - secure heuristic fallback if model output is unavailable
- Reporting:
  - `case_report.json`
  - `case_report.md`
  - `case_report.html`
  - `case_report.pdf` (when `reportlab` is available)
  - `attack_navigator_layer.json`
  - `case_stix_bundle.json`
- API + dashboard:
  - FastAPI backend
  - browser-based case operations console

## Security Design

Secure-by-default controls implemented:
- strict `case_id` validation
- path confinement checks to prevent directory escape
- bounded text-file reads and artifact size limits
- symlink handling policy for ingestion
- parameterized SQL usage
- strict CORS default (disabled unless configured)
- trusted host middleware
- optional API key auth (`X-API-Key`) with constant-time hash comparison
- security response headers and restrictive CSP

## Install

### Windows

```powershell
cd "C:\Users\Benji\Documents\Auto Forensics"
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e .[server,dev,desktop]
```

### Linux

```bash
cd /path/to/Auto\ Forensics
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[server,dev,desktop]"
```

## CLI Usage

Initialize and run a full managed case workflow:

```bash
auto-forensics init --case-id case-2026-001
auto-forensics ingest --case-id case-2026-001 --source-dir ./examples/case1/artifacts
auto-forensics analyze --case-id case-2026-001 --disable-llama
auto-forensics overview --case-id case-2026-001
auto-forensics report --case-id case-2026-001 --format md
auto-forensics export --case-id case-2026-001 --dest ./case-2026-001.zip
auto-forensics import --archive ./case-2026-001.zip
auto-forensics migrate --status
auto-forensics migrate
auto-forensics enrich --case-id case-2026-001
auto-forensics enrich --case-id case-2026-001 --status
auto-forensics jobs --case-id case-2026-001
auto-forensics jobs --case-id case-2026-001 --type enrichment --limit 50
auto-forensics cleanup-jobs --retention-days 14
```

### File Scanning

Scan individual files or directories without creating a case:

```bash
auto-forensics scan --path suspicious.exe
auto-forensics scan --path suspicious.exe --json
auto-forensics scan-dir --path ./evidence --json
auto-forensics scan-dir --path ./evidence --no-recursive
```

### Case Conclusions

Generate automated forensic conclusions and risk verdicts from case data:

```bash
auto-forensics conclusions --case-id case-2026-001
auto-forensics conclusions --case-id case-2026-001 --json
```

### Timeline Filtering

```bash
auto-forensics timeline-filter --case-id case-2026-001 --min-risk 50
auto-forensics timeline-filter --case-id case-2026-001 --after 2026-01-01 --before 2026-02-01
auto-forensics timeline-filter --case-id case-2026-001 --event-type logon --keyword admin
```

### IOC Listing and Export

```bash
auto-forensics iocs --case-id case-2026-001
auto-forensics iocs --case-id case-2026-001 --type ip
auto-forensics iocs --case-id case-2026-001 --export csv > iocs.csv
auto-forensics iocs --case-id case-2026-001 --export json > iocs.json
```

### Audit Trail

```bash
auto-forensics audit
auto-forensics audit --case-id case-2026-001
auto-forensics audit --limit 50 --json
```

### File Hashing

```bash
auto-forensics hash --path file.exe --algo all
auto-forensics hash --path file.exe --algo sha256
auto-forensics hash --path file.exe --json
```

### Configuration and Version

```bash
auto-forensics config
auto-forensics version
```

List cases:

```bash
auto-forensics list
```

Legacy one-shot runner is still available:

```bash
auto-forensics run --case-id demo-case --input-dir ./examples/case1/artifacts --output-dir ./output/demo-case --disable-llama
```

## Desktop App

Standalone app:

```bash
auto-forensics-app
```

Portable app:

```bash
AutoForensics.exe
```

The portable bundle stores its data next to the app in a local `data/`
folder.

Legacy browser/tray launcher:

```bash
auto-forensics serve --host 127.0.0.1 --port 8765
auto-forensics start --host 127.0.0.1 --port 8765
auto-forensics-launcher
```

Windows one-click launch:
- double-click `AutoForensics.exe` for the standalone app
- double-click `start-portable.cmd` inside the portable bundle for portable mode
- double-click `start-auto-forensics.cmd` for the legacy browser/tray launcher

If you use the browser launcher, open:
- `http://127.0.0.1:8765/` (dashboard)
- `http://127.0.0.1:8765/docs` (dev mode only)

Dashboard highlights:
- case list filtering (`q`, `status`, `limit`) and global case stats
- live analysis + IOC enrichment status bars
- timeline filtering, case search, analyst notes, and report viewer
- archive export/import controls for signed case bundles

Live analysis status:
- `POST /api/cases/{case_id}/analyze/async` starts background analysis
- `GET /api/cases/{case_id}/status` returns current status
- `GET /api/cases/{case_id}/status?stream=true` streams status updates as SSE
- `GET /api/cases/{case_id}/notes` / `POST /api/cases/{case_id}/notes` for analyst collaboration notes
- `POST /api/cases/{case_id}/export` exports a signed case archive
- `POST /api/cases/import` imports a signed case archive
- `GET /api/admin/migrations` and `POST /api/admin/migrations` inspect/apply DB migrations
- `POST /api/cases/{case_id}/enrich/async` starts IOC enrichment in the background
- `GET /api/cases/{case_id}/enrich/status` returns enrichment job status (or stream with `?stream=true`)
- `GET /api/cases/{case_id}/jobs` lists job history (optionally filter with `job_type=analysis|enrichment`)
- `POST /api/admin/jobs/cleanup` removes job history older than configured or supplied retention days

Operational logs:
- evidence hash entries are appended during ingestion for chain-of-custody support
- audit trail entries are recorded for case create/ingest/analyze/note actions

Set production mode and API key:

### Windows PowerShell

```powershell
$env:AUTO_FORENSICS_ENV="prod"
$env:AUTO_FORENSICS_API_KEY="replace-with-strong-random-secret"
$env:AUTO_FORENSICS_TRUSTED_HOSTS="127.0.0.1,localhost"
$env:AUTO_FORENSICS_ALLOWED_INGEST_ROOTS="C:\Evidence,C:\Cases"
$env:AUTO_FORENSICS_RATE_LIMIT_PER_MINUTE="240"
$env:AUTO_FORENSICS_OPENAI_ENDPOINT="https://api.openai.com"
$env:AUTO_FORENSICS_OPENAI_API_KEY="replace-with-api-key"
auto-forensics serve
```

### Linux

```bash
export AUTO_FORENSICS_ENV=prod
export AUTO_FORENSICS_API_KEY='replace-with-strong-random-secret'
export AUTO_FORENSICS_TRUSTED_HOSTS='127.0.0.1,localhost'
export AUTO_FORENSICS_ALLOWED_INGEST_ROOTS='/mnt/evidence,/srv/cases'
export AUTO_FORENSICS_RATE_LIMIT_PER_MINUTE='240'
export AUTO_FORENSICS_OPENAI_ENDPOINT='https://api.openai.com'
export AUTO_FORENSICS_OPENAI_API_KEY='replace-with-api-key'
auto-forensics serve
```

## Artifact Formats

Supported input types:
- `.json` list/object event files
- `.csv` event tables
- `.txt` / `.log` line-based notes/events
- `.evtx` Windows Event Logs (requires optional `python-evtx`)
- `.pcap` / `.pcapng` packet captures (requires optional `dpkt`)
- `.pf` Windows Prefetch files (PECmd subprocess preferred, filename fallback)
- Registry hives: `SOFTWARE`, `SYSTEM`, `SAM`, `SECURITY`, `NTUSER.DAT`, `USRCLASS.DAT` (requires optional `python-registry`)
- `$MFT` / `.mft` NTFS MFT artifacts (analyzeMFT subprocess preferred)
- memory dumps: `.raw`, `.dmp`, `.mem` (Volatility3 subprocess plugins when available)
- binaries: `.exe`, `.dll`, `.sys`, `.bin`

Text formats support:
- `timestamp|event_type|description`
- free-text lines (stored as analyst notes)

YARA support:
- drop custom `.yar` / `.yara` rules into `AUTO_FORENSICS_RULES_DIR` (default: `<AUTO_FORENSICS_HOME>/rules`)
- all ingested files are scanned when rules and `yara-python` are available

Sigma support:
- drop Sigma `.yml` / `.yaml` rules into `AUTO_FORENSICS_SIGMA_RULES_DIR` (default: `<AUTO_FORENSICS_HOME>/rules/sigma`)
- timeline events are evaluated against keyword detections when `pyyaml` is installed

## Data Location

Default application data root:
- Windows: `C:\Users\<User>\.auto_forensics`
- Linux: `/home/<user>/.auto_forensics`

Override with:
- `AUTO_FORENSICS_HOME=/custom/path`

Database URL override:
- `AUTO_FORENSICS_DATABASE_URL=sqlite:///C:/cases/auto_forensics.db`
- PostgreSQL example: `AUTO_FORENSICS_DATABASE_URL=postgresql+psycopg://user:password@host:5432/auto_forensics`

Database migrations:
- migrations are applied automatically at service startup
- inspect with `auto-forensics migrate --status`
- apply explicitly with `auto-forensics migrate`

Job retention:
- background analysis and IOC enrichment jobs are persisted in `analysis_jobs`
- list case job history with `auto-forensics jobs --case-id <id>`
- remove stale history with `auto-forensics cleanup-jobs --retention-days <days>`
- configure default cleanup window using `AUTO_FORENSICS_JOB_RETENTION_DAYS` (default `30`)

## Development

Run tests:

```bash
pytest -q
```

## Local Fine-Tuning

For local adapter training tuned to this application's strict JSON prompts, see:

- `training/README.md`

Included scripts:

- `training/generate_synthetic_dataset.py`
- `training/train_lora.py`
- `training/evaluate_lora.py`
- `training/merge_lora.py`

Cross-platform CI matrix is included at `.github/workflows/ci.yml` for Windows and Linux.

## Project Layout

```text
src/auto_forensics/
  api.py
  artifacts.py
  binary_analysis.py
  case_manager.py
  cli.py
  config.py
  db.py
  llama_workflow.py
  models.py
  pipeline.py
  plugins.py
  security.py
  service.py
  timeline.py
  web/
    dashboard.html
    dashboard.css
    dashboard.js
tests/
examples/case1/artifacts/
```

Architecture details: `ARCHITECTURE.md`.

## Plugin SDK

Drop plugin files into `AUTO_FORENSICS_PLUGIN_DIRS` (comma-separated paths, default `<AUTO_FORENSICS_HOME>/plugins`).

Each plugin file should expose a `register(registry)` function:

```python
from pathlib import Path
from auto_forensics.models import ArtifactEvent


class SysmonTextParser:
    name = "sysmon-text-parser"
    supported_suffixes = (".sysmon",)
    supported_names = ()

    def parse(self, path: Path, max_text_bytes: int = 4 * 1024 * 1024) -> list[ArtifactEvent]:
        # return ArtifactEvent objects
        return []


def register(registry):
    registry.artifact_parsers.register(SysmonTextParser())
```

Plugins can register custom artifact parsers, binary analyzers, detectors, enrichers, and reporters.

Built-in detector plugins ship for Sysmon, Windows Defender, Zeek, and Suricata-style telemetry patterns.
