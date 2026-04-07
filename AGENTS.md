# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## Commands

**Install (dev mode with all required extras):**
```bash
pip install -e .[server,dev]
# For PostgreSQL support also add: ,[db]
```

**Run all tests:**
```bash
python -m pytest tests/ -q
```

**Run a single test file:**
```bash
python -m pytest tests/test_security_and_service.py -q
```

**Run a single test by name:**
```bash
python -m pytest tests/ -q -k "test_validate_case_id"
```

**Start the API server (dev):**
```bash
auto-forensics serve --host 127.0.0.1 --port 8765
```

**CLI case workflow:**
```bash
auto-forensics init --case-id case-001
auto-forensics ingest --case-id case-001 --source-dir ./examples/case1/artifacts
auto-forensics analyze --case-id case-001 --disable-llama
auto-forensics report --case-id case-001 --format md
```

## Style guide

Follow the Google Python Style Guide (`conductor/code_styleguides/python.md`):
- Max 80-character lines, 4-space indentation, no tabs.
- `snake_case` for functions/variables/modules, `PascalCase` for classes, `ALL_CAPS` for module-level constants.
- No bare `except:` clauses — always catch specific exception types.
- Type annotations required on all public APIs.
- Avoid mutable default arguments.
- Match the existing style of the file being edited.

## Optional extras

The `.[server,dev]` install covers CLI + tests. Individual extras:

| Extra | Enables |
|---|---|
| `pe` | PE binary analysis (`pefile`) |
| `evtx` | Windows Event Log parsing (`python-evtx`) |
| `pcap` | PCAP parsing (`dpkt`) |
| `registry` | Registry hive parsing (`python-registry`) |
| `yara` | YARA rule scanning (`yara-python`) |
| `sigma` | Sigma rule evaluation (`pyyaml`) |
| `memory` | Memory dump analysis (`volatility3`) |
| `pdf` | PDF report export (`reportlab`) |
| `db` | PostgreSQL + SQLAlchemy backend |
| `server` | FastAPI + uvicorn API server |
| `dev` | pytest |

Tests for optional-dep features are skipped with `pytest.importorskip(...)`. The CI matrix installs only `.[dev,db]` — do not add mandatory deps.

## Architecture

### Layered structure
```
cli.py / api.py       ← user-facing entrypoints
service.py            ← orchestrates the full case lifecycle
pipeline.py           ← artifact parsing, binary analysis, timeline generation, report export
plugins.py            ← registries for parsers, analyzers, detectors, enrichers, reporters
db.py / db_sqlalchemy.py ← persistence (selected via AUTO_FORENSICS_DATABASE_URL)
security.py / config.py  ← input validation and environment-driven configuration
```

### Entry points
Two console scripts are installed:
- `auto-forensics` → `auto_forensics.cli:main` (30+ subcommands for the full case lifecycle)
- `auto-forensics-api` → `auto_forensics.api:main` (FastAPI server; same as `auto-forensics serve`)

### Plugin registry pattern (`plugins.py`)
`PluginRegistry` holds four sub-registries: `ArtifactParserRegistry`, `DetectorRegistry`, `EnricherRegistry`, and `ReporterRegistry`, plus a `binary_analyzers` list. Every subsystem calls into the registry rather than importing concrete implementations directly. External plugins drop `.py` files into `AUTO_FORENSICS_PLUGIN_DIRS` and expose a `register(registry: PluginRegistry)` function.

### Data models (`models.py`)
All domain objects are frozen `@dataclass(slots=True)`: `ArtifactEvent`, `BinaryFeature`, `Finding`, `IOC`, `IOCEnrichment`, `TimelineEvent`, `CaseReport`. These are the interchange types across every layer.

### Data flow
1. `case_manager.py` — ingests evidence, hashes files, records chain-of-custody
2. `pipeline.py` — dispatches each file to the matching `ArtifactParserPlugin`, runs `binary_analysis.py` on binaries, calls `DetectorRegistry.detect()`, builds timeline via `timeline.py`, extracts IOCs via `ioc_pipeline.py`
3. `service.py` — runs analysis and enrichment in background `ThreadPoolExecutor` pools (4 analysis workers, 2 enrichment workers); uses separate `_analysis_lock` and `_enrichment_lock` for their respective state dicts
4. `db.py` / `db_sqlalchemy.py` — persist artifacts, findings, timeline, IOCs, jobs; selected at startup based on `AUTO_FORENSICS_DATABASE_URL`; schema migrations applied via `migrations.py`

### Security boundary (`security.py`)
`confine_path(root, candidate)` enforces directory confinement — call it before any file access using a user-supplied path. `validate_case_id()` enforces the `^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$` pattern. `SecurityPolicy` dataclass holds size/count limits read from env vars. All SQL uses parameterized queries only.

### Configuration (`config.py`)
`AppConfig.from_env()` reads all settings from environment variables prefixed `AUTO_FORENSICS_`. Key vars: `AUTO_FORENSICS_HOME`, `AUTO_FORENSICS_ENV` (`dev`/`prod`), `AUTO_FORENSICS_API_KEY`, `AUTO_FORENSICS_DATABASE_URL`, `AUTO_FORENSICS_ALLOWED_INGEST_ROOTS`, `AUTO_FORENSICS_VIRUSTOTAL_API_KEY`, `AUTO_FORENSICS_OPENAI_ENDPOINT`, `AUTO_FORENSICS_OPENAI_API_KEY`.

**OpenAI-compatible endpoint convention:** `AUTO_FORENSICS_OPENAI_ENDPOINT` must be the base URL **including** any version path up to (but not including) `/chat/completions`. Examples:
- OpenAI: `https://api.openai.com/v1`
- Gemini: `https://generativelanguage.googleapis.com/v1beta/openai`

### Optional dependencies
All heavy deps are optional extras. Guards follow the pattern:
```python
try:
    import yara
except ImportError:
    yara = None  # type: ignore
```

### Database backends
`db.py` is the plain SQLite backend (no extra deps). `db_sqlalchemy.py` supports SQLite and PostgreSQL via SQLAlchemy + psycopg. Both implement the `DatabaseBackend` protocol in `db_backend.py`. `service.py` selects the backend at startup.

### Key subsystems
| File | Purpose |
|---|---|
| `artifacts.py` | Built-in parsers: JSON, CSV, text, EVTX, PCAP, Prefetch, Registry, MFT, memory |
| `binary_analysis.py` | Streaming entropy, string extraction, PE import hints, suspicious scoring |
| `builtin_detectors.py` | Sysmon, Defender, Zeek, Suricata pattern detectors |
| `event_detectors.py` | Windows event-ID-based detection with MITRE ATT&CK technique mapping |
| `ioc_pipeline.py` | IOC extraction (IPs, domains, hashes, URLs) from timeline events |
| `ioc_enrichment.py` | VirusTotal, MalwareBazaar, AbuseIPDB lookups with retry/backoff |
| `yara_detector.py` | YARA rule scanning (uses `confine_path()` per rule file) |
| `sigma_rules.py` | Sigma rule evaluation against timeline events |
| `attack_mapper.py` | MITRE ATT&CK STIX bundle lookups |
| `stix_export.py` | STIX 2.1 bundle export |
| `llama_workflow.py` | Ollama/OpenAI-compatible LLM triage with prompt-injection sanitization |
| `pdf_report.py` | PDF report generation via `reportlab` |
| `migrations.py` | Versioned schema migration steps |
| `timeline.py` | Timeline assembly and risk scoring |

### Case directory layout
Cases live under `$AUTO_FORENSICS_HOME/cases/{case_id}/`:
- `evidence/` — raw artifact files copied in during ingest
- `output/` — generated reports (`case_report.json`, `case_report.md`, `case_report.pdf`)

### Extended CLI commands
Beyond the basic workflow, the CLI provides: `scan` / `scan-dir` (standalone file/directory analysis without a case), `conclusions` (MITRE tactic correlation and risk verdicts), `audit` (chain-of-custody audit trail), `hash` (artifact hashing), `stats` (global case count summary), `search` (full-text search across cases), `notes` / `add-note` (analyst notes), `jobs` / `cleanup-jobs` (job queue management), `export` / `import` (case archiving), `delete` (case removal), `migrate` (schema migration).

### Training directory
`training/` contains a separate fine-tuning pipeline (Qwen 2.5 LoRA) for the LLM triage component. It has its own `.venv` and is not part of the main package.
