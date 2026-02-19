# Auto Forensics — Project Wiki

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Installation & Setup](#installation--setup)
4. [Configuration](#configuration)
5. [CLI Reference](#cli-reference)
6. [API Reference](#api-reference)
7. [Pipeline Internals](#pipeline-internals)
8. [Artifact Parsers](#artifact-parsers)
9. [Detection & Analysis](#detection--analysis)
10. [IOC Extraction & Enrichment](#ioc-extraction--enrichment)
11. [Database](#database)
12. [Security Model](#security-model)
13. [Plugin System](#plugin-system)
14. [Reports & Exports](#reports--exports)
15. [Testing](#testing)
16. [Changelog](#changelog)

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

**No mandatory runtime dependencies** — all integrations (YARA, Sigma, EVTX parsing, LLM, enrichment) are optional and gracefully skipped if the library is absent.

---

## Architecture

```
src/auto_forensics/
├── api.py              # FastAPI application, all HTTP endpoints
├── cli.py              # argparse CLI (entry point: auto-forensics)
├── config.py           # AppConfig dataclass, env var loading
├── service.py          # AutoForensicsService — orchestration layer
├── pipeline.py         # run_case() — single-pass analysis pipeline
├── plugins.py          # Plugin registries (parsers, detectors, enrichers)
├── artifacts.py        # All artifact loaders (CSV, JSON, TXT, EVTX, PCAP, …)
├── binary_analysis.py  # PE/ELF heuristics, entropy, string extraction
├── event_detectors.py  # Windows event ID → Finding mappings
├── yara_detector.py    # YARA rule loading and scanning
├── sigma_rules.py      # Sigma YAML rule evaluation against timeline
├── attack_mapper.py    # STIX ATT&CK technique lookup + keyword fallback
├── ioc_pipeline.py     # IOC extraction from findings, timeline, binaries
├── ioc_enrichment.py   # HTTP enrichment clients (VT, MBAZAAR, ABUSEIPDB)
├── case_manager.py     # Filesystem case directory management
├── db.py               # SQLite database backend
├── db_sqlalchemy.py    # PostgreSQL / SQLAlchemy backend
├── db_backend.py       # Abstract DatabaseBackend protocol
├── models.py           # Dataclasses: Finding, TimelineEvent, IOC, …
├── security.py         # SecurityPolicy, confine_path, validate_case_id
├── stix_export.py      # STIX 2.1 bundle generation
├── report.py           # HTML / Markdown report generation
├── pdf_report.py       # PDF report generation (reportlab optional)
├── attack_navigator.py # ATT&CK Navigator JSON layer export
├── llama_workflow.py   # Ollama/OpenAI-compatible LLM analysis workflow
├── migrations.py       # Database schema migrations
└── web/                # Static dashboard assets (HTML, CSS, JS)
```

### Data flow

```
CLI / API request
      │
      ▼
AutoForensicsService
      │  uses
      ├─► CaseManager        → filesystem dirs
      ├─► Database           → SQLite / PostgreSQL
      └─► run_case()         → PipelineConfig
               │
               ├─► discover_artifacts()   → ArtifactEvent list
               ├─► binary_analysis()      → BinaryFeature list
               ├─► findings_from_events() → Finding list
               ├─► YARA scan             → Finding list
               ├─► Sigma evaluation      → Finding list
               ├─► ATT&CK mapping        → enriched findings
               ├─► normalize_timeline()  → TimelineEvent list
               ├─► extract_iocs()        → IOC list
               ├─► enrich_iocs()         → IOCEnrichment list
               └─► write reports         → JSON / MD / HTML / PDF / STIX
```

### Concurrency

- **Analysis jobs**: `ThreadPoolExecutor(max_workers=4)`, guarded by `_analysis_lock`
- **Enrichment jobs**: `ThreadPoolExecutor(max_workers=2)`, guarded by `_enrichment_lock` (separate lock — holding one does not block the other)
- Both job types persist state to the database and to in-memory dicts for fast polling

---

## Installation & Setup

### Requirements

- Python 3.10 – 3.12
- pip

### Basic install

```bash
pip install -e .
```

Optional extras:

```bash
pip install yara-python        # YARA rule scanning
pip install pyyaml             # Sigma rule evaluation
pip install python-evtx        # .evtx Windows event log parsing
pip install dpkt               # PCAP / network artifact parsing
pip install python-registry    # Windows registry hive parsing
pip install reportlab          # PDF report generation
pip install sqlalchemy         # PostgreSQL backend
pip install ollama             # Llama LLM workflow
```

### First run

```bash
# Start API server (defaults to http://127.0.0.1:8765)
auto-forensics serve

# Or run a one-shot case analysis without the server
auto-forensics run \
  --case-id case-001 \
  --input-dir /evidence/case-001 \
  --output-dir /reports/case-001
```

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
| `AUTO_FORENSICS_ALLOWED_INGEST_ROOTS` | `~` | Comma-separated paths from which evidence may be ingested |
| `AUTO_FORENSICS_RATE_LIMIT_PER_MINUTE` | `240` | Per-IP rate limit |
| `AUTO_FORENSICS_LLAMA_ENDPOINT` | `http://localhost:11434` | Ollama endpoint |
| `AUTO_FORENSICS_LLAMA_MODEL` | `llama3.1:8b` | Ollama model name |
| `AUTO_FORENSICS_OPENAI_ENDPOINT` | *(none)* | OpenAI-compatible endpoint (e.g. LM Studio) |
| `AUTO_FORENSICS_OPENAI_API_KEY` | *(none)* | API key for OpenAI-compatible endpoint |
| `AUTO_FORENSICS_DATABASE_URL` | *(SQLite)* | PostgreSQL URL, e.g. `postgresql://user:pw@host/db` |
| `AUTO_FORENSICS_RULES_DIR` | `$HOME/.auto_forensics/rules` | YARA rules directory |
| `AUTO_FORENSICS_SIGMA_RULES_DIR` | `$RULES_DIR/sigma` | Sigma rules directory |
| `AUTO_FORENSICS_ATTACK_STIX_PATH` | `$HOME/.auto_forensics/attack/enterprise-attack.json` | ATT&CK STIX bundle |
| `AUTO_FORENSICS_VIRUSTOTAL_API_KEY` | *(none)* | VirusTotal v3 API key |
| `AUTO_FORENSICS_MALWAREBAZAAR_API_KEY` | *(none)* | MalwareBazaar API key |
| `AUTO_FORENSICS_ABUSEIPDB_API_KEY` | *(none)* | AbuseIPDB v2 API key |
| `AUTO_FORENSICS_ENABLE_WHOIS` | `false` | Enable WHOIS lookups for domains |
| `AUTO_FORENSICS_ENRICHMENT_CACHE_TTL_MINUTES` | `1440` (24 h) | IOC enrichment cache TTL |
| `AUTO_FORENSICS_MAX_FILE_SIZE_BYTES` | `104857600` (100 MB) | Maximum single file size |
| `AUTO_FORENSICS_MAX_TOTAL_FILES` | `200000` | Maximum files per case |
| `AUTO_FORENSICS_MAX_TEXT_BYTES` | `4194304` (4 MB) | Maximum text bytes read per file |
| `AUTO_FORENSICS_JOB_RETENTION_DAYS` | `30` | Job history retention window |
| `AUTO_FORENSICS_PLUGIN_DIRS` | `$HOME/.auto_forensics/plugins` | Plugin directories |

---

## CLI Reference

```
auto-forensics <command> [options]
```

### Commands

#### `init`
Create a new case workspace (idempotent).
```bash
auto-forensics init --case-id CASE_ID
```

#### `list`
List all cases.
```bash
auto-forensics list [--json]
```

#### `ingest`
Copy and hash evidence files from a source directory into the case.
```bash
auto-forensics ingest --case-id CASE_ID --source-dir /path/to/evidence
```

#### `analyze`
Run the full analysis pipeline on an ingested case.
```bash
auto-forensics analyze --case-id CASE_ID [--disable-llama]
```

#### `overview`
Print the full case overview (findings, timeline, IOCs, notes, audit log) as JSON.
```bash
auto-forensics overview --case-id CASE_ID
```

#### `report`
Print the generated report in various formats.
```bash
auto-forensics report --case-id CASE_ID --format [json|md|html|navigator|stix]
```

#### `enrich`
Trigger or check IOC enrichment for a case.
```bash
auto-forensics enrich --case-id CASE_ID          # start enrichment
auto-forensics enrich --case-id CASE_ID --status # check status
```

#### `jobs`
List analysis/enrichment job history.
```bash
auto-forensics jobs --case-id CASE_ID [--type analysis|enrichment] [--limit N]
```

#### `cleanup-jobs`
Delete job history older than the retention window.
```bash
auto-forensics cleanup-jobs [--retention-days N]
```

#### `export`
Export a case as a signed zip archive (includes manifest with file hashes).
```bash
auto-forensics export --case-id CASE_ID --dest /path/to/archive.zip
```

#### `import`
Import a previously exported archive. Verifies the cryptographic signature.
```bash
auto-forensics import --archive /path/to/archive.zip [--case-id NEW_CASE_ID]
```

#### `migrate`
Run or inspect database schema migrations.
```bash
auto-forensics migrate          # apply pending migrations
auto-forensics migrate --status # inspect current schema version
```

#### `serve`
Start the API server and web dashboard.
```bash
auto-forensics serve [--host HOST] [--port PORT]
```

#### `run`
Full one-shot pipeline (no persistent service required).
```bash
auto-forensics run \
  --case-id case-001 \
  --input-dir /evidence \
  --output-dir /reports \
  [--llama-endpoint http://localhost:11434] \
  [--llama-model llama3.1:8b] \
  [--disable-llama]
```

---

## API Reference

Base URL: `http://127.0.0.1:8765`

All endpoints return JSON. If `AUTO_FORENSICS_API_KEY` is set, include the header:
```
X-API-Key: <your-api-key>
```

### Error format

All errors follow:
```json
{"error": "error_type", "detail": "human-readable message", "status_code": 422}
```

### Cases

| Method | Path | Description |
|---|---|---|
| `POST` | `/cases` | Create a new case |
| `GET` | `/cases` | List all cases |
| `GET` | `/cases/{case_id}` | Get case metadata |
| `POST` | `/cases/{case_id}/ingest` | Ingest evidence from a source directory |
| `POST` | `/cases/{case_id}/analyze` | Start async analysis |
| `GET` | `/cases/{case_id}/status` | Poll analysis job status |
| `GET` | `/cases/{case_id}/status/stream` | Server-sent events status stream |
| `GET` | `/cases/{case_id}/overview` | Full case overview (findings, IOCs, timeline) |
| `GET` | `/cases/{case_id}/report` | Get report (`?format=json\|md\|html\|navigator\|stix`) |

### IOC Enrichment

| Method | Path | Description |
|---|---|---|
| `POST` | `/cases/{case_id}/enrich` | Start IOC enrichment job |
| `GET` | `/cases/{case_id}/enrich/status` | Poll enrichment status |

### Notes & Search

| Method | Path | Description |
|---|---|---|
| `POST` | `/cases/{case_id}/notes` | Add analyst note |
| `GET` | `/cases/{case_id}/notes` | List analyst notes |
| `GET` | `/cases/{case_id}/search?q=QUERY` | Full-text search across findings, timeline, IOCs |

### Jobs

| Method | Path | Description |
|---|---|---|
| `GET` | `/cases/{case_id}/jobs` | List job history |
| `DELETE` | `/jobs/cleanup` | Prune old jobs |

### Archive

| Method | Path | Description |
|---|---|---|
| `POST` | `/cases/{case_id}/export` | Export case archive |
| `POST` | `/cases/import` | Import case archive |

### Admin

| Method | Path | Description |
|---|---|---|
| `POST` | `/db/migrate` | Run database migrations |
| `GET` | `/db/migrate/status` | Get migration status |
| `GET` | `/health` | Health check |

---

## Pipeline Internals

`run_case(config: PipelineConfig) -> CaseReport`

The pipeline runs in a single call and proceeds through these stages:

1. **Artifact discovery** (`discover_artifacts`):
   Walks the evidence directory (depth ≤ 20), dispatches each file to the matching parser, accumulates `ArtifactEvent` list and a list of binary paths.

2. **Binary analysis** (`analyze_binary`):
   Runs in a `ThreadPoolExecutor(4)`. Computes entropy, extracts printable strings, checks PE/ELF magic bytes, scores suspicious indicators.

3. **YARA scan** (`scan_paths_with_yara`):
   Applies compiled YARA rules from `rules_dir` to all non-binary files. Wrapped in try/except — a failed scan degrades gracefully.

4. **Event detection** (`findings_from_artifact_events`):
   Maps Windows event IDs to known-suspicious activities (30 event IDs covered). Falls back to technique-level findings from artifact metadata.

5. **Sigma rule evaluation** (`evaluate_sigma_rules`):
   Loads YAML rules from `sigma_rules_dir`, counts keyword matches against timeline events, emits findings with ATT&CK technique IDs.

6. **ATT&CK mapping** (`apply_attack_mapping`):
   Resolves each finding's `technique_id` against the STIX ATT&CK bundle for tactic, name, and URL. Falls back to a keyword-based heuristic if the bundle is unavailable.

7. **LLM workflow** (optional, `LlamaWorkflow`):
   Sends binary feature summaries to an Ollama or OpenAI-compatible endpoint for a reasoning pass. Evidence is sanitised before prompt construction to prevent injection.

8. **Timeline normalisation** (`normalize_timeline`):
   Merges artifact events and analysis hints, assigns risk scores, deduplicates, sorts by timestamp.

9. **IOC extraction** (`extract_iocs`):
   Finds IPs, domains, URLs, and file hashes across all findings, timeline events, and binary strings. Deduplicates by type+value.

10. **IOC enrichment** (`enrich_iocs_with_cache`):
    Queries VirusTotal, MalwareBazaar, AbuseIPDB, and WHOIS for each IOC. Results are cached in the database with a configurable TTL.

11. **Report generation**:
    Writes JSON, Markdown, HTML, ATT&CK Navigator JSON, STIX 2.1 bundle, and optionally PDF to the case output directory.

---

## Artifact Parsers

Parsers are registered via `ArtifactParserRegistry`. Each parser implements `parse(path, max_text_bytes) -> list[ArtifactEvent]`.

| Parser class | Triggers on | Library needed |
|---|---|---|
| `JsonArtifactParser` | `.json` | — |
| `CsvArtifactParser` | `.csv` | — |
| `TextArtifactParser` | `.txt`, `.log` | — |
| `EvtxArtifactParser` | `.evtx` | `python-evtx` |
| `PcapArtifactParser` | `.pcap`, `.pcapng` | `dpkt` |
| `PrefetchArtifactParser` | `.pf` | `PECmd` (optional) |
| `RegistryArtifactParser` | `.hiv`, `.hive`, `SAM`, `SYSTEM`, … | `python-registry` |
| `MftArtifactParser` | `.mft`, `$MFT` | `analyzeMFT` (optional) |
| `MemoryDumpArtifactParser` | `.raw`, `.dmp`, `.mem` | `volatility3` |

### Text format for `.txt` / `.log` files

Lines matching `TIMESTAMP|EVENT_TYPE|DESCRIPTION` (pipe-delimited) are parsed as structured events. All other lines become `text_note` events.

### PCAP analysis

- DNS queries, HTTP requests, and TLS SNI values extracted per packet
- Beaconing detection: groups flows by (dst_ip, dst_port, proto); flags connections with ≥ 5 packets and coefficient of variation < 0.2

---

## Detection & Analysis

### Windows Event IDs

The following event IDs are mapped to ATT&CK techniques:

| Event ID | Event type | Tactic | Technique |
|---|---|---|---|
| 4624 | Successful logon | initial-access | T1078 |
| 4625 | Failed logon | credential-access | T1110 |
| 4648 | Logon with explicit credentials | lateral-movement | T1550.002 |
| 4688 | Process creation | execution | T1059 |
| 4698 | Scheduled task created | persistence | T1053.005 |
| 4699 | Scheduled task deleted | defense-evasion | T1070 |
| 4702 | Scheduled task updated | persistence | T1053.005 |
| 4720 | User account created | persistence | T1136 |
| 4726 | User account deleted | defense-evasion | T1070 |
| 4732 | Member added to security group | privilege-escalation | T1078 |
| 4740 | Account locked out | credential-access | T1110 |
| 4756 | Member added to universal group | privilege-escalation | T1078 |
| 5145 | Network share access | lateral-movement | T1021.002 |
| 7045 | Service installed | persistence | T1543.003 |
| 7036 | Service state changed | execution | T1569.002 |
| … (30 total) | | | |

### YARA rules

Place `.yar` / `.yara` files in `$RULES_DIR`. Rules are compiled once at scan time. Path traversal is prevented via `confine_path()`.

### Sigma rules

Place `.yml` / `.yaml` files in `$SIGMA_RULES_DIR`. Supported fields:
- `title`, `level`, `tags` (ATT&CK technique IDs as `attack.TXXXX`)
- `detection.keywords` (list of strings matched against timeline descriptions)
- Any nested detection structure (values extracted as keyword lists)

### Heuristic binary scoring

Each binary is scored 0–10 based on:
- Shannon entropy (> 7.0 → likely packed/encrypted)
- Presence of suspicious strings (`VirtualAlloc`, `CreateRemoteThread`, PowerShell encoded commands, Base64 blobs, C2-like URLs)
- Import hints from PE header
- File magic (MZ / ELF)

---

## IOC Extraction & Enrichment

### IOC types extracted

| Type | Pattern |
|---|---|
| `ip` | IPv4 addresses (non-RFC1918 by default) |
| `domain` | FQDNs with known TLDs |
| `url` | HTTP/HTTPS URLs |
| `sha256` | 64-character hex strings |
| `md5` | 32-character hex strings |

### Enrichment providers

| Provider | IOC types | Env var |
|---|---|---|
| VirusTotal | sha256, md5, ip, domain, url | `AUTO_FORENSICS_VIRUSTOTAL_API_KEY` |
| MalwareBazaar | sha256, md5 | `AUTO_FORENSICS_MALWAREBAZAAR_API_KEY` |
| AbuseIPDB | ip | `AUTO_FORENSICS_ABUSEIPDB_API_KEY` |
| WHOIS | domain | `AUTO_FORENSICS_ENABLE_WHOIS=true` |

Enrichment results are cached in the database (`ioc_enrichment_cache` table) with a TTL controlled by `AUTO_FORENSICS_ENRICHMENT_CACHE_TTL_MINUTES` (default 24 hours).

---

## Database

### Backends

- **SQLite** (default): file at `$HOME/.auto_forensics/app.db`
- **PostgreSQL** (via SQLAlchemy): set `AUTO_FORENSICS_DATABASE_URL=postgresql://...`

### Schema tables

| Table | Description |
|---|---|
| `cases` | Case metadata, status, directory paths |
| `artifacts` | Ingested file manifest per case |
| `findings` | Analysis findings with MITRE mappings |
| `timeline` | Normalised timeline events |
| `case_iocs` | Extracted IOCs per case |
| `ioc_enrichment_cache` | Shared enrichment result cache |
| `case_ioc_enrichments` | Per-case enrichment view |
| `analyst_notes` | Investigator annotations |
| `evidence_hash_log` | SHA-256 chain-of-custody log |
| `audit_log` | Immutable action audit trail |
| `analysis_jobs` | Analysis and enrichment job state |
| `schema_migrations` | Migration history |

### Migrations

Migrations run automatically on service start. To apply manually:
```bash
auto-forensics migrate
```

---

## Security Model

### `SecurityPolicy`

Controls resource limits applied throughout the pipeline:

- `max_file_size_bytes` — files larger than this are skipped
- `max_total_files` — ingestion halts at this limit
- `max_text_bytes` — maximum bytes read as text per file (prevents OOM)
- `follow_symlinks` — whether to follow symlinks during evidence ingestion (default: `False`)

### `confine_path(root, candidate)`

Resolves `candidate` and asserts it is inside `root`. Any path that escapes the boundary raises `SecurityError`. Applied:
- During artifact ingestion
- On every YARA / Sigma rule file
- On asset serving from the web directory
- On archive extraction (zip path traversal prevention)

### `validate_case_id(case_id)`

Case IDs must match `[a-zA-Z0-9_-]{1,64}`. Any other value raises `SecurityError`.

### LLM prompt injection defence

Before constructing LLM prompts, `_sanitize_dict()` strips common injection patterns (`ignore previous instructions`, `system:`, etc.) from all evidence strings. Evidence values are also truncated to 512 characters.

### API authentication

If `AUTO_FORENSICS_API_KEY` is set, every request must include `X-API-Key: <key>`. The key is stored as a SHA-256 hash — the raw key is never persisted.

### Rate limiting

Per-IP rate limiting (default: 240 requests/minute) is enforced by middleware. The counter resets every 60 seconds.

---

## Plugin System

Three plugin registries exist in `plugins.py`:

| Registry | Interface method | Purpose |
|---|---|---|
| `ArtifactParserRegistry` | `parse(path, max_text_bytes)` | Custom artifact parsers |
| `DetectorRegistry` | `detect(events)` | Custom finding generators |
| `EnricherRegistry` | `enrich(ioc)` | Custom IOC enrichers |

### Loading external plugins

Place `.py` files in `$AUTO_FORENSICS_PLUGIN_DIRS`. Each file can export a class or function matching the expected interface. Plugin loading errors are logged (not silently swallowed).

### Registering built-in plugins

```python
registry = PluginRegistry()
registry.register_defaults()
registry.load_external_plugins(config.plugin_dirs)
```

---

## Reports & Exports

### Output files (per case)

| File | Format | Description |
|---|---|---|
| `case_report.json` | JSON | Complete report including all findings, timeline, IOCs |
| `case_report.md` | Markdown | Human-readable summary |
| `case_report.html` | HTML | Browser-viewable report with styling |
| `case_report.pdf` | PDF | Printable report (requires `reportlab`) |
| `attack_navigator_layer.json` | JSON | ATT&CK Navigator v4.x layer |
| `case_stix_bundle.json` | STIX 2.1 | STIX bundle for threat intel sharing |

### Case archive

`export` / `import` commands create a signed zip archive. The manifest includes SHA-256 hashes for every file. Signature is computed as `SHA-256(json(manifest) + api_key_hash)`. Import verifies the signature before extracting.

---

## Testing

```bash
python -m pytest tests/ -q
```

**52 tests, 5 skipped** (optional deps: pyyaml, dpkt, symlink support).

### Test files

| File | What it covers |
|---|---|
| `test_api_endpoints.py` | FastAPI routes, authentication, rate limiting |
| `test_attack_mapper.py` | ATT&CK technique resolution and keyword fallback |
| `test_cli_jobs.py` | CLI job management commands |
| `test_event_detectors.py` | Windows event ID → finding mapping |
| `test_improvements.py` | Bug fixes: JSON decode safety, enrichment lock, sigma edge cases, artifact parsers |
| `test_ioc_pipeline_and_db.py` | IOC extraction, database cache roundtrip |
| `test_migrations.py` | Schema migration idempotency |
| `test_plugin_and_artifact_registry.py` | Plugin registration and dispatch |
| `test_postgres_optional.py` | PostgreSQL backend (skipped if SQLAlchemy absent) |
| `test_security_and_service.py` | End-to-end case lifecycle, path confinement, async jobs |
| `test_sigma_rules.py` | Sigma rule evaluation |
| `test_sqlalchemy_backend.py` | SQLAlchemy backend (skipped if absent) |
| `test_stix_export.py` | STIX bundle generation |
| `test_timeline.py` | Timeline normalisation |
| `test_yara_detector.py` | YARA rule compilation and scanning |

---

## Changelog

### Session 3 (2026-02-19)

**Bug fixes:**
- `service.py`: Added dedicated `_enrichment_lock` to prevent race conditions between concurrent analysis and enrichment jobs
- `sigma_rules.py`: Bounds-safe split in `_extract_attack_technique` — no longer crashes on malformed `attack.` tags with no technique suffix
- `db.py` / `db_sqlalchemy.py`: `get_findings`, `get_timeline`, `get_case_latest_job`, `list_case_jobs` now wrap JSON decode in try/except, returning empty defaults instead of raising on corrupt stored data
- `ioc_enrichment.py`: `urllib.parse.quote(value, safe='')` used consistently to prevent path injection via IOC values in VirusTotal API URLs

**Performance improvements:**
- `pipeline.py`: `scan_candidates` is now a generator expression instead of a full list — reduces peak memory consumption on large evidence directories

**Tests added (`test_improvements.py`):**
- 20 new passing tests covering sigma tag parsing, database JSON decode safety, enrichment lock isolation, artifact parser edge cases, and event detector string event IDs

### Session 2 (prior)

- `event_detectors.py`: Event map expanded to 30 Windows events with full MITRE mappings
- `db.py`: Transaction rollback on connection failure; LIKE escape in search queries
- `pipeline.py`: Exception fallback in `analyze_one`; YARA scan wrapped in try/except; `rglob` depth capped at 20
- `sigma_rules.py`: Specificity improvements; `confine_path()` per rule file
- `ioc_pipeline.py`: 4 MB text guard; extended URL trailing-char strip
- `ioc_enrichment.py`: HTTP 4xx debug logging; separate URLError/TimeoutError handling
- `pdf_report.py`: Full rewrite — page numbers, `…` truncation, all findings included

### Session 1 (prior)

- `yara_detector.py`: Path traversal prevention via `confine_path()`
- `plugins.py`: Silent exception swallowed on plugin load replaced with `logger.error()`
- `artifacts.py`: `ImportError` vs `OSError` specificity
- `binary_analysis.py`: Streaming entropy; string extraction capped at 32 MB
- `llama_workflow.py`: Prompt injection defence via `_sanitize_dict()`
- `dashboard.js` / `dashboard.css`: Client-side input validation with inline error display
- `api.py`: Structured error response format `{error, detail, status_code}`
