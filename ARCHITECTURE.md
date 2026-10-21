# Auto Forensics Application Architecture

## Core Components

- `auto_forensics/security.py`:
  - input/path validation
  - file-size and text-size guards
  - case ID hardening
- `auto_forensics/config.py`:
  - environment-driven configuration
  - cross-platform data paths
  - security and API runtime settings
- `auto_forensics/db.py`:
  - SQLite persistence for cases, artifacts, findings, timeline
- `auto_forensics/db_sqlalchemy.py`:
  - optional SQLAlchemy backend for SQLite/PostgreSQL via `AUTO_FORENSICS_DATABASE_URL`
- `auto_forensics/db_backend.py`:
  - typed database backend protocol shared by SQLite and SQLAlchemy implementations
- `auto_forensics/migrations.py`:
  - versioned schema migration steps and latest schema version tracking
- `auto_forensics/case_manager.py`:
  - secure evidence ingestion and indexing
- `auto_forensics/pipeline.py`:
  - artifact parsing, binary analysis plugins, timeline generation, report exports
- `auto_forensics/plugins.py`:
  - parser/analyzer/detector/enricher/reporter registries
  - optional external plugin auto-loading from configured directories
- `auto_forensics/service.py`:
  - application service layer orchestrating case lifecycle
- `auto_forensics/api.py`:
  - FastAPI interface and secure dashboard serving
- `auto_forensics/cli.py`:
  - operations entrypoint for Windows/Linux terminal workflows

## Data Flow

1. Create case (`init` / `POST /api/cases`)
2. Ingest evidence (`ingest` / `POST /api/cases/{id}/ingest`)
3. Analyze (`analyze` / `POST /api/cases/{id}/analyze`)
4. Keep a finding only when its citation matches an artifact hashed in this run (`citations.py`)
5. Persist findings, citations, and timeline
6. Write `case_report.json` and `run_manifest.json`
7. Query overview/report (`overview`, `report`, API endpoints)

## Citations and the run manifest

`Citation` stores `artifact_id`, `source_file`, `sha256`, and either `row` or `offset`. `drop_uncited` removes a finding whose citations do not match the catalog built from this run. The catalog entry is kept, not the copy a model returned.

`run_manifest.json` records input hashes, the tool version, the prompt-template hash, model provider, temperature, and the SHA-256 of `case_report.json`. Temperature is 0 for a live Ollama or OpenAI-compatible call. It is null for the offline mock, which does not sample. `seed` is null. The manifest does not replay the run.

## Workers, tools, and the case store

`run_case` is the only worker. Its name is `pipeline`. Stages that
read evidence or draft text are invoked through `ToolRegistry`, and
each attempt is stored on `MemoryCaseStore` and copied into the
manifest. `PluginRegistry` is unchanged: it loads parsers and
detectors and is not that allow-list.

`DatabaseBackend` is still the durable database behind `init` and
`analyze`. `run_case` does not open it. A `CaseStore` backed by that
database, and an orchestrator that runs more than one worker, are
planned and are not called. See `docs/ROADMAP.md`.

Evidence sent to a model is JSON inside a `<<<EVIDENCE_DATA` fence. The instruction text does not contain evidence values.

## Security Highlights

- Strict identifier and input validation
- Directory confinement and optional ingest root allowlist
- API key authentication for server mode
- per-client API rate limiting
- Trusted host and CORS restrictions
- CSP and anti-caching headers for dashboard/API responses
- Prepared SQL statements only

## Cross-Platform Notes

- Uses `pathlib` and standard Python filesystem APIs
- No OS-specific shell dependencies in application runtime
- Works in Windows PowerShell and Linux shells with same CLI semantics
