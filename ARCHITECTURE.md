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
4. Persist findings/timeline (`db.py`)
5. Render reports (`case_report.json`, `case_report.md`)
6. Query overview/report (`overview`, `report`, API endpoints)

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
