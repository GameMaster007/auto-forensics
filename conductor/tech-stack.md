# Tech Stack

## Language
- **Python (>=3.10):** Primary programming language.

## Backend & Frameworks
- **FastAPI:** High-performance web framework for the API backend.
- **Uvicorn:** ASGI web server for FastAPI.

## Database & ORM
- **SQLAlchemy:** ORM for managing database operations.
- **SQLite / PostgreSQL:** Supported database backends for case management and timeline storage.

## Forensic Libraries & Tooling
- **pefile:** Windows PE binary analysis.
- **python-evtx:** Windows Event Log parsing.
- **dpkt:** PCAP parsing.
- **python-registry:** Windows Registry hive parsing.
- **yara-python:** YARA rule execution.
- **pyyaml:** Sigma rule loading.
- **volatility3:** Memory dump analysis.

## Utility & Reporting
- **rich:** Rich text and beautiful formatting in the CLI.
- **reportlab:** PDF report generation.

## Frontend
- **Vanilla HTML/CSS/JS:** Built-in dashboard views rendered by FastAPI.