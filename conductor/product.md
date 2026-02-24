# Product Definition

## Vision
To provide a fast, secure, and automated malware-oriented binary analysis and incident timeline generation framework that empowers security analysts and incident responders.

## Target Audience
- Security Operations Center (SOC) Analysts
- Incident Responders (IR)
- Malware Researchers

## Core Capabilities
- **Case Management:** Full lifecycle tracking of incidents with persistent SQLite/PostgreSQL backend.
- **Evidence Ingestion:** Secure parsing of diverse artifacts including events (JSON, CSV, EVTX), PCAP, Windows Prefetch, Registry hives, MFT, and memory dumps.
- **Malware Analysis:** Automated analysis of binaries with static heuristic scoring, string extraction, YARA/Sigma rule scanning, and plugin-based extensibility.
- **AI-Assisted Triage:** Ollama-compatible Llama workflow for analyzing findings, generating timeline hints, and summarizing cases.
- **Flexible Interfaces:** Cross-platform CLI for automated operations and FastAPI-driven dashboard for browser-based case management.
- **Comprehensive Reporting:** Exportable reports in MD, HTML, JSON, STIX, and PDF formats.