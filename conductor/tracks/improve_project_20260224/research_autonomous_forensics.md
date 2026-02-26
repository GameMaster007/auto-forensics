# Research: Autonomous Forensics Implementation

**Date**: 2026-02-26

## 1. Executive Summary
The project has undergone a major feature expansion focusing on autonomous forensic capabilities. New components include a `ForensicAgent` for one-shot case solving, a `DropWatcher` for automated directory monitoring, and a `DiskMounter` for artifact extraction from disk images. The implementation appears complete and verified by 127 passing tests, though the git state remains uncommitted and several files are untracked.

## 2. Technical Context
- **ForensicAgent** (`src/auto_forensics/agent.py:80`): Implements a zero-interaction pipeline: `init` → `ingest` → `analyze` → `conclusions` → `report`.
- **DiskMounter** (`src/auto_forensics/disk_image.py:108`): Handles mounting of E01, VHD, VMDK, and raw images on Windows (via Arsenal Image Mounter) and Linux (via libewf/losetup).
- **DropWatcher** (`src/auto_forensics/watcher.py:126`): Polls a "drop" directory for new images or folders, triggering automated processing via `AutoForensicsService.process_drop_item`.
- **CLI Integration** (`src/auto_forensics/cli.py:910`): New commands `solve`, `watch`, `extract`, `scan`, `scan-dir`, `conclusions`, `timeline-filter`, `iocs`, `audit`, `hash` added to the main entry point.

## 3. Findings & Analysis
- **Case Discovery**: `agent.py` and `watcher.py` use heuristic folder/file discovery. `Case` folders are automatically identified if they start with "Case" (case-insensitive).
- **Artifact Extraction**: `disk_image.py` targets specific Windows artifacts (`SYSTEM`, `SOFTWARE`, `NTUSER.DAT`, `.evtx`, `$MFT`, etc.) during volume walks.
- **Service Layer**: `AutoForensicsService` now acts as the central coordinator, managing async jobs for analysis and enrichment, and providing the entry point for drop-folder processing.
- **Audit Logging**: All autonomous actions (extraction, ingestion, analysis) are recorded in the SQLite audit log.

## 4. Technical Constraints
- **External Dependencies**: Disk mounting on Windows requires `aim_cli.exe` (Arsenal Image Mounter) to be on the PATH.
- **Python Dependencies**: Optional modules like `pefile`, `yara-python`, `python-evtx`, and `python-registry` are required for full forensic depth.
- **Path Security**: All ingestion paths are validated against `allowed_ingest_roots` to prevent directory traversal.

## 5. Architecture Documentation
- **Async Job Pattern**: Analysis and enrichment are handled via `ThreadPoolExecutor` with state tracked in the database and a local memory cache for live status.
- **Plugin System**: `PluginRegistry` is used to load artifact parsers and binary analyzers, allowing the autonomous agent to leverage new detection logic without modification.
- **Heuristic Conclusions**: `service.py:1037` implements a non-LLM conclusion engine that calculates risk verdicts based on severity distribution and MITRE ATT&CK coverage.
