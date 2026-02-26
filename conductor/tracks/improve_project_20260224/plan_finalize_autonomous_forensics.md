# Finalize Autonomous Forensics Implementation Plan

## Overview
This plan focuses on finalizing the "Autonomous Forensics" feature set, cleaning up the uncommitted git state, and ensuring the new components (`ForensicAgent`, `DiskMounter`, `DropWatcher`) are fully integrated and documented.

## Scope Definition
### In Scope
- Staging and committing all new and modified files related to the autonomous forensics update.
- Verifying the `ForensicAgent` and `DropWatcher` integration with the existing `AutoForensicsService`.
- Refactoring any leftover debug logic or boilerplate in the new files.
- Finalizing the `Case/` directory as a formal example/test case.

### Out of Scope
- Implementing new forensic parsers or analyzers beyond the current set.
- Modifying the core `Pipeline` execution logic except for bug fixes.

## Current State Analysis
- **Codebase**: 127 tests passing, covering new components (`test_disk_image.py`, `test_watcher.py`).
- **Files**: 8 untracked files and 19 modified files (`git status`).
- **Features**: `auto-forensics solve` and `auto-forensics watch` are implemented but not committed.
- **Evidence**: `Case/` directory contains a successful analysis run (M57-Jean case).

## Implementation Phases
### Phase 1: Git Cleanup & Staging
- **Goal**: Bring the repository into a clean, committed state.
- **Steps**:
  1. [ ] Add untracked files: `agent.py`, `disk_image.py`, `watcher.py`, and related tests.
  2. [ ] Stage modified core files: `service.py`, `api.py`, `cli.py`, `pyproject.toml`, `config.py`, etc.
  3. [ ] Verify staging with `git status`.
- **Verification**: `git status` should show only staged changes.

### Phase 2: Final Integration & Verification
- **Goal**: Ensure the autonomous features work in the current environment.
- **Steps**:
  1. [ ] Run all tests again: `pytest -v`.
  2. [ ] Verify `auto-forensics solve` using the `Case/` directory.
  3. [ ] Verify `auto-forensics watch` with a dummy drop folder.
- **Verification**: `pytest` passes 100%; `solve` generates a correct report.

### Phase 3: Refactoring & Slop Removal
- **Goal**: Purge technical debt and optimize the new code.
- **Steps**:
  1. [ ] Remove any `print()` statements or unused imports in `agent.py` and `watcher.py`.
  2. [ ] Standardize logging across new modules.
  3. [ ] Review `service.py` for "AI slop" or redundant logic in `process_drop_item`.
- **Verification**: Code passes linting (if available) and review.

### Phase 4: Final Documentation & Commit
- **Goal**: Finalize documentation and commit the work.
- **Steps**:
  1. [ ] Review `ARCHITECTURE.md` and `README.md` for accuracy.
  2. [ ] Draft and execute the commit message.
- **Verification**: `git log` shows the final commit; all docs are up-to-date.
