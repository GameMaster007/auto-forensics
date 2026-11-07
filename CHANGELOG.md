# Changelog

## [Unreleased] — 0.1.0

### Integrity fixes

- Support managed ingestion on filesystems without hard links using an
  exclusive verified copy, preserving competing files and rolling back
  only unchanged partial data after failure. Refuse invalid finding IDs
  before review writes; retain escaped JSON review notes through replay.
- Keep YARA citations and finding identities relative to the evidence
  root so identical files under different hosts remain distinct and
  replay still matches after evidence relocation.
- Scope durable finding IDs to each case, preserving existing rows in a
  transactional compatibility migration. Failed table rebuilds roll back.
- Preserve distinct cited rows when a detector reuses an ID within one
  case; disambiguate them deterministically and deduplicate exact repeats.
- Enable SQLite foreign keys on each connection, serialize schema setup,
  avoid PostgreSQL duplicate-column transaction failures, and refuse
  database downgrades. Add PostgreSQL-backed CI migration coverage.

- Add a read-only `verify` command with explicit evidence change lists,
  report hash checks, citation file checks, and optional relocated inputs.
- Record parser limits and rule/STIX hashes in manifest version 2;
  reject malformed manifests and stop replay before executing changed inputs.
- Refuse output inside evidence and replay over the original run directory.
  Refuse incomplete file inventories and evidence changes during a run.
- Print the installed package version with `--version`.
- Validate archive metadata and contents before publishing an imported
  case; bound compressed and expanded sizes, reject symlinks/aliases,
  restore custody indexes, and publish exports atomically.
- Declare checksum versus keyed HMAC archive integrity. Read legacy
  archives without treating their public default checksum as a signature.
- Preserve prior evidence and its provenance on incremental ingestion.
  Stage new files, reject conflicting overwrites, and support JSONL.
- Lock review publication across processes, stage complete report files,
  and hash every published format plus the validated review log. Replay
  copies review logs and repeated default replays use fresh directories.

- Keep evidence text inside the HTML report's data string even when it
  contains a closing script tag. Escape quotes in generated table cells.
- Reject negative, zero-row, boolean, and non-integer citation locations.
- Exclude files reached through directory symlinks, including links back
  into the evidence tree. Qualified citation paths do not fall back to
  a different directory with the same filename.
- Preserve multiline CSV fields and cite their final physical line.

First public foundation. The package already contained a case store, a
CLI, and tests. This version makes a fresh install the supported path
and states what the tool will not claim.

### Added

- `Citation` on each finding: artifact id, source file, row or byte
  offset, and SHA-256.
- Findings with no citation that matches this run are dropped before
  the report is written.
- `run_manifest.json` with input hashes, tool version, prompt-template
  hash, model provider, temperature, seed, worker list, and the
  allow-listed tool log.
- `--llm mock` for an offline draft that does not use an API key.
- Evidence is sent to a model only inside a quoted JSON block.
- `Worker`, `ToolRegistry`, and `CaseStore`. The only worker that runs
  is `pipeline`.
- `Finding.worker`, set by the case store rather than by model output.
- Tests for citations, the quote fence, the mock, the manifest, a
  denied tool, and two workers sharing one in-memory store.
- GitHub Actions: ruff, pytest on Python 3.10–3.12, and gitleaks.
- Project docs: licence, contributing, security, code of conduct, and
  `docs/ROADMAP.md`.

### Changed

- Live Ollama and OpenAI-compatible calls use temperature 0.
- The synthetic case uses the documentation address `203.0.113.19`.
- Author metadata is Benjamin Christy. The `pyproject.toml` licence
  field already said MIT. A `LICENSE` file is now in the tree.

### Added after the first foundation commit

- Verifier pass. It re-reads each cited file, checks the hash, and
  drops a claim whose sentences are not in that row. Verdicts are
  stored on the report and the manifest. `--llm mock` uses the offline
  judge. A live model can judge as well, and a failed call leaves the
  rule result in place.
- `auto-forensics replay run_manifest.json`. The canonical report hash
  omits `generated_at`. Live model calls send seed 0.
- Finding and artifact ids that the pipeline writes are derived from
  the record, so a second run of the same input can match.

### Not in this version

- Analyst accept/reject, Plaso/Hayabusa/Chainsaw import, and a
  multi-worker orchestrator. The verifier is a pipeline stage.
- A published precision or recall figure.
