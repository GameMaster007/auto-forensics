# Changelog

## [Unreleased] — 0.1.0

### Autopilot plugin and detection

- New `auto_forensics_autopilot` package and `auto-forensics-autopilot`
  command: custody record, triage, parallel agents (core pipeline,
  injection sentinel, secrets sweep, memory), coordinator, and a sign-off
  gate that blocks export until every finding is decided and signed.
  See `docs/AUTOPILOT.md`.
- Windows behaviour rules (`windows_rules.py`) for Sysmon, Security,
  System, PowerShell, WinRM, DCOM and SQL Server events.
- Persistence detector; Sysmon process and network findings graded by
  behaviour instead of all-medium; Sysmon recognised from the EVTX
  provider; small binary size is no longer a signal on its own.
- EVTX: the Rust `evtx` reader is preferred (about 30x faster end to end,
  up to ~1800x on large logs) with `python-evtx` as the fallback. Unnamed
  `<Data>` values and `<UserData>` fields are now kept. Timestamps are
  normalised to milliseconds (`2026-02-17T13:25:12.000Z`) and hex,
  boolean and wrapped string values to one form, so both readers produce
  the same events. Reports from earlier builds will not replay byte-for-byte.
- Test lab (`lab/`): synthetic cases with an answer key, a hold-out set,
  and benchmarks on public EVTX attack samples. Loop results: `lab/LOOP_LOG.md`.

### Integrity fixes

- Require HMAC on keyed version-2 archive imports, refusing an
  attacker-selected public-checksum downgrade before case publication.
  Preserve legacy archives that match the configured key.
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
