# Changelog

## [Unreleased] — 0.1.0

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

### Not in this version

- Replay, a verifier, analyst accept/reject, Plaso/Hayabusa/Chainsaw
  import, and a multi-worker orchestrator.
- A published precision or recall figure.
