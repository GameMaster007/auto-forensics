# Roadmap

This is the work that follows the 0.1.0 foundation. Nothing here is a
promise of a date. The pitch stays the same: AI drafts, the analyst
verifies, everything is cited.

The project does not publish precision, recall, or timing numbers.
Those belong in a later evaluation issue, after a public case has been
run and the misses have been counted.

## Priority

| Item | State in this tree |
| --- | --- |
| 1. Mandatory citations. Drop a claim that does not cite an ingested row and hash. | The report keeps a finding only when its citation matches an artifact hashed in this run. The check is that the pointer exists. It does not re-read the row and decide whether the sentence is supported. Sigma keyword matches have no row citation, so they are dropped. |
| 2. Ingest Plaso, Hayabusa, and Chainsaw output. | Not started. The parsers in this tree read a small set of teaching formats. |
| 3. Run manifest and replay. | `run_manifest.json` records input hashes, tool version, prompt-template hash, provider, temperature, seed (always null), the tool-call log, the worker list, and the report hash. Replay is not implemented. Two runs of the same input do not share a report hash, because the report contains timestamps. |
| 4. Verifier. Re-fetch each cited row and check that it supports the claim. | Not started. `limits.verifier` in the manifest is `not-run`. |
| 5. Local model through Ollama, offline. | `--llm ollama` calls a local endpoint at temperature 0. The demo and the tests use `--llm mock` and do not need a model or an API key. |
| 6. Analyst accept or reject, logged on the finding. | `review_status` is stored and defaults to `unverified`. There is no command or control that changes it. |
| 7. Import pcaplens findings. | Not started. |

## Phase 2: more than one worker

Do not build an orchestrator on top of the current pipeline until the
seams below are the ones it calls. They are in the tree so a later
change can add workers without inventing a second finding type.

What exists now:

- `Worker` in `src/auto_forensics/workers.py`. `run_case` is the only
  worker, and its name is `pipeline`.
- `ToolRegistry` in `src/auto_forensics/tools.py`. The pipeline's
  evidence and drafting stages are allow-listed. A name that is not on
  the list is refused and still written to the tool log. The log is
  copied into the manifest. It stores the tool name, the worker, and a
  status. It does not store evidence text.
- `CaseStore` and `MemoryCaseStore` in `src/auto_forensics/case_store.py`.
  Workers submit findings through `add_findings`. The store sets
  `Finding.worker`, so a model response cannot choose that name.
- Findings already carry citations and a worker name. Two workers can
  write into one `MemoryCaseStore`. A unit test covers that. No
  production path runs a second worker.

What is planned, and is not in the running path:

- An orchestrator that selects workers and feeds them one store.
- Further workers, for example a verifier worker distinct from the
  pipeline.
- A `CaseStore` implementation on the durable case database. Today
  `DatabaseBackend` is that database, and `run_case` does not open it.
  The service saves the finished report afterwards. Those are two
  stores, not one.

`PluginRegistry` stays the loader for parsers and detectors. It is not
the tool allow-list. Folding the two together would hide which calls
were permitted.

## Evaluation

A later change should run one public case, such as M57-Jean, and
publish the misses as well as the hits. Do not score a case that was
used to tune prompts. Do not put a number in the README until that run
exists.

## Out of scope

Imaging, a timeline viewer, endpoint collection, and a model trained
for this project. Plaso, Hayabusa, and Chainsaw remain the parsers.
This repository drafts a cited brief on top of their output once that
import exists.
