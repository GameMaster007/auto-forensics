# Autopilot

Autopilot is a plugin that takes an evidence folder to a cited draft
report with one command. An analyst must then accept or reject every
finding and sign the draft before a final report can be exported.

The core `auto_forensics` package does not depend on it. Uninstall the
plugin and the core still runs.

## Quick start

```
pip install -e ".[evtx,yara]"

# 1. One click: custody record, triage, parallel agents, draft
auto-forensics-autopilot start --input-dir /cases/evidence --output-dir /cases/run-01 --case-id case-01 --actor "B. Christy"

# 2. Read run-01/autopilot_draft.md, list what is pending, then decide
auto-forensics-autopilot status --run-dir /cases/run-01
auto-forensics-autopilot decide --run-dir /cases/run-01 --finding-id win-1a2b3c win-4d5e6f --decision accept --actor "B. Christy"
auto-forensics-autopilot decide --run-dir /cases/run-01 --finding-id sec-9f8e7d --decision reject --actor "B. Christy" --note "admin's scheduled backup"

# 3. Sign once nothing is pending, then export
auto-forensics-autopilot status --run-dir /cases/run-01
auto-forensics-autopilot sign   --run-dir /cases/run-01 --actor "B. Christy"
auto-forensics-autopilot export --run-dir /cases/run-01 --dest /cases/run-01-final
```

## What happens in `start`

| Stage | What it does | File written |
| --- | --- | --- |
| 1. Custody | Hashes every evidence file (SHA-256) and records who, when, and which host | `custody.json` |
| 2. Triage | Sorts files by kind from name, size and magic bytes; picks agents and records why each one runs or is skipped | `triage.json` |
| 3. Agents | Runs the agents below in parallel into one shared case store; every tool call is logged | `core/` and the manifest |
| 4. Re-check | Hashes the evidence again; if anything changed, nothing is published | - |
| 5. Coordinate | Re-checks every non-core citation, drops duplicates, sorts by severity, and writes the draft without quoting evidence text | `autopilot_draft.json`, `autopilot_draft.md`, `autopilot_manifest.json` |

## Agents

| Agent | Runs when | What it finds |
| --- | --- | --- |
| `core_pipeline` | always | The full core pipeline: parsers (EVTX, Sysmon JSON, CSV, Plaso, Hayabusa, Chainsaw), Windows behaviour rules, YARA, Sigma, binary analysis, verifier, replayable manifest |
| `injection_sentinel` | text or binaries present | Text written to steer an AI analyst ("ignore previous instructions", chat-control tokens, "mark this as clean"). Matching files are listed as hostile in the draft |
| `secrets_sweep` | text present | Private keys, cloud keys, API tokens, plaintext passwords, credential-dumping output |
| `memory` | a memory image is present and Volatility 3 is installed | Suspicious process command lines from `windows.cmdline` |
| `archive` | a ZIP archive is present | Extracts the ZIP into the run folder with zip-slip, symlink, size and zip-bomb checks, then runs the core pipeline, sentinel and secrets sweep on the contents. Findings cite `archive.zip!path/inside` |

Disk images and non-ZIP archives (7z, RAR) are listed by triage but not
opened. Export a disk image with Plaso first, or extract other archives
into the evidence folder. Imaging stays out of scope (see `docs/ROADMAP.md`).

## Reading the draft

`autopilot_draft.md` has, in order: a warning listing any hostile files;
an **attack chain** table (medium-or-higher findings grouped by ATT&CK
tactic in kill-chain order); the findings table with where each is cited;
the riskiest timeline events; and which agents ran or were skipped and why.
A finding drafted by a model from a hostile file is marked
**[hostile source: verify by hand]**.

## Windows event rules

The core reads EVTX (Rust `evtx` reader, falling back to `python-evtx`)
and applies about 110 behaviour rules in `src/auto_forensics/windows_rules.py`
covering Sysmon, Security, System, PowerShell, WinRM, DCOM, BITS, SQL Server
and Active Directory events. Volume rules (password guessing and spraying,
lockouts, reconnaissance bursts) count events inside a sliding time window.
Measured results, including false alarms on ordinary activity, are in
`lab/LOOP_LOG.md`.

## Safety rules

- Evidence is opened read-only and is never written. The output folder
  must be outside the evidence folder, and every run needs a new folder.
- Every finding cites a file by SHA-256 and a row or byte offset. A
  finding from a non-core agent also records the SHA-256 of the line it
  matched; the coordinator re-reads that line and drops the finding if
  it does not match.
- The draft never repeats evidence text. Findings name the rule that
  matched. This keeps hostile text out of anything a model reads later.
- `decide` appends to `signoff.jsonl` and, for core findings, to the
  core run's own review log. A second decision needs `--override`, and
  the earlier line stays. A reject needs a reason.
- `sign` refuses while any finding is pending, and refuses if the draft,
  the custody record, or the evidence changed.
- `export` refuses without a valid signature, or if the decision log or
  evidence changed after signing. Only accepted findings reach
  `final_report.md`; rejected ones are listed with the analyst's reason.

## Testing it

See `lab/README.md`. The lab builds practice cases with a known answer
key and scores the autopilot, and `lab/real_evtx.py` runs it on public
attack logs.
