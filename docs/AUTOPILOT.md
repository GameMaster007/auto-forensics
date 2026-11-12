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
| `disk_image` | a disk image is present and the `disk` extra is installed | Opens the image read-only, copies key Windows artefacts into the run folder, then runs the core pipeline, sentinel and secrets sweep on the copies. Findings cite `pc.E01!/C:/path/in/image`. See [Disk images](#disk-images) |

Non-ZIP archives (7z, RAR) are listed by triage but not opened; extract
them into the evidence folder. Making an image of a disk stays out of
scope (see `docs/ROADMAP.md`): the autopilot reads images you already have.

## Disk images

Install the extra once:

```bash
pip install -e ".[disk,evtx]"
```

It adds [dissect.target](https://github.com/fox-it/dissect.target) (and
`dissect.fat` for USB sticks). Without it, a disk image is still hashed in
the custody record, and the draft lists it as a coverage gap that says to
install the `disk` extra.

**What it reads.** Raw/DD images (`.dd`, `.img`, `.raw`, `.001`, `.002`,
...), EnCase images (`.E01` with `.E02`, `.E03`, ... next to it) and VMDK.
Put every segment in the evidence folder; the autopilot opens the first
one and the reader finds the rest. A `.raw` or `.001` file counts as a disk
image only if it starts like one (a partition table or boot sector), so a
memory dump or a split 7-Zip file is not mistaken for one.

**What it copies out.** Only these files, from every volume in the image:

| Kind | Where in the image |
| --- | --- |
| Event logs | `Windows/System32/winevt/Logs/*.evtx` (and old `*.evt`) |
| Registry hives | `SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`, `Amcache.hve`, each user's `NTUSER.DAT` and `UsrClass.dat` |
| Prefetch | `Windows/Prefetch/*.pf` |
| Recent files | LNK files and Jump Lists in each user's `Recent` folder, Office `Recent` |
| Browser history | Chrome and Edge `History`, Firefox `places.sqlite`, Internet Explorer `index.dat` and `WebCacheV01.dat` |
| PowerShell | `PSReadLine/ConsoleHost_history.txt` |
| Scheduled tasks | `Windows/System32/Tasks/**`, `Windows/Tasks/*.job` |
| USB history | `Windows/inf/setupapi.dev.log` (and XP's `setupapi.log`) |
| Recycle Bin | `$Recycle.Bin/*/$I*` (the index files, not the deleted content) |

Documents, pictures and other user files are not copied. Copies go to
`RUN/disk/<image>-<hash>/files/C/...`, never next to the evidence. Each
copy is hashed as it is written and listed in `RUN/disk/disk_images.json`
with the path it came from. A finding about a copy cites the image and the
path inside it, for example
`pc.E01!/C:/Windows/System32/winevt/Logs/Security.evtx`, and the
coordinator re-checks it against the copy just as it does for ZIP members.

**Limits.** At most 5,000 files and 2 GB per run, and 512 MB per file.
A file that is too big, past the budget, or has a name that cannot be
stored safely on Windows (`CON`, `a:b`, a trailing dot, a name that differs
from another only by case) is skipped and listed as a coverage gap. Links
and junctions inside the image are not followed. The NTFS `$MFT` is not
copied by default (it can be hundreds of MB).

**Summary.** `RUN/disk/<image>-<hash>/disk_summary.json` records what
dissect reports cheaply: the OS, host name, time zone, users, user folders,
USB devices, installed programs, run keys, recent files, Recycle Bin and
services (up to 500 rows each), the volumes it found, and the segment
hashes from the custody record. For a volume without Windows, such as a
USB stick, it lists up to 2,000 file names with sizes and times instead.
Anything dissect cannot report becomes a coverage gap; it never stops the run.

**Time and space.** The image is read in full three times: the custody
hash, the core pipeline's own inventory, and the final "has the evidence
changed?" check. For a 7 GB E01 on a laptop SSD expect a few minutes for
each pass (longer from a USB disk). Copying the artefacts reads only those
files. Leave a few GB free on the run folder's disk.

## Review page

```
auto-forensics-autopilot serve            # opens http://127.0.0.1:8765 in your browser
```

The page does everything the commands above do, without typing paths or
fingerprints from memory. It runs on this computer only (127.0.0.1), and
every request needs the session token in the link printed when it starts.

**Choosing the evidence.** A folder browser lists folders (never file
names) and says how many files and bytes a folder holds, so you can check
you picked the right one. Hidden and system folders are left out.

**While a run is going.** The page shows which of the five stages the run
is in (fingerprinting, planning, analysing, re-checking, writing), which
checks are waiting, running, done or failed, and how far the fingerprinting
has got in bytes. Fingerprinting a large disk image takes minutes; the
counter keeps moving.

**Checking a finding by eye.** Opening a finding shows the row it cites,
read again from the evidence at that moment: the line of a text file, the
record of a CSV, JSON or event log, or 256 bytes around the offset for a
binary file. The file's SHA-256 is compared with the custody record first.
If the file has changed, moved or gone, the page says so and shows nothing
from it. Excerpts are capped at 4,000 characters, have control characters
replaced, and are never written to a report or a log. A file is hashed
once and remembered until its size or modified time changes, so ten
findings on one 2 GB image do not hash it ten times. Each core finding
also shows the time of the event it cites, taken from the run's own
timeline (never guessed from text).

**Deciding in batches.** Accepting or rejecting many findings at once
checks the evidence once for the whole batch, then writes one log line per
finding, exactly as single decisions do.

**The signed report.** Export also writes `final_report.html`: one file
with no scripts that loads nothing from the internet, laid out to print.
The page opens it in a new tab through a random link that stops working
after five minutes. Like `final_report.md`, it names who signed and when
but does not print the signature fingerprint; that is in
`final_report.json`.

**Runs that did not finish.** A run that failed, or was cut off when the
window was closed, is listed as failed or incomplete and can be removed
from the list. Removing it moves its folder to `removed/` inside the
workspace (nothing is deleted) and clears the lock it left behind. A run
with a finished draft cannot be removed from the page.

**Disk images.** For a run that read a disk image, the page lists what
`disk_summary.json` recorded: operating system, host name, time zone,
users, USB devices, volumes, and anything that could not be read.

For anyone changing the page, the API under `/api/` is: `info`, `browse`,
`runs` (list and start), `runs/{id}` (progress or the draft; `DELETE`
removes a broken run), `runs/{id}/findings/{finding_id}/evidence`,
`runs/{id}/disks`, `runs/{id}/decide`, `sign`, `export`, `copied` and
`report-link`. `tests/test_autopilot_web_api.py` pins the response shapes.

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
  `final_report.md` and `final_report.html`; rejected ones are listed with
  the analyst's reason.

## Testing it

See `lab/README.md`. The lab builds practice cases with a known answer
key and scores the autopilot, and `lab/real_evtx.py` runs it on public
attack logs.
