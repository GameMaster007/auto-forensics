# Improvement loop log

Each loop makes one change, then re-runs the lab (40 synthetic cases,
seed 7) and the tests. The hold-out set (40 cases, seed 2026) is never
used to choose a change; it is checked every few loops to catch
overfitting to the lab.

Score = 100 × (0.35 recall + 0.25 precision + 0.15 injection recall +
0.10 no-canary-leak + 0.15 sign-off gate checks), reduced by any crashes.

| Loop | Change | Score | Recall | Precision | Hold-out |
| --- | --- | --- | --- | --- | --- |
| 0 | Baseline on first 30 cases (answer key had a CSV row bug) | 86.55 | 0.902 | 0.598 | - |
| 1 | Fix answer key: CSV rows are cited by file line (header = 1); 40 cases; add hold-out set | 87.65 | 0.926 | 0.610 | 89.38 |
| 2 | Core: new persistence detector (Run/RunOnce, Winlogon, IFEO, Startup folder, tasks and services without an event ID) | 90.61 | 1.000 | 0.624 | |
| 3 | Core: Sysmon process starts are medium only for user-writable paths, encoded PowerShell, or LOLBin download/exec; others are low | 91.91 | 1.000 | 0.676 | |
| 4 | Core: Sysmon DNS/NTP/DHCP and local traffic are low, not medium | 93.32 | 1.000 | 0.733 | |
| 5 | Autopilot: weak injection phrases ("ignore previous instructions", "do not report") need machine-directed context | 95.15 | 1.000 | 0.806 | |
| 6 | Autopilot: password rule needs a secret-looking value; fix `db_password` underscore boundary found by a new test | 97.31 | 1.000 | 0.893 | |
| 7 | Core: small file size is a modifier, not a signal on its own | 100.00 | 1.000 | 1.000 | 100.00 |

After loop 7 the synthetic lab and its hold-out both score 100, so the lab
no longer separates good changes from bad ones. Later loops use real public
attack data (see below) instead of adding more synthetic cases.

## Real attack logs

Development set: EVTX-ATTACK-SAMPLES (278 files, 9 tactic folders).
Hold-out: EVTX-to-MITRE-Attack (293 files), never used to write rules.
"Detected" = at least one medium-or-higher cited finding for the file;
"tactic" = such a finding has the folder's ATT&CK tactic. Every file is
an attack, so these numbers do not measure false alarms; rule precision
is covered by look-alike unit tests in `tests/test_windows_rules.py`.

| Loop | Change | Detected | Tactic | Hold-out detected / tactic |
| --- | --- | --- | --- | --- |
| 8 | Benchmarks built: end-to-end run (`real_evtx.py`, 16 min) and cached detector loop (`evtx_dev.py`, seconds). End-to-end baseline at loop 7 code | 41.0% | 9.2% | |
| 9 | Core: Sysmon recognised by EVTX provider/channel (measured together with the loop 8 dev baseline) | 45.0% | 10.0% | 44.4% / 11.8% |
| 10 | Core: Windows behaviour rule library (`windows_rules.py`, ~60 rules) switched on | 67.6% | 28.0% | |
| 11 | Fix two of my rules: "renamed tool" now checks the name actually differs; "RDP tunnel" needs an RDP logon type. Score drops because those hits were false | 61.9% | 26.4% | |
| 12 | Fix access masks written with leading zeros (0x001fffff); LSASS handle audit (4656/4663), LSASS writing files, memory reads from user folders | 68.4% | 31.8% | |
| 13 | UAC bypass: COM surrogate/MMC shells, auto-elevating binaries started from user folders or loading user-folder DLLs; DLL side-loading; LSASS access by permission bit | 70.9% | 37.6% | 51.2% / 22.1% |
| 14 | Registry tampering: UAC off, PowerShell logging/CLM off, execution policy, Office macro guard, event channels disabled, history wiped, port proxy, new shares, null-session pipes, RID hijack, hidden/new local accounts | 75.5% | 41.8% | |
| 15 | Shells started by browsers, servers, update or print processes; more rundll32/LOLBAS tricks (zipfldr, advpack, pcwutl, desktopimgdownldr, explorer /root, wscript /E:) | 78.8% | 43.3% | |
| 16 | Core parser keeps unnamed `<Data>` and `<UserData>` fields (SQL Server, RDP, WinRM were blank); pipe impersonation (potato attacks), getsystem, WinRM shells, remote DCOM, SQL xp_cmdshell | 82.4% | 46.0% | 55.3% / 23.9% |
| 17 | Rust EVTX reader (10 MB log: 93 s to 0.05 s; cache rebuild 2 min 52 s to 6 s); values normalised so both readers produce identical events (264 of 277 files byte-identical; the rest differ only in BITS file times and binary privilege lists); EVTX reader recorded in the manifest | 82.4% | 46.0% | 55.3% / 23.9% |
| 18 | Precision pass: BITS rule matched 293 events of Microsoft/Google update traffic; vendor update hosts now skipped, local-program BITS jobs (persistence) now caught | 82.7% | 46.4% | |
| 19 | Single-event signals: LSASS silent-exit dump, DSRM password, SID history, SeDebugPrivilege, boot debug/test-signing, Event Log service stopped, local group enumeration, MSI from URL, SQL `sa` failures, PowerShell 800/4103 and obfuscation; Defender detector recognises the EVTX provider | 87.8% | 49.4% | 56.3% / 24.6% |

A third set (Yamato Security and DeepBlueCLI samples from
hayabusa-sample-evtx, 37 files, "dev2") was added at loop 19 because the
gap between the development set and the hold-out showed the rules were
partly fitted to the development samples. It scored 81.1% before any
rule was written for it.

| Loop | Change | Dev | Dev2 | Hold-out (detected / tactic) |
| --- | --- | --- | --- | --- |
| 20 | Compile-after-delivery (csc/vbc), PowerShell v2 downgrade, Windows Audit-CVE exploit events | 87.8% | 89.2% | 56.3% / 24.6% |
| 21 | Active Directory changes from general AD knowledge (not from hold-out misses): delegation, SPN on users, DCShadow SPN, shadow credentials/RBCD and other sensitive attributes, AdminSDHolder, GPO edits, GPP passwords in SYSVOL, ntds.dit/SAM file access | 87.8% | 89.2% | 59.7% / 27.1% |
| 22 | Volume rules: password guessing (10+ failures), spraying (5+ accounts), lockouts, SQL brute force. The first version skipped every rule; the benchmark caught it and it was fixed in the same loop | 87.8% | 89.2% | 60.1% / 27.5% |
| 23 | Robustness test with broken and hostile evidence. Found: one CSV with a 2 MB cell crashed the whole core pipeline (fixed: a file that cannot be parsed becomes a visible `parse_error` event and the rest of the case continues). Kept: the core refuses to publish a report whose evidence text contains NUL rather than altering it (a PR #17 integrity rule with its own tests); the autopilot shows the reason and the other agents still finish. Deep trees (>20 levels) are refused with a clear reason | 87.8% | 89.2% | 60.1% / 27.5% |
| 24 | Injection sentinel folds full-width and compatibility letters and drops zero-width characters before matching; new rule for text hidden with invisible or right-to-left override characters | - | - | lab 100 |
| 25 | Analyst workflow: `status` lists pending findings with severity, title and citation; `decide` takes several ids at once (each still logged separately; no "accept all") | - | - | - |
| 26 | Draft gains an attack chain: medium-or-higher findings grouped by ATT&CK tactic in kill-chain order | - | - | - |
| 27 | Secrets sweep: chat webhooks, Google API keys, cloud storage keys, payment secret keys, JWTs, `user:rid:lm:nt` hash dumps, credential-dumping tool names (medium: backup logs mention ntds.dit). End-to-end benchmark re-run through the full autopilot with the verifier | 87.8% | 49.4% | 278 files in 36.6 s (was 958 s at loop 8, 41.0% / 9.2%) |

## False alarms

All three real-log sets are attacks, so they cannot show false alarms.
`lab/benign.py` generates ordinary Windows activity with real field names
(Office, browsers, updaters, Teams/OneDrive in AppData, EDR agents reading
LSASS, vendor service installs, admin scripts, logons and typos) and counts
medium-or-higher findings. I wrote this generator, so "0" means the rules do
not fire on the ordinary activity I modelled, not that a real network will
produce no false alarms.

| Loop | Change | False alarms in 20,000 benign events | Dev / Dev2 / Hold-out detected |
| --- | --- | --- | --- |
| 28 | Benign benchmark built | 70 (35 per 10k) | 87.8% / 89.2% / 60.1% |
| 29 | Volume rules use sliding time windows per source (guessing 10 in 10 min, spraying 5 accounts in 15 min from one IP); recon needs 3 different commands in 5 min; service-host shell only when it has no arguments | 30 | 87.8% / 89.2% / 60.1% |
| 30 | LSASS reads by installed security products excluded (by install folder, so a renamed tool elsewhere still fires); autoruns that start an installed or well-known app with no script, LOLBin or temp path are not reported; well-known per-user apps (OneDrive, Teams, Zoom...) connecting out are not reported | 0 | 87.8% / 89.2% / 60.1% |

| Loop | Change | Tests / checks |
| --- | --- | --- |
| 31 | Memory agent tested with simulated Volatility output: suspicious command lines flagged and cited by row, one failing image does not stop the others, skipped with a reason when Volatility is missing | 2 new tests |
| 32 | Model-drafted findings that cite a file the sentinel flags as hostile carry a "model read hostile text" warning in the draft | 1 new test |
| 33 | Evidence ZIPs are extracted into the run folder (never the evidence folder) with zip-slip, symlink, case-collision, size, count and zip-bomb checks, then analysed by the core pipeline, sentinel and secrets sweep; findings cite `archive.zip!member` and are verified against the extracted copy | 9 new tests |
| 34 | User guide updated: archives, pending list, attack chain, multi-id decide, hostile-source flag, Windows rules section | docs |
| 35 | README: autopilot section; removed two stale claims (review step and Plaso/Hayabusa import are implemented) | docs |

## Independent review

After loop 36 a separate agent that had not seen this work reviewed the
autopilot for security and integrity defects and confirmed 14 issues, each
with a proof of concept. Each fix below has a regression test in
`tests/test_autopilot_review_fixes.py` that reproduces the attack.

| Loop | Review issue | Fix |
| --- | --- | --- |
| 36 | (CI check) | Full suite run on Python 3.10 with CI's extras: 895 passed; lint clean on 3.12 |
| 37 | #1 evidence text reached the draft through timeline highlights; #8 integrity errors inside an agent were swallowed and agent errors could quote evidence | Highlights keep only tool-assigned event types, well-formed times and scores; integrity errors ("changed", custody, inventory) abort the run with nothing published; other agent failures record only the error type |
| 38 | #2 file names could inject markdown/HTML into the draft and final report | Table text escapes every markdown/HTML control character; file names go in code spans whose fence is longer than any backtick run in the name |
| 39 | #3 evidence and custody.json could be replaced together after signing; signature.json could be forged; #4 draft and manifest could be swapped before signing | Run fingerprint printed at `start` must be typed back at `sign`; export re-checks custody against manifest and signature, re-counts decisions, and checks the fingerprint; optional HMAC seal with `AUTO_FORENSICS_SIGNING_KEY`; export takes the run lock, refuses the run folder and existing reports; malformed log entries refused |
| 40 | #5, #6 crafted fields made some rules take 8-31 s per event (ReDoS) | Unbounded `.*` gaps bounded to 400 chars; PowerShell rule split into two simple checks; fields capped at 8 KB (scripts 64 KB) and lines at 16 KB after Unicode folding; the reviewer's end-to-end DoS cases dropped from 31.2 s and 16.7 s to 0.0-0.1 s; timing-budget tests for every rule |
| 41 | #7 appending `#<string>` to a command line erased it (rules went blind); #13 an event's payload could overwrite `row`, `event_id`, `provider` | Only values made entirely of `<string>` wrappers are unwrapped; payload keys that collide with parser keys are stored as `data_<key>` |
| 42 | #10 UTF-16 text was never scanned; #11 row numbers drifted on U+2028, form feed, 0x85 | Encoding detected from BOM or NUL pattern; lines split on LF only, so rows are physical lines |
| 43 | #12 "drive clean" flagged as injection; `ghostscript_installer` flagged as a token; `PWD=/opt` as a password; two dead injection phrases; BITS vendor exclusion spoofable with `?`/`#`/`@` | Verdict rule needs a machine-directed address; real token formats only; path values excluded; phrases fixed; host part restricted |
| 44 | #9 memory findings were labelled as row-verified | Each non-core finding is labelled with what was actually checked (row re-read / file hash only / verified in archive run), shown in a new "Checked" column |
| 45 | #14 two `start` commands on one folder could overwrite each other | Emptiness re-checked under the lock |
| 46 | Suspected: dead `ad-spn-on-user` rule, unused constant, PsExec's real OriginalFileName, bare-hex registry values | Rule removed (5136 covers SPN changes), constant removed, `psexec.c` added, `0x1`/`0x0` handled |
| 47 | Suspected: files over 8 MB partly scanned without saying so; Cyrillic/Greek look-alike letters dodge the sentinel | "Coverage gaps" section in the draft (partly scanned files, failed agents, unopened archives, disk images); look-alike letters folded to Latin |

After loop 47: 985 tests pass; lab 100; 0 false alarms on 20,000 benign
events; detection unchanged (87.8% / 89.2% / 60.1%).

## Re-review and final loops

The same reviewer re-ran its proofs of concept against loop 47: 11 of 14
fixed, 3 partial, and 8 new defects introduced or exposed by the fixes.

| Loop | Change | Result |
| --- | --- | --- |
| 48 | Re-review requested (fresh proofs of concept against the fixes) | 11 fixed, 3 partial, 8 new |
| 49 | End-to-end benchmark on both real sets with every fix | Dev 87.8% in 38 s; hold-out 60.1% in 157 s, 0 errors, but one hold-out file produced 500 serious findings |
| 50 | Core event-ID findings: one per event ID per file with a count (not one per event); process creation 4688 and PowerShell 4103/4104 are low context, not alerts (content rules still raise the suspicious ones) | Worst file 500 to 42 serious findings; hold-out run 157 s to 27 s; hold-out "detected" 60.1% to 44.7%, because many of those files had been counted as detected only because every process creation raised an alert |
| 51 | Command-line obfuscation rule (caret splitting, `%VAR:~x,y%` substrings, split quotes) | General technique; did not change the hold-out |
| 52 | N2: sealed signature cannot be exported without the key; export needs the signature fingerprint printed by `sign` (kept outside the run folder); fingerprints need 32+ hex characters; final report says sealed or unsealed. N3: `sign` refuses when an agent failed unless `--accept-gaps`, which is recorded in the final report | 5 new tests |
| 53 | N4: core raises a dedicated `IntegrityError` at its integrity checks; the autopilot aborts on that type instead of guessing from message words | A folder named "inventory" no longer aborts a run |
| 54 | N5 text agents scan both the byte-wise and UTF-16 readings, so a fake BOM cannot hide text; N6 an archive member cannot shadow a real file of the same name; N7 archive type read from 4 bytes, whole-archive zip-bomb ratio, run-wide extraction budget, identical archives in two folders both analysed; N8 archive findings labelled honestly, "you" removed from injection context | 5 new tests |
| 55 | N1 padding evasion: whitespace runs collapsed in command lines; token gap widened to 2,000 chars (cost unchanged with 8 KB fields); command lines over 2,000 chars from programs outside Program Files are a medium finding | Reviewer's padding cases now caught; timing budgets still pass |
| 56 | Regression caught by the lab: guessed UTF-16 readings of binaries produced hidden-text alarms; such lines are now scanned only if mostly ordinary text | Lab back to 100 |
| 57 | Regression caught by a new test: soft hyphens (0xAD bytes in binaries) triggered hidden-text; removed from that rule | 1,010 tests pass |

## Where it ended (loop 57)

| Measure | Start | End |
| --- | --- | --- |
| Tests | 771 passed | 1,010 passed (3.13), new tests also pass on 3.10 |
| Synthetic lab / hold-out | 86.55 / 89.38 | 100 / 100 (saturated; see note at loop 7) |
| Real attack logs, dev set (278 files), end to end | 41.0% detected, 9.2% right tactic, 958 s | 86.7%, 49.4%, 37 s |
| Dev2 (37 files, added at loop 19) | 81.1% | 86.5% |
| Hold-out (293 files, never used to write rules) | 44.4% / 11.8% | 45.1% / 25.7% |
| Worst file, serious findings | 500 | 42 |
| False alarms in 20,000 benign events | 70 | 0 |

The hold-out detection rate ends close to where it started because loop 50
stopped counting routine telemetry as detections; the correct-tactic rate
more than doubled. Raising it further needs rules for the Security-log
techniques that set covers, written from ATT&CK knowledge rather than from
its files, and real benign logs to check them against.

## Loop 58: defense evasion and lateral movement

The hold-out showed two weak tactics: defense evasion (10 of 55 files caught)
and lateral movement (5 of 18). 34 rules were added and 4 widened, written from
ATT&CK knowledge and checked only against the development sets, dev2 and the
benign generator. The hold-out was measured once, after the rules were frozen.

Defense evasion: Defender tampering (5001/5010/5012/5013, 5007 exclusions,
`-RemoveDefinitions`), security settings weakened in the registry through
Sysmon or Security 4657 (Defender, UAC, script logging, event channels, firewall,
ETW, NLA, security services set to disabled), auditpol/wevtutil/Sysmon unload,
AMSI and ETW bypass strings, event log files deleted, timestomping (Sysmon 2),
clock changed by a shell (4616), injection into long-running processes (Sysmon
10), process tampering (Sysmon 25), Windows process names outside the Windows
folder, LOLBins loading from user folders, alternate data streams, firewall
opened for remote-access ports or user-folder programs, drivers from user
folders, bcdedit test signing. Lateral movement: NTLM network logon with no
session key, inbound RDP (4624 type 10, 4778, 1149, 21/25, 131), admin share
opened (5140) or mounted, PsExec-style service processes, files written by the
SMB server, wmiexec/smbexec output on `\\127.0.0.1\ADMIN$`, DCOM MMC, remote
PowerShell host sessions, tscon hijack, Restricted Admin/RDP enabled in the
registry, remote `schtasks /s`, `sc \\host`, remote DCOM ProgIDs.

| Measure | Before (loop 57) | After (loop 58) |
| --- | --- | --- |
| Dev detected / tactic (278 files, cached) | 86.7% / 49.4% | 88.5% / 52.5% |
| Dev defense evasion / lateral movement (detected, tactic) | 31/36, 19 · 40/47, 14 | 31/36, 20 · 43/47, 21 |
| Dev2 detected (37 files) | 86.5% | 91.9% |
| Hold-out detected / tactic (293 files) | 45.1% / 25.7% | 50.2% / 29.3% |
| Hold-out defense evasion (detected, tactic) | 10/55, 9 | 15/55, 14 |
| Hold-out lateral movement (detected, tactic) | 5/18, 4 | 10/18, 9 |
| False alarms in 20,000 benign events | 0 | 0 |
| End-to-end dev run (278 files) | 33.2 s, median 1 serious finding | 34.6 s, median 2 |
| Slowest hostile event, all rules | 0.27 s | 0.28 s |

Defense evasion on the hold-out is still the weakest tactic: 40 of 55 files
raise nothing. Two of the new lateral-movement rules are broad: "NTLM logon with
no session key" fired in 12 hold-out files and "admin share opened" in 10, most
of them outside the lateral-movement folder. Lab domains have little ordinary
NTLM and share traffic, and the benign generator models neither, so their real
false-alarm rate is unknown; both are medium severity.
