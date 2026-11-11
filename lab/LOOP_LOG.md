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
