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
