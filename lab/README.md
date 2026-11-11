# Test lab

Three ways to measure the autopilot. Results from each improvement loop
are in `LOOP_LOG.md`.

## 1. Synthetic cases with an answer key

```
python lab/generate.py --out lab/cases --cases 40 --seed 7
python lab/run_lab.py --cases lab/cases --json lab/results/latest.json
```

Each case mixes attack traces, ordinary activity (including look-alikes
such as an email that says "ignore the previous instructions from IT"),
and sometimes text planted to steer an AI analyst, with a hidden canary
string. Nothing in it is real malware. The scorer reports recall,
precision, injection detection, canary leaks, and whether the sign-off
gate refuses every shortcut (export before signing, signing after the
evidence changed, a tampered draft or decision log).

Keep a second set with another seed (`--seed 2026`) as a hold-out and do
not tune against it.

## 2. Public attack logs

```
git clone --depth 1 https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
git clone --depth 1 https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack
pip install -e ".[evtx]"

# fast: parse once, cache, score the detectors (seconds after the first run)
cd lab && python evtx_dev.py --root ../EVTX-ATTACK-SAMPLES --cache /tmp/attack.pkl --show-missed

# end to end: every file through `autopilot start`
python lab/real_evtx.py --root EVTX-ATTACK-SAMPLES --json lab/results/real.json
```

Every sample is an attack, so these numbers measure detection and the
tactic label, not false alarms. Use EVTX-ATTACK-SAMPLES to develop rules
and EVTX-to-MITRE-Attack as the hold-out.

## 3. Full practice cases (manual download)

These need a download on your own computer. Unzip or export them into an
evidence folder, then run `auto-forensics-autopilot start`.

| Case | What it has | Answers |
| --- | --- | --- |
| [NIST CFReDS Data Leakage Case](https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html) | Windows 7 disk image (E01) and USB images | Official answer PDF |
| [DFIR Madness: The Stolen Szechuan Sauce](https://www.iblue.team/ctf-challenges/dfir-madness-ctf-challenges/case-001-szechuan-sauce) | Disk images, memory dumps, event logs, PCAP for one incident | Community write-ups |
| [MemLabs](https://github.com/stuxnet999/MemLabs) | Windows memory dumps, easy to hard | Flags, community write-ups |
| [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) | JSON event exports with ATT&CK labels | YAML metadata per dataset |

Disk images must be turned into a Plaso export first
(`log2timeline.py` then `psort.py -o l2tcsv`); the autopilot reads the
export, not the raw image.
