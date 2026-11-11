"""Benchmark the autopilot on public attack event logs.

Each .evtx file is run as its own case. A file counts as detected when
the draft has a medium-or-higher finding that cites it, and as
tactic-matched when such a finding's tactic equals the folder's ATT&CK
tactic. Every sample is an attack, so this measures detection, not false
alarms; ``noise`` reports how many serious findings a file produced, as a
rough guide to alert volume.

    git clone --depth 1 https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
    python lab/real_evtx.py --root EVTX-ATTACK-SAMPLES --json lab/results/real-08.json
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import tempfile
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from auto_forensics_autopilot.orchestrator import start

SERIOUS = {"medium", "high", "critical"}
TACTICS = {
    "initial access", "execution", "persistence", "privilege escalation", "defense evasion",
    "credential access", "discovery", "lateral movement", "collection", "command and control",
    "exfiltration", "impact",
}


def tactic_of(path: Path, root: Path) -> str | None:
    """Folder name gives the tactic: 'Credential Access' or 'TA0006-Credential Access'."""
    for part in path.relative_to(root).parts[:-1]:
        name = re.sub(r"^TA\d{4}\s*-\s*", "", part).strip().lower()
        if name in TACTICS:
            return name.replace(" ", "-")
    return None


def run_one(evtx: Path, root: Path, work: Path, index: int) -> dict[str, Any]:
    evidence = work / f"ev-{index}"
    evidence.mkdir(parents=True)
    shutil.copy2(evtx, evidence / evtx.name)
    tactic = tactic_of(evtx, root)
    started = time.monotonic()
    try:
        draft = start(input_dir=evidence, output_dir=work / f"run-{index}", case_id=f"real-{index}", llm="mock")
    except Exception as exc:  # noqa: BLE001
        return {"file": str(evtx.relative_to(root)), "tactic": tactic, "error": f"{type(exc).__name__}: {exc}"}
    serious = [f for f in draft["findings"] if f["severity"] in SERIOUS]
    shutil.rmtree(evidence, ignore_errors=True)
    shutil.rmtree(work / f"run-{index}", ignore_errors=True)
    return {
        "file": str(evtx.relative_to(root)),
        "tactic": tactic,
        "seconds": round(time.monotonic() - started, 3),
        "detected": bool(serious),
        "tactic_match": any(f["tactic"] == tactic for f in serious) if tactic else None,
        "serious": len(serious),
        "titles": sorted({f["title"] for f in serious}),
        "agent_errors": [a["name"] for a in draft["agents"] if a["status"] != "ok"],
    }


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    ok = [r for r in rows if "error" not in r]
    by: dict[str, Counter] = defaultdict(Counter)
    for r in ok:
        key = r["tactic"] or "unlabelled"
        by[key]["total"] += 1
        by[key]["detected"] += int(r["detected"])
        by[key]["tactic"] += int(bool(r["tactic_match"]))
    labelled = [r for r in ok if r["tactic"]]
    detection = sum(r["detected"] for r in ok) / len(ok) if ok else 0.0
    tactic_rate = sum(bool(r["tactic_match"]) for r in labelled) / len(labelled) if labelled else 0.0
    serious = sorted(r["serious"] for r in ok)
    return {
        "files": len(rows),
        "errors": [r["file"] + ": " + r["error"] for r in rows if "error" in r],
        "detection_rate": round(detection, 4),
        "tactic_match_rate": round(tactic_rate, 4),
        "median_serious_findings": serious[len(serious) // 2] if serious else 0,
        "max_serious_findings": serious[-1] if serious else 0,
        "seconds_total": round(sum(r["seconds"] for r in ok), 1),
        "by_tactic": {k: f"{v['detected']}/{v['total']} detected, {v['tactic']} tactic-matched"
                      for k, v in sorted(by.items())},
        "missed": sorted(r["file"] for r in ok if not r["detected"]),
        "agent_errors": sorted({e for r in ok for e in r["agent_errors"]}),
        "rows": rows,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--json", type=Path, default=None)
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    files = sorted(p for p in root.rglob("*.evtx") if p.is_file())[: args.limit]
    with tempfile.TemporaryDirectory(prefix="af-real-") as tmp:
        rows = [run_one(path, root, Path(tmp), i) for i, path in enumerate(files)]
    summary = summarize(rows)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: summary[k] for k in (
        "files", "detection_rate", "tactic_match_rate", "median_serious_findings", "max_serious_findings",
        "seconds_total")}, indent=2))
    print(json.dumps(summary["by_tactic"], indent=1))
    if summary["errors"] or summary["agent_errors"]:
        print("errors:", summary["errors"][:5], summary["agent_errors"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
