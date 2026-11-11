"""Fast detector loop on public EVTX samples.

Parsing EVTX is the slow part of a run, so this parses each file once,
caches the events, and then scores the core detectors on the cache in a
few seconds. Use ``real_evtx.py`` to confirm a result end to end.

    python lab/evtx_dev.py --root EVTX-ATTACK-SAMPLES --cache /tmp/evtx-cache.pkl
"""

from __future__ import annotations

import argparse
import json
import pickle
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any

from real_evtx import SERIOUS, tactic_of  # noqa: E402  (run from lab/)

from auto_forensics.artifacts import _ensure_provenance, load_evtx_artifacts
from auto_forensics.event_detectors import findings_from_artifact_events
from auto_forensics.models import ArtifactEvent
from auto_forensics.plugins import PluginRegistry


def _parse(path_text: str) -> tuple[str, list[ArtifactEvent]]:
    path = Path(path_text)
    events = load_evtx_artifacts(path)
    _ensure_provenance(events, path, path.name)
    return path_text, events


def load_cache(root: Path, cache: Path, workers: int) -> dict[str, list[ArtifactEvent]]:
    if cache.is_file():
        data = pickle.loads(cache.read_bytes())
        if data.get("root") == str(root):
            return data["events"]
    files = sorted(str(p) for p in root.rglob("*.evtx") if p.is_file())
    with ProcessPoolExecutor(max_workers=workers) as pool:
        events = dict(pool.map(_parse, files, chunksize=4))
    cache.write_bytes(pickle.dumps({"root": str(root), "events": events}))
    return events


def detect(events: list[ArtifactEvent], registry: PluginRegistry) -> list[Any]:
    return findings_from_artifact_events(events) + registry.detectors.detect(events, [], [])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--json", type=Path, default=None)
    parser.add_argument("--show-missed", action="store_true")
    parser.add_argument("--without", nargs="*", default=[], help="Detector names to leave out, for comparison.")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    cache = load_cache(root, args.cache, args.workers)
    registry = PluginRegistry()
    registry.register_defaults()
    registry.detectors.detectors = [d for d in registry.detectors.detectors if d.name not in args.without]
    by: dict[str, Counter] = defaultdict(Counter)
    rows = []
    rule_hits: Counter = Counter()
    for path_text, events in sorted(cache.items()):
        path = Path(path_text)
        tactic = tactic_of(path, root) or "unlabelled"
        findings = [f for f in detect(events, registry) if f.severity in SERIOUS and f.citations]
        detected = bool(findings)
        matched = any(f.tactic == tactic for f in findings)
        rule_hits.update({f.title for f in findings})
        by[tactic]["total"] += 1
        by[tactic]["detected"] += int(detected)
        by[tactic]["tactic"] += int(matched)
        rows.append({"file": str(path.relative_to(root)), "tactic": tactic, "detected": detected,
                     "tactic_match": matched, "events": len(events), "serious": len(findings),
                     "ids": sorted({str(e.metadata.get("event_id")) for e in events})[:12]})
    total = len(rows)
    labelled = [r for r in rows if r["tactic"] != "unlabelled"]
    summary = {
        "files": total,
        "detection_rate": round(sum(r["detected"] for r in rows) / total, 4),
        "tactic_match_rate": round(sum(r["tactic_match"] for r in labelled) / max(1, len(labelled)), 4),
        "median_serious": sorted(r["serious"] for r in rows)[total // 2],
        "by_tactic": {k: f"{v['detected']}/{v['total']} det, {v['tactic']} tac" for k, v in sorted(by.items())},
        "top_rules": rule_hits.most_common(15),
    }
    print(json.dumps(summary, indent=1))
    if args.show_missed:
        for r in rows:
            if not r["detected"]:
                print("MISSED", r["tactic"], r["file"], r["events"], r["ids"])
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps({**summary, "rows": rows}, indent=1) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
