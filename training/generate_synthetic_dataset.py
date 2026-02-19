from __future__ import annotations

import argparse
import csv
import json
import random
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

SYSTEM_PROMPT = "You are an incident response analyst. Always return strict JSON."


@dataclass(slots=True)
class BinaryFeatureSeed:
    path: str
    sha256: str
    entropy: float
    suspicious_score: float
    rationale: list[str]
    string_hits: list[str]
    import_hints: list[str]


@dataclass(slots=True)
class TimelineSeed:
    timestamp: str | None
    event_type: str
    description: str
    source: str


def _iso(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _read_example_events(base_dir: Path) -> list[TimelineSeed]:
    events: list[TimelineSeed] = []
    events_json = base_dir / "events.json"
    persistence_csv = base_dir / "persistence.csv"
    notes_txt = base_dir / "notes.txt"

    if events_json.exists():
        try:
            payload = json.loads(events_json.read_text(encoding="utf-8"))
            if isinstance(payload, list):
                for item in payload:
                    if not isinstance(item, dict):
                        continue
                    events.append(
                        TimelineSeed(
                            timestamp=item.get("timestamp") if isinstance(item.get("timestamp"), str) else None,
                            event_type=str(item.get("event_type", "event")),
                            description=str(item.get("description", "")),
                            source=str(item.get("source", "artifact")),
                        )
                    )
        except json.JSONDecodeError:
            pass

    if persistence_csv.exists():
        with persistence_csv.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                events.append(
                    TimelineSeed(
                        timestamp=row.get("timestamp") or None,
                        event_type=row.get("event_type") or "event",
                        description=row.get("description") or "",
                        source=row.get("source") or "artifact",
                    )
                )

    if notes_txt.exists():
        for line in notes_txt.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if "|" in stripped:
                parts = stripped.split("|", 2)
                if len(parts) == 3:
                    events.append(
                        TimelineSeed(
                            timestamp=parts[0],
                            event_type=parts[1],
                            description=parts[2],
                            source="analyst_note",
                        )
                    )
                    continue
            events.append(
                TimelineSeed(
                    timestamp=None,
                    event_type="analyst_note",
                    description=stripped,
                    source="analyst_note",
                )
            )

    return events


def _make_binary_seed(rng: random.Random, scenario_id: int) -> BinaryFeatureSeed:
    families = [
        ("loader", ["powershell", "cmd.exe", "rundll32"], ["CreateRemoteThread", "WinExec"]),
        ("credential_access", ["mimikatz", "wmic", "net user"], ["VirtualAlloc", "WriteProcessMemory"]),
        ("persistence", ["schtasks", "regsvr32", "powershell"], ["RegSetValueExA", "WinExec"]),
        ("downloader", ["http://", "https://", "powershell"], ["URLDownloadToFileA", "InternetOpenA"]),
    ]
    family, string_pool, import_pool = rng.choice(families)
    score = round(rng.uniform(1.2, 8.4), 2)
    entropy = round(rng.uniform(5.7, 7.9), 4)
    host_index = scenario_id % 25

    hits = rng.sample(string_pool, k=rng.randint(1, min(3, len(string_pool))))
    imports = rng.sample(import_pool, k=rng.randint(1, min(2, len(import_pool))))
    rationale = [
        f"Suspicious strings found: {', '.join(hits)}.",
        f"Risky PE imports found: {', '.join(imports)}.",
    ]
    if entropy >= 7.2:
        rationale.append(f"High entropy ({entropy}) indicates packing or encryption.")
    elif entropy >= 6.8:
        rationale.append(f"Elevated entropy ({entropy}) may indicate obfuscation.")

    sha = f"{scenario_id:08x}{rng.getrandbits(224):056x}"
    path = f"C:/Cases/WS-{host_index:02d}/{family}_payload_{scenario_id:04d}.exe"
    return BinaryFeatureSeed(
        path=path,
        sha256=sha,
        entropy=entropy,
        suspicious_score=score,
        rationale=rationale,
        string_hits=hits,
        import_hints=imports,
    )


def _mutate_event(rng: random.Random, base: TimelineSeed, start: datetime) -> dict[str, Any]:
    ts: str | None
    if base.timestamp:
        ts = base.timestamp
    else:
        ts = _iso(start + timedelta(seconds=rng.randint(0, 1200)))
    return {
        "timestamp": ts,
        "source": base.source,
        "event_type": base.event_type,
        "description": base.description,
        "risk_score": round(rng.uniform(2.0, 7.6), 2),
        "tags": ["artifact"],
        "related": {},
    }


def _build_observation(binary: BinaryFeatureSeed, nearby: list[dict[str, Any]]) -> dict[str, Any]:
    observations = [
        f"Binary score {binary.suspicious_score} with entropy {binary.entropy}.",
        f"Suspicious string hits include: {', '.join(binary.string_hits)}.",
        f"Potentially risky imports include: {', '.join(binary.import_hints)}.",
    ]
    if nearby:
        observations.append(f"Nearby timeline includes {nearby[0].get('event_type', 'event')} activity.")

    likely_behaviors: list[str] = []
    if any("powershell" in item for item in binary.string_hits):
        likely_behaviors.append("Scripted post-execution command activity")
    if any("http" in item for item in binary.string_hits):
        likely_behaviors.append("C2 or payload retrieval over web protocols")
    if any("schtasks" in item for item in binary.string_hits):
        likely_behaviors.append("Scheduled task persistence")
    if any("mimikatz" in item for item in binary.string_hits):
        likely_behaviors.append("Credential access behavior")
    if not likely_behaviors:
        likely_behaviors.append("Likely execution and defense evasion workflow")

    return {
        "observations": observations[:10],
        "likely_behaviors": likely_behaviors,
        "preliminary_risk": max(0.0, min(1.0, round(binary.suspicious_score / 8.5, 2))),
    }


def _severity(score: float) -> str:
    if score >= 7.0:
        return "high"
    if score >= 4.5:
        return "medium"
    return "low"


def _build_findings(binary: BinaryFeatureSeed, nearby: list[dict[str, Any]]) -> dict[str, Any]:
    severity = _severity(binary.suspicious_score)
    confidence = max(0.5, min(0.97, round(0.48 + (binary.suspicious_score / 12.0), 2)))
    tactic = "execution"
    technique = "T1059"
    if any("schtasks" in hit for hit in binary.string_hits):
        tactic = "persistence"
        technique = "T1053"
    elif any("mimikatz" in hit for hit in binary.string_hits):
        tactic = "credential-access"
        technique = "T1003"
    elif any("http" in hit for hit in binary.string_hits):
        tactic = "command-and-control"
        technique = "T1071"

    finding = {
        "title": "Potential malware execution chain detected",
        "severity": severity,
        "confidence": confidence,
        "confidence_low": max(0.0, round(confidence - 0.15, 2)),
        "confidence_high": min(1.0, round(confidence + 0.12, 2)),
        "tactic": tactic,
        "technique_id": technique,
        "sub_technique": "",
        "evidence": binary.rationale[:4],
        "recommendation": "Isolate host, collect volatile data, and pivot on binary hash in telemetry.",
    }

    hints: list[dict[str, Any]] = []
    for event in nearby[:2]:
        hints.append(
            {
                "timestamp": event.get("timestamp"),
                "event_type": event.get("event_type", "model_inference"),
                "description": f"Correlated activity: {event.get('description', 'unknown event')}",
                "risk_score": max(0.0, min(10.0, round(binary.suspicious_score + 1.3, 2))),
                "tags": ["model", "correlated"],
            }
        )
    if not hints:
        hints.append(
            {
                "timestamp": None,
                "event_type": "binary_risk_assessed",
                "description": "Model-derived risk for suspicious binary.",
                "risk_score": max(0.0, min(10.0, round(binary.suspicious_score + 1.0, 2))),
                "tags": ["model", "binary"],
            }
        )

    attack_chain = [
        "Initial execution",
        "Post-execution scripting",
        "Persistence or C2 follow-on",
    ]
    if technique == "T1003":
        attack_chain.insert(2, "Credential access activity")

    return {
        "findings": [finding],
        "timeline_hints": hints,
        "attack_chain": attack_chain,
    }


def _build_summary(findings: list[dict[str, Any]], timeline: list[dict[str, Any]]) -> dict[str, Any]:
    high_count = sum(1 for f in findings if str(f.get("severity", "")).lower() == "high")
    confidence = 0.55
    if findings:
        confidence = round(sum(float(f.get("confidence", 0.5)) for f in findings) / len(findings), 2)

    assessment = "Evidence suggests likely malicious execution with follow-on activity."
    if high_count > 0:
        assessment = "High-risk malicious execution is likely; immediate containment is warranted."

    actions = [
        "Isolate affected endpoint from network.",
        "Acquire memory and volatile process data.",
        "Block observed hashes and network indicators.",
        "Hunt for related process and persistence artifacts.",
    ]

    chain = ["Execution", "Persistence", "Command and Control"]
    if any("credential" in str(item.get("description", "")).lower() for item in timeline):
        chain.insert(2, "Credential Access")

    return {
        "assessment": assessment,
        "priority_actions": actions[:5],
        "attack_chain": chain[:8],
        "confidence": max(0.0, min(1.0, confidence)),
    }


def _messages(user_prompt: str, assistant_obj: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
        {
            "role": "assistant",
            "content": json.dumps(assistant_obj, ensure_ascii=True, separators=(",", ":")),
        },
    ]


def _build_records(
    rng: random.Random,
    scenario_count: int,
    seed_events: list[TimelineSeed],
) -> list[dict[str, Any]]:
    start = datetime(2026, 2, 17, 12, 45, tzinfo=timezone.utc)
    default_events = [
        TimelineSeed(
            timestamp=None,
            event_type="process_start",
            description="Unknown executable launched from temporary directory.",
            source="sysmon",
        ),
        TimelineSeed(
            timestamp=None,
            event_type="network_connection",
            description="Outbound connection to uncommon external address.",
            source="firewall",
        ),
    ]
    catalog = seed_events or default_events
    records: list[dict[str, Any]] = []

    for scenario_id in range(scenario_count):
        binary = _make_binary_seed(rng, scenario_id)
        event_count = rng.randint(2, min(6, len(catalog)))
        selected = rng.sample(catalog, k=event_count)
        nearby = [_mutate_event(rng, item, start + timedelta(minutes=scenario_id * 2)) for item in selected]

        first_pass = _build_observation(binary, nearby)
        first_prompt = (
            "First-pass triage. Return strict JSON with keys "
            "'observations' (array of <=10 strings), 'likely_behaviors' (array), "
            "and 'preliminary_risk' (0..1).\n\n"
            f"Binary Feature JSON:\n{json.dumps(asdict(binary), indent=2)}\n\n"
            f"Nearby timeline JSON:\n{json.dumps(nearby, indent=2)}"
        )
        records.append(
            {
                "task": "first_pass",
                "messages": _messages(first_prompt, first_pass),
                "metadata": {"scenario_id": scenario_id},
            }
        )

        second_pass = _build_findings(binary, nearby)
        second_prompt = (
            "Second-pass attack-chain analysis. Return strict JSON with keys "
            "'findings' (array), 'timeline_hints' (array), and 'attack_chain' (array). "
            "Finding object keys: title,severity,confidence,confidence_low,confidence_high,tactic,"
            "technique_id,sub_technique,evidence,recommendation. "
            "Timeline hint keys: timestamp,event_type,description,risk_score,tags. "
            "Use ISO timestamp or null.\n\n"
            f"First pass observations:\n{json.dumps(first_pass, indent=2)}\n\n"
            f"Binary Feature JSON:\n{json.dumps(asdict(binary), indent=2)}\n\n"
            f"Nearby timeline JSON:\n{json.dumps(nearby, indent=2)}"
        )
        records.append(
            {
                "task": "second_pass",
                "messages": _messages(second_prompt, second_pass),
                "metadata": {"scenario_id": scenario_id},
            }
        )

        summary = _build_summary(second_pass["findings"], nearby + second_pass["timeline_hints"])
        summary_prompt = (
            "You are writing an incident summary. Return strict JSON with keys "
            "'assessment', 'priority_actions' (array of <=5), 'attack_chain' (array), "
            "and 'confidence' (0..1).\n\n"
            f"Findings:\n{json.dumps(second_pass['findings'], indent=2)}\n\n"
            f"Timeline:\n{json.dumps(nearby + second_pass['timeline_hints'], indent=2)}"
        )
        records.append(
            {
                "task": "summary",
                "messages": _messages(summary_prompt, summary),
                "metadata": {"scenario_id": scenario_id},
            }
        )

    rng.shuffle(records)
    return records


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=True) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic SFT dataset for Auto Forensics LLM tuning.")
    parser.add_argument(
        "--examples-dir",
        type=Path,
        default=Path("examples") / "case1" / "artifacts",
        help="Path to seed artifacts directory.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("training") / "data",
        help="Output directory for train/validation JSONL files.",
    )
    parser.add_argument("--scenario-count", type=int, default=260, help="Synthetic scenario count.")
    parser.add_argument("--validation-ratio", type=float, default=0.1, help="Validation split ratio.")
    parser.add_argument("--seed", type=int, default=42, help="Random seed.")
    args = parser.parse_args()

    rng = random.Random(args.seed)
    seed_events = _read_example_events(args.examples_dir)
    records = _build_records(rng, max(10, args.scenario_count), seed_events)

    val_count = int(len(records) * max(0.01, min(0.4, args.validation_ratio)))
    val_count = max(1, val_count)
    valid = records[:val_count]
    train = records[val_count:]

    args.output_dir.mkdir(parents=True, exist_ok=True)
    train_path = args.output_dir / "train.jsonl"
    valid_path = args.output_dir / "valid.jsonl"
    manifest_path = args.output_dir / "manifest.json"

    _write_jsonl(train_path, train)
    _write_jsonl(valid_path, valid)

    task_counts: dict[str, int] = {}
    for item in records:
        key = str(item.get("task", "unknown"))
        task_counts[key] = task_counts.get(key, 0) + 1

    manifest = {
        "created_at": _iso(datetime.now(timezone.utc)),
        "seed": args.seed,
        "scenario_count": args.scenario_count,
        "total_records": len(records),
        "train_records": len(train),
        "valid_records": len(valid),
        "task_breakdown": task_counts,
        "files": {
            "train": str(train_path),
            "valid": str(valid_path),
        },
    }
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
