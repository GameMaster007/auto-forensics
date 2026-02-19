from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import Finding


@dataclass(slots=True)
class AttackTechnique:
    technique_id: str
    name: str
    tactics: list[str]


def _extract_attack_external_id(obj: dict[str, Any]) -> str:
    refs = obj.get("external_references", [])
    if not isinstance(refs, list):
        return ""
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        source = str(ref.get("source_name", "")).lower()
        ext_id = str(ref.get("external_id", ""))
        if source in {"mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"} and ext_id:
            return ext_id
    return ""


def _extract_tactics(obj: dict[str, Any]) -> list[str]:
    phases = obj.get("kill_chain_phases", [])
    if not isinstance(phases, list):
        return []
    out: list[str] = []
    for phase in phases:
        if not isinstance(phase, dict):
            continue
        phase_name = str(phase.get("phase_name", "")).strip()
        if phase_name:
            out.append(phase_name)
    return out


def load_attack_techniques(stix_path: Path | None) -> dict[str, AttackTechnique]:
    if stix_path is None or not stix_path.exists():
        return {}
    try:
        payload = json.loads(stix_path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    objects = payload.get("objects", []) if isinstance(payload, dict) else []
    if not isinstance(objects, list):
        return {}

    mapping: dict[str, AttackTechnique] = {}
    for item in objects:
        if not isinstance(item, dict):
            continue
        if item.get("type") != "attack-pattern":
            continue
        technique_id = _extract_attack_external_id(item)
        if not technique_id:
            continue
        mapping[technique_id] = AttackTechnique(
            technique_id=technique_id,
            name=str(item.get("name", technique_id)),
            tactics=_extract_tactics(item),
        )
    return mapping


def _keyword_technique_fallback(finding: Finding) -> str:
    text = f"{finding.title} {' '.join(finding.evidence)} {finding.recommendation}".lower()
    if "powershell" in text or "cmd.exe" in text:
        return "T1059"
    if "service" in text and ("install" in text or "create" in text):
        return "T1543.003"
    if "scheduled" in text and "task" in text:
        return "T1053.005"
    if "logon" in text and "failed" in text:
        return "T1110"
    if "logon" in text:
        return "T1078"
    return ""


def apply_attack_mapping(findings: list[Finding], techniques: dict[str, AttackTechnique]) -> list[Finding]:
    for finding in findings:
        if not finding.technique_id:
            finding.technique_id = _keyword_technique_fallback(finding)
        if not finding.technique_id:
            continue
        if finding.technique_id not in techniques and "." in finding.technique_id:
            parent = finding.technique_id.split(".", 1)[0]
            if parent in techniques:
                finding.sub_technique = finding.technique_id
                finding.technique_id = parent

        info = techniques.get(finding.technique_id)
        if info is None:
            continue
        if (not finding.tactic or finding.tactic == "unknown") and info.tactics:
            finding.tactic = info.tactics[0]
    return findings


def build_attack_navigator_layer(
    case_id: str,
    findings: list[Finding],
    techniques: dict[str, AttackTechnique],
) -> dict[str, Any]:
    score_by_technique: dict[str, float] = {}
    for finding in findings:
        tid = finding.technique_id
        if not tid:
            continue
        score_by_technique[tid] = max(score_by_technique.get(tid, 0.0), finding.confidence)

    techniques_payload: list[dict[str, Any]] = []
    for tid, confidence in sorted(score_by_technique.items()):
        technique = techniques.get(tid)
        comment = ""
        if technique is not None:
            comment = technique.name
        techniques_payload.append(
            {
                "techniqueID": tid,
                "score": round(confidence * 100),
                "comment": comment,
            }
        )

    tactic_counts = Counter(f.tactic for f in findings if f.tactic)
    metadata = [{"name": tactic, "value": str(count)} for tactic, count in sorted(tactic_counts.items())]
    return {
        "name": f"Auto Forensics {case_id}",
        "version": "4.6",
        "domain": "enterprise-attack",
        "description": f"Automatically generated ATT&CK coverage for case {case_id}",
        "techniques": techniques_payload,
        "metadata": metadata,
        "gradient": {
            "colors": ["#ffe9d9", "#f7a65a", "#e67e22", "#c84f00"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#f4f4f4",
        "selectTechniquesAcrossTactics": True,
    }
