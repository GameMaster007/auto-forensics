from __future__ import annotations

import logging
import uuid
from pathlib import Path
from typing import Any

from .models import Finding, TimelineEvent
from .security import confine_path, SecurityError

logger = logging.getLogger(__name__)


# MITRE ATT&CK tactic names as they appear in Sigma rule tags (with both
# hyphenated and underscore forms to handle different Sigma rule authors).
_MITRE_TACTICS: frozenset[str] = frozenset({
    "initial_access", "initial-access",
    "execution",
    "persistence",
    "privilege_escalation", "privilege-escalation",
    "defense_evasion", "defense-evasion",
    "credential_access", "credential-access",
    "discovery",
    "lateral_movement", "lateral-movement",
    "collection",
    "command_and_control", "command-and-control",
    "exfiltration",
    "impact",
})

# Normalise tactic names to the hyphenated form used throughout this codebase.
_TACTIC_NORMALISE: dict[str, str] = {
    "initial_access": "initial-access",
    "privilege_escalation": "privilege-escalation",
    "defense_evasion": "defense-evasion",
    "credential_access": "credential-access",
    "lateral_movement": "lateral-movement",
    "command_and_control": "command-and-control",
}


def _extract_attack_technique(tags: list[str]) -> tuple[str, str]:
    for tag in tags:
        clean = tag.strip().lower()
        if clean.startswith("attack.t"):
            parts = clean.split("attack.", 1)
            if len(parts) == 2 and parts[1]:
                return parts[1].upper(), ""
    return "", ""


def _extract_attack_tactic(tags: list[str]) -> str:
    """Return the first MITRE ATT&CK tactic found in *tags*, or empty string."""
    for tag in tags:
        clean = tag.strip().lower()
        if not clean.startswith("attack."):
            continue
        suffix = clean[len("attack."):]
        if suffix in _MITRE_TACTICS:
            return _TACTIC_NORMALISE.get(suffix, suffix)
    return ""


def _detection_keywords(rule: dict[str, Any]) -> list[str]:
    detection = rule.get("detection")
    if not isinstance(detection, dict):
        return []
    keywords = detection.get("keywords")
    if isinstance(keywords, list):
        return [str(item).strip() for item in keywords if str(item).strip()]

    values: list[str] = []
    for value in detection.values():
        if isinstance(value, list):
            values.extend(str(item).strip() for item in value if str(item).strip())
        elif isinstance(value, dict):
            for inner in value.values():
                if isinstance(inner, list):
                    values.extend(str(item).strip() for item in inner if str(item).strip())
    return values


def _timeline_match_count(timeline: list[TimelineEvent], keywords: list[str]) -> int:
    if not keywords:
        return 0
    count = 0
    lowered_keywords = [k.lower() for k in keywords]
    for event in timeline:
        blob = f"{event.event_type} {event.source} {event.description}".lower()
        if any(keyword in blob for keyword in lowered_keywords):
            count += 1
    return count


def evaluate_sigma_rules(timeline: list[TimelineEvent], rules_dir: Path | None) -> list[Finding]:
    if rules_dir is None or not rules_dir.exists():
        return []
    try:
        import yaml  # type: ignore
    except ImportError:
        logger.debug("pyyaml not installed; Sigma rule evaluation skipped")
        return []

    findings: list[Finding] = []
    for rule_path in sorted(rules_dir.rglob("*")):
        if not rule_path.is_file() or rule_path.suffix.lower() not in {".yml", ".yaml"}:
            continue
        try:
            confine_path(rules_dir, rule_path)
        except SecurityError:
            logger.warning("Sigma rule file escapes rules directory, skipping: %s", rule_path)
            continue
        try:
            payload = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
        except OSError as exc:
            logger.warning("Could not read Sigma rule %s: %s", rule_path, exc)
            continue
        except yaml.YAMLError as exc:
            logger.warning("YAML parse error in Sigma rule %s: %s", rule_path, exc)
            continue
        if not isinstance(payload, dict):
            continue

        title = str(payload.get("title") or rule_path.stem)
        level = str(payload.get("level") or "medium").lower()
        tags = [str(tag) for tag in payload.get("tags", [])] if isinstance(payload.get("tags"), list) else []
        keywords = _detection_keywords(payload)
        matched = _timeline_match_count(timeline, keywords)
        if matched == 0:
            continue

        technique_id, sub_technique = _extract_attack_technique(tags)
        tactic = _extract_attack_tactic(tags) or "detection"
        confidence = min(0.95, 0.55 + min(0.35, matched * 0.05))
        findings.append(
            Finding(
                finding_id=f"sigma-{uuid.uuid4().hex[:12]}",
                title=f"Sigma rule match: {title}",
                severity=level if level in {"critical", "high", "medium", "low"} else "medium",
                confidence=confidence,
                tactic=tactic,
                evidence=[f"rule={rule_path}", f"matched_events={matched}", *keywords[:5]],
                recommendation="Review matched events and validate against host/network context.",
                technique_id=technique_id,
                sub_technique=sub_technique,
                confidence_low=max(0.0, confidence - 0.2),
                confidence_high=min(1.0, confidence + 0.1),
            )
        )
    return findings
