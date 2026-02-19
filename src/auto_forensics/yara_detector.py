from __future__ import annotations

import logging
import uuid
from pathlib import Path
from typing import Any

from .models import Finding, TimelineEvent
from .security import confine_path, SecurityError

logger = logging.getLogger(__name__)


def _severity_from_tags(tags: list[str]) -> str:
    lowered = {item.lower() for item in tags}
    if "critical" in lowered:
        return "critical"
    if "high" in lowered:
        return "high"
    if "low" in lowered:
        return "low"
    return "medium"


def _attack_from_meta(meta: dict[str, Any]) -> tuple[str, str, str]:
    tactic = str(meta.get("attack_tactic") or meta.get("tactic") or "execution")
    technique = str(meta.get("attack_technique_id") or meta.get("technique_id") or "")
    sub_technique = str(meta.get("attack_sub_technique") or meta.get("sub_technique") or "")
    return tactic, technique, sub_technique


def _compile_rules(rules_dir: Path) -> list[tuple[Path, Any]]:
    try:
        import yara  # type: ignore
    except Exception:
        return []

    compiled: list[tuple[Path, Any]] = []
    for rule_file in sorted(rules_dir.rglob("*")):
        if not rule_file.is_file():
            continue
        if rule_file.suffix.lower() not in {".yar", ".yara"}:
            continue
        try:
            confine_path(rules_dir, rule_file)
        except SecurityError:
            logger.warning("YARA rule file escapes rules directory, skipping: %s", rule_file)
            continue
        try:
            compiled.append((rule_file, yara.compile(filepath=str(rule_file))))
        except Exception as exc:
            logger.warning("Failed to compile YARA rule %s: %s", rule_file, exc)
            continue
    return compiled


def scan_paths_with_yara(
    files: list[Path],
    rules_dir: Path | None,
    max_file_size_bytes: int = 200 * 1024 * 1024,
) -> tuple[list[Finding], list[TimelineEvent]]:
    if rules_dir is None or not rules_dir.exists():
        return [], []

    compiled_rules = _compile_rules(rules_dir)
    if not compiled_rules:
        return [], []

    findings: list[Finding] = []
    hints: list[TimelineEvent] = []
    for sample in files:
        if not sample.is_file():
            continue
        if sample.stat().st_size > max_file_size_bytes:
            continue

        for rule_file, compiled in compiled_rules:
            try:
                matches = compiled.match(str(sample), timeout=20)
            except Exception as exc:
                logger.debug("YARA match error for %s with rule %s: %s", sample, rule_file, exc)
                continue
            if not matches:
                continue

            for match in matches:
                tags = [str(tag) for tag in getattr(match, "tags", [])]
                meta = getattr(match, "meta", {}) if isinstance(getattr(match, "meta", {}), dict) else {}
                tactic, technique, sub_technique = _attack_from_meta(meta)
                severity = _severity_from_tags(tags)
                rule_name = str(getattr(match, "rule", "yara_rule"))
                findings.append(
                    Finding(
                        finding_id=f"yara-{uuid.uuid4().hex[:12]}",
                        title=f"YARA match: {rule_name}",
                        severity=severity,
                        confidence=0.85,
                        tactic=tactic,
                        evidence=[f"file={sample}", f"rule_file={rule_file}", f"tags={','.join(tags)}"],
                        recommendation="Validate rule context, isolate host if malicious indicators are confirmed.",
                        technique_id=technique,
                        sub_technique=sub_technique,
                        confidence_low=0.7,
                        confidence_high=0.95,
                    )
                )
                hints.append(
                    TimelineEvent(
                        timestamp=None,
                        source="yara",
                        event_type="yara_match",
                        description=f"Rule {rule_name} matched {sample.name}",
                        risk_score=7.5 if severity in {"high", "critical"} else 5.0,
                        tags=["yara", severity],
                        related={
                            "file": str(sample),
                            "rule_name": rule_name,
                            "rule_file": str(rule_file),
                            "tags": tags,
                        },
                    )
                )

    return findings, hints
