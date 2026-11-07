from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from .ids import stable_id
from .models import Citation, Finding, TimelineEvent
from .security import SecurityError, bounded_tree_paths, read_limited_text, sha256_file, stays_in_tree

logger = logging.getLogger(__name__)


def _extract_attack_technique(tags: list[str]) -> tuple[str, str]:
    for tag in tags:
        if not isinstance(tag, str):
            continue
        clean = tag.strip().lower()
        if re.fullmatch(r"attack\.t\d{4}(?:\.\d{3})?", clean):
            return clean.removeprefix("attack.").upper(), ""
    return "", ""


def _keyword_selection(rule: dict[str, Any]) -> tuple[list[str], bool] | None:
    """Support one literal keyword selector and its optional |all modifier.

    Never flatten field maps, filters, or boolean conditions into an OR
    search. Unsupported rules are explicitly skipped by the caller.
    """
    detection = rule.get("detection")
    if not isinstance(detection, dict):
        return None
    selectors = {key: value for key, value in detection.items() if key != "condition"}
    if len(selectors) != 1:
        return None
    selector, keywords = next(iter(selectors.items()))
    condition = detection.get("condition", "keywords" if selector == "keywords" else None)
    if not isinstance(selector, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", selector) or condition != selector:
        return None
    match_all = isinstance(keywords, dict) and set(keywords) == {"|all"}
    if match_all:
        keywords = keywords["|all"]
    if not isinstance(keywords, list) or not 1 <= len(keywords) <= 256 or any(
        not isinstance(value, str) or not value.strip() or len(value) > 4096 or any(char in value for char in "*?\\")
        for value in keywords
    ):
        return None
    return sorted(set(keywords)), match_all


def _logsource_constraints(rule: dict[str, Any]) -> dict[str, str] | None:
    value = rule.get("logsource", {})
    if not isinstance(value, dict) or value.keys() - {"category", "product", "service", "definition"}:
        return None
    if any(not isinstance(item, str) for item in value.values()):
        return None
    return {key: item.casefold() for key, item in value.items() if key != "definition"}


def evaluate_sigma_rules(
    timeline: list[TimelineEvent], rules_dir: Path | None, *, diagnostics: dict[str, Any] | None = None,
) -> list[Finding]:
    diagnostics = diagnostics if diagnostics is not None else {}
    diagnostics.update(evaluated_rules=0, skipped_rules=0, skipped=[], skipped_details_truncated=False, available=True)
    if rules_dir is None or not rules_dir.exists():
        return []
    try:
        import yaml  # type: ignore
    except ImportError:
        logger.debug("pyyaml not installed; Sigma rule evaluation skipped")
        diagnostics["available"] = False
        return []

    findings: list[Finding] = []
    root = rules_dir.resolve()

    def skipped(path: Path, reason: str) -> None:
        diagnostics["skipped_rules"] += 1
        if len(diagnostics["skipped"]) < 1000:
            diagnostics["skipped"].append({"rule": str(path.relative_to(root)), "reason": reason})
        else:
            diagnostics["skipped_details_truncated"] = True

    for rule_path in sorted(bounded_tree_paths(root)):
        if not stays_in_tree(rule_path, root) or rule_path.suffix.lower() not in {".yml", ".yaml"}:
            continue
        try:
            payload = yaml.safe_load(read_limited_text(rule_path, 4 * 1024 * 1024))
        except (OSError, SecurityError) as exc:
            logger.warning("Could not read Sigma rule %s: %s", rule_path, exc)
            skipped(rule_path, "unreadable_or_over_size_limit")
            continue
        except yaml.YAMLError as exc:
            logger.warning("YAML parse error in Sigma rule %s: %s", rule_path, exc)
            skipped(rule_path, "invalid_yaml")
            continue
        if not isinstance(payload, dict):
            skipped(rule_path, "not_a_rule_object")
            continue

        selection = _keyword_selection(payload)
        constraints = _logsource_constraints(payload)
        if selection is None or constraints is None or payload.get("correlation") or payload.get("filter"):
            logger.warning("Unsupported Sigma semantics skipped: %s", rule_path)
            skipped(rule_path, "unsupported_semantics")
            continue
        diagnostics["evaluated_rules"] += 1
        keywords, match_all = selection
        title = payload.get("title")
        title = title[:256] if isinstance(title, str) and title.strip() else rule_path.stem
        level = payload.get("level")
        level = level.lower() if isinstance(level, str) else "medium"
        tags = [tag for tag in payload.get("tags", [])[:128] if isinstance(tag, str)] if isinstance(payload.get("tags"), list) else []
        technique_id, sub_technique = _extract_attack_technique(tags)
        rule_digest = sha256_file(rule_path)
        for event in timeline:
            logsource = event.related.get("logsource")
            logsource = logsource if isinstance(logsource, dict) else {}
            if any(logsource.get(key) != value for key, value in constraints.items()):
                continue
            raw = event.related.get("citation")
            try:
                citation = Citation(**raw) if isinstance(raw, dict) else None
            except TypeError:
                continue
            if citation is None or not citation.is_complete():
                continue
            blob = f"{event.event_type} {event.source} {event.description}".casefold()
            matched = [keyword for keyword in keywords if keyword.casefold() in blob]
            if not matched or (match_all and len(matched) != len(keywords)):
                continue
            findings.append(Finding(
                finding_id=stable_id("sigma", title, rule_digest, citation.source_file, citation.row, citation.offset),
                title=f"Sigma rule match (keyword subset): {title}",
                severity=level if level in {"critical", "high", "medium", "low"} else "medium",
                confidence=0.6,
                tactic="detection",
                evidence=[f"rule_file={rule_path.relative_to(root)}", "matched_events=1", *matched[:5]],
                recommendation="Review matched events and validate against host/network context.",
                technique_id=technique_id,
                sub_technique=sub_technique,
                confidence_low=0.4,
                confidence_high=0.7,
                citations=[citation],
            ))
            if len(findings) > 10_000:
                raise SecurityError("Sigma keyword matches exceed the finding limit (10000)")
    return findings
