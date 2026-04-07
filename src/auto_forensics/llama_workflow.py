from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.request
import uuid
from dataclasses import asdict
from typing import Any

from .models import BinaryFeature, Finding, TimelineEvent

logger = logging.getLogger(__name__)

# Patterns that may indicate prompt-injection attempts embedded in evidence data.
_INJECTION_PATTERN = re.compile(
    r"(ignore\s+(previous|prior|above|all)\s+instructions?|"
    r"you\s+are\s+now\s+a|"
    r"disregard\s+(all\s+)?previous|"
    r"system\s*:\s*|"
    r"<\s*system\s*>|"
    r"<\s*/?\s*instructions?\s*>|"
    r"\[INST\]|\[\/INST\])",
    re.IGNORECASE,
)

_MAX_PROMPT_FIELD_LEN = 512  # truncate individual evidence strings to limit token size


def _sanitize_text(value: str) -> str:
    """Strip potential prompt-injection sequences from an evidence string."""
    cleaned = _INJECTION_PATTERN.sub("[REDACTED]", value)
    if len(cleaned) > _MAX_PROMPT_FIELD_LEN:
        cleaned = cleaned[:_MAX_PROMPT_FIELD_LEN] + "...[truncated]"
    return cleaned


def _sanitize_dict(obj: Any, depth: int = 0) -> Any:
    """Recursively sanitize string values in a dict/list structure."""
    if depth > 6:
        return obj
    if isinstance(obj, str):
        return _sanitize_text(obj)
    if isinstance(obj, dict):
        return {k: _sanitize_dict(v, depth + 1) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize_dict(item, depth + 1) for item in obj]
    return obj


def _safe_float(v: Any, default: float = 0.5) -> float:
    try:
        return float(v)
    except Exception:
        return default


class LlamaWorkflow:
    def __init__(
        self,
        endpoint: str,
        model: str,
        timeout_seconds: int = 60,
        provider: str = "ollama",
        api_key: str | None = None,
    ):
        self.endpoint = endpoint.rstrip("/")
        self.model = model
        self.timeout_seconds = timeout_seconds
        self.provider = provider
        self.api_key = api_key

    def _call_ollama(self, prompt: str) -> dict[str, Any] | None:
        payload = {
            "model": self.model,
            "stream": False,
            "format": "json",
            "prompt": prompt,
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.endpoint}/api/generate",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                parsed = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            return None

        text = parsed.get("response", "")
        if not isinstance(text, str):
            return None
        try:
            result = json.loads(text)
            if isinstance(result, dict):
                return result
        except json.JSONDecodeError:
            return None
        return None

    def _call_openai_compatible(self, prompt: str) -> dict[str, Any] | None:
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are an incident response analyst. Always return strict JSON.",
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
            "temperature": 0.2,
        }
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        req = urllib.request.Request(
            f"{self.endpoint.rstrip('/')}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                parsed = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            return None

        choices = parsed.get("choices", []) if isinstance(parsed, dict) else []
        if not isinstance(choices, list) or not choices:
            return None
        first = choices[0] if isinstance(choices[0], dict) else {}
        message = first.get("message", {}) if isinstance(first.get("message", {}), dict) else {}
        content = message.get("content", "")
        if not isinstance(content, str):
            return None
        try:
            result = json.loads(content)
            if isinstance(result, dict):
                return result
        except json.JSONDecodeError:
            return None
        return None

    def _call(self, prompt: str) -> dict[str, Any] | None:
        if self.provider == "openai_compatible":
            return self._call_openai_compatible(prompt)
        return self._call_ollama(prompt)

    def analyze_binary(
        self, binary: BinaryFeature, nearby_events: list[TimelineEvent]
    ) -> tuple[list[Finding], list[TimelineEvent]]:
        sanitized_binary = _sanitize_dict(asdict(binary))
        sanitized_events = _sanitize_dict([asdict(e) for e in nearby_events])

        observe_prompt = (
            "First-pass triage. Return strict JSON with keys "
            "'observations' (array of <=10 strings), 'likely_behaviors' (array), "
            "and 'preliminary_risk' (0..1).\n\n"
            f"Binary Feature JSON:\n{json.dumps(sanitized_binary, indent=2)}\n\n"
            f"Nearby timeline JSON:\n{json.dumps(sanitized_events, indent=2)}"
        )
        observations = self._call(observe_prompt) or {}

        prompt = (
            "Second-pass attack-chain analysis. Return strict JSON with keys "
            "'findings' (array), 'timeline_hints' (array), and 'attack_chain' (array). "
            "Finding object keys: title,severity,confidence,confidence_low,confidence_high,tactic,technique_id,sub_technique,evidence,recommendation. "
            "Timeline hint keys: timestamp,event_type,description,risk_score,tags. "
            "Use ISO timestamp or null.\n\n"
            f"First pass observations:\n{json.dumps(observations, indent=2)}\n\n"
            f"Binary Feature JSON:\n{json.dumps(sanitized_binary, indent=2)}\n\n"
            f"Nearby timeline JSON:\n{json.dumps(sanitized_events, indent=2)}"
        )
        model_out = self._call(prompt)
        if model_out is None:
            return self._heuristic_fallback(binary)

        findings_raw = model_out.get("findings", [])
        hints_raw = model_out.get("timeline_hints", [])
        findings: list[Finding] = []
        timeline_hints: list[TimelineEvent] = []

        if isinstance(findings_raw, list):
            for item in findings_raw:
                if not isinstance(item, dict):
                    continue
                findings.append(
                    Finding(
                        finding_id=f"fdg-{uuid.uuid4().hex[:10]}",
                        title=str(item.get("title", "Unspecified finding")),
                        severity=str(item.get("severity", "medium")).lower(),
                        confidence=max(0.0, min(1.0, _safe_float(item.get("confidence"), 0.6))),
                        tactic=str(item.get("tactic", "unknown")),
                        technique_id=str(item.get("technique_id", "")),
                        sub_technique=str(item.get("sub_technique", "")),
                        evidence=[str(x) for x in item.get("evidence", [])][:10]
                        if isinstance(item.get("evidence"), list)
                        else [],
                        recommendation=str(item.get("recommendation", "")),
                        confidence_low=max(0.0, min(1.0, _safe_float(item.get("confidence_low"), 0.5))),
                        confidence_high=max(0.0, min(1.0, _safe_float(item.get("confidence_high"), 0.9))),
                    )
                )

        if isinstance(hints_raw, list):
            for item in hints_raw:
                if not isinstance(item, dict):
                    continue
                tags_raw = item.get("tags", [])
                timeline_hints.append(
                    TimelineEvent(
                        timestamp=item.get("timestamp") if isinstance(item.get("timestamp"), str) else None,
                        source="llama",
                        event_type=str(item.get("event_type", "model_inference")),
                        description=str(item.get("description", "Llama-generated timeline hint")),
                        risk_score=max(0.0, min(10.0, _safe_float(item.get("risk_score"), 4.0))),
                        tags=[str(t) for t in tags_raw] if isinstance(tags_raw, list) else [],
                        related={"binary_sha256": binary.sha256},
                    )
                )

        if not findings:
            return self._heuristic_fallback(binary)
        return findings, timeline_hints

    def summarize_case(
        self, findings: list[Finding], timeline: list[TimelineEvent]
    ) -> dict[str, Any] | None:
        sanitized_findings = _sanitize_dict([asdict(f) for f in findings])
        sanitized_timeline = _sanitize_dict([asdict(t) for t in timeline])
        prompt = (
            "You are writing an incident summary. Return strict JSON with keys "
            "'assessment', 'priority_actions' (array of <=5), 'attack_chain' (array), "
            "and 'confidence' (0..1).\n\n"
            f"Findings:\n{json.dumps(sanitized_findings, indent=2)}\n\n"
            f"Timeline:\n{json.dumps(sanitized_timeline, indent=2)}"
        )
        out = self._call(prompt)
        if not out:
            return None
        return {
            "assessment": str(out.get("assessment", "")),
            "priority_actions": [
                str(x) for x in out.get("priority_actions", [])[:5]
            ]
            if isinstance(out.get("priority_actions"), list)
            else [],
            "attack_chain": [str(x) for x in out.get("attack_chain", [])[:8]]
            if isinstance(out.get("attack_chain"), list)
            else [],
            "confidence": max(0.0, min(1.0, _safe_float(out.get("confidence"), 0.5))),
        }

    def _heuristic_fallback(self, binary: BinaryFeature) -> tuple[list[Finding], list[TimelineEvent]]:
        return heuristic_fallback(binary)


def heuristic_fallback(binary: BinaryFeature) -> tuple[list[Finding], list[TimelineEvent]]:
    severity = "high" if binary.suspicious_score >= 4 else "medium"
    finding = Finding(
        finding_id=f"fdg-{uuid.uuid4().hex[:10]}",
        title="Heuristic malware risk signal",
        severity=severity,
        confidence=min(0.95, 0.4 + (binary.suspicious_score / 10.0)),
        tactic="execution",
        evidence=binary.rationale[:5],
        recommendation=(
            "Isolate affected host, collect memory image, and pivot on the SHA256 hash "
            "across endpoint and network telemetry."
        ),
    )
    hint = TimelineEvent(
        timestamp=None,
        source="heuristic",
        event_type="binary_risk_assessed",
        description=f"Heuristic score {binary.suspicious_score} for {binary.path}",
        risk_score=min(10.0, 1.5 + binary.suspicious_score),
        tags=["binary", "triage", severity],
        related={"binary_sha256": binary.sha256},
    )
    return [finding], [hint]
