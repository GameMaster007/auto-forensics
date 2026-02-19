from __future__ import annotations

import uuid

from .models import ArtifactEvent, BinaryFeature, Finding, TimelineEvent


def _finding(
    title: str,
    severity: str,
    tactic: str,
    evidence: list[str],
    technique_id: str = "",
) -> Finding:
    return Finding(
        finding_id=f"plg-{uuid.uuid4().hex[:12]}",
        title=title,
        severity=severity,
        confidence=0.72,
        tactic=tactic,
        evidence=evidence[:8],
        recommendation="Validate scope and pivot to endpoint/network telemetry for confirmation.",
        technique_id=technique_id,
        confidence_low=0.55,
        confidence_high=0.85,
    )


class SysmonDetector:
    name = "builtin-sysmon-detector"

    def detect(
        self,
        artifacts: list[ArtifactEvent],
        binary_features: list[BinaryFeature],
        timeline: list[TimelineEvent],
    ) -> list[Finding]:
        del binary_features, timeline
        findings: list[Finding] = []
        for item in artifacts:
            src = item.source.lower()
            if "sysmon" not in src and "sysmon" not in item.event_type.lower():
                continue
            if "process" in item.event_type.lower() or str(item.metadata.get("event_id")) == "1":
                findings.append(
                    _finding(
                        title="Sysmon process execution signal",
                        severity="medium",
                        tactic="execution",
                        evidence=[item.description, f"source={item.source}"],
                        technique_id="T1059",
                    )
                )
            elif "network" in item.event_type.lower() or str(item.metadata.get("event_id")) == "3":
                findings.append(
                    _finding(
                        title="Sysmon network connection signal",
                        severity="medium",
                        tactic="command-and-control",
                        evidence=[item.description, f"source={item.source}"],
                        technique_id="T1071",
                    )
                )
            if len(findings) >= 100:
                break
        return findings


class DefenderDetector:
    name = "builtin-defender-detector"

    def detect(
        self,
        artifacts: list[ArtifactEvent],
        binary_features: list[BinaryFeature],
        timeline: list[TimelineEvent],
    ) -> list[Finding]:
        del binary_features, timeline
        findings: list[Finding] = []
        for item in artifacts:
            src = item.source.lower()
            text = f"{item.event_type} {item.description}".lower()
            if "defender" not in src and "windows_defender" not in text:
                continue
            if "threat" in text or "malware" in text or "detected" in text:
                findings.append(
                    _finding(
                        title="Windows Defender threat detection",
                        severity="high",
                        tactic="defense-evasion",
                        evidence=[item.description, f"source={item.source}"],
                        technique_id="T1562",
                    )
                )
            if len(findings) >= 100:
                break
        return findings


class ZeekDetector:
    name = "builtin-zeek-detector"

    def detect(
        self,
        artifacts: list[ArtifactEvent],
        binary_features: list[BinaryFeature],
        timeline: list[TimelineEvent],
    ) -> list[Finding]:
        del binary_features, timeline
        findings: list[Finding] = []
        for item in artifacts:
            src = item.source.lower()
            if "zeek" not in src:
                continue
            if item.event_type in {"dns_query", "http_request", "tls_client_hello", "c2_beacon_suspected"}:
                findings.append(
                    _finding(
                        title="Zeek network telemetry signal",
                        severity="medium",
                        tactic="command-and-control",
                        evidence=[item.description, f"event_type={item.event_type}"],
                        technique_id="T1071",
                    )
                )
            if len(findings) >= 100:
                break
        return findings


class SuricataDetector:
    name = "builtin-suricata-detector"

    def detect(
        self,
        artifacts: list[ArtifactEvent],
        binary_features: list[BinaryFeature],
        timeline: list[TimelineEvent],
    ) -> list[Finding]:
        del binary_features, timeline
        findings: list[Finding] = []
        for item in artifacts:
            src = item.source.lower()
            if "suricata" not in src and "alert" not in item.event_type.lower():
                continue
            sev_value = str(item.metadata.get("severity") or "").lower()
            severity = "high" if sev_value in {"1", "high", "critical"} else "medium"
            findings.append(
                _finding(
                    title="Suricata alert signal",
                    severity=severity,
                    tactic="command-and-control",
                    evidence=[item.description, f"source={item.source}"],
                    technique_id="T1071",
                )
            )
            if len(findings) >= 100:
                break
        return findings
