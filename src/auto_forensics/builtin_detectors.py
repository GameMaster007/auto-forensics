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


# Maps Sysmon Event IDs to (title, severity, tactic, technique_id).
_SYSMON_EVENT_MAP: dict[int, tuple[str, str, str, str]] = {
    1:  ("Sysmon process creation",            "medium", "execution",            "T1059"),
    3:  ("Sysmon network connection",          "medium", "command-and-control",  "T1071"),
    7:  ("Sysmon image (DLL) loaded",          "medium", "defense-evasion",      "T1055"),
    8:  ("Sysmon CreateRemoteThread detected", "high",   "defense-evasion",      "T1055.001"),
    10: ("Sysmon process memory access",       "high",   "credential-access",    "T1003"),
    11: ("Sysmon file created",                "low",    "collection",           "T1005"),
    12: ("Sysmon registry key create/delete",  "medium", "persistence",          "T1112"),
    13: ("Sysmon registry value set",          "medium", "persistence",          "T1112"),
    15: ("Sysmon file stream created (ADS)",   "high",   "defense-evasion",      "T1564.004"),
    17: ("Sysmon named pipe created",          "medium", "command-and-control",  "T1071"),
    18: ("Sysmon named pipe connected",        "medium", "lateral-movement",     "T1021"),
    22: ("Sysmon DNS query",                   "medium", "command-and-control",  "T1071.004"),
    23: ("Sysmon file deleted",                "medium", "defense-evasion",      "T1485"),
    25: ("Sysmon process tampering detected",  "high",   "defense-evasion",      "T1055"),
}


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
            eid_raw = item.metadata.get("event_id")
            try:
                eid = int(eid_raw) if eid_raw is not None else None
            except (TypeError, ValueError):
                eid = None

            mapped = _SYSMON_EVENT_MAP.get(eid) if eid is not None else None
            if mapped:
                title, severity, tactic, technique_id = mapped
                findings.append(
                    _finding(
                        title=title,
                        severity=severity,
                        tactic=tactic,
                        evidence=[item.description, f"source={item.source}", f"event_id={eid}"],
                        technique_id=technique_id,
                    )
                )
            elif "process" in item.event_type.lower():
                findings.append(
                    _finding(
                        title="Sysmon process execution signal",
                        severity="medium",
                        tactic="execution",
                        evidence=[item.description, f"source={item.source}"],
                        technique_id="T1059",
                    )
                )
            elif "network" in item.event_type.lower():
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
                        tactic="execution",
                        evidence=[item.description, f"source={item.source}"],
                        technique_id="T1204",
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


class RDPDetector:
    """Detect RDP-based lateral movement from Windows TerminalServices event logs."""

    name = "builtin-rdp-detector"

    # TerminalServices-RemoteConnectionManager / LocalSessionManager event IDs
    _RDP_CONNECT_IDS = frozenset({"21", "22", "25", "41", "1149"})
    _RDP_FAILED_IDS = frozenset({"131"})

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
            is_rdp_source = any(k in src for k in ("terminalservices", "rdp", "remote_desktop", "remoteconnection"))
            eid = str(item.metadata.get("event_id") or "")
            if not is_rdp_source and eid not in self._RDP_CONNECT_IDS | self._RDP_FAILED_IDS:
                continue
            if eid in self._RDP_FAILED_IDS:
                findings.append(
                    _finding(
                        title="RDP connection attempt failed",
                        severity="medium",
                        tactic="lateral-movement",
                        evidence=[item.description, f"source={item.source}", f"event_id={eid}"],
                        technique_id="T1021.001",
                    )
                )
            else:
                findings.append(
                    _finding(
                        title="RDP session established",
                        severity="medium",
                        tactic="lateral-movement",
                        evidence=[item.description, f"source={item.source}", f"event_id={eid}"],
                        technique_id="T1021.001",
                    )
                )
            if len(findings) >= 100:
                break
        return findings
