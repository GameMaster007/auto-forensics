from __future__ import annotations

import ipaddress
import re

from .citations import citation_from_event
from .ids import stable_id
from .models import ArtifactEvent, BinaryFeature, Citation, Finding, TimelineEvent


def _finding(
    title: str,
    severity: str,
    tactic: str,
    evidence: list[str],
    technique_id: str = "",
    citation: Citation | None = None,
) -> Finding:
    return Finding(
        finding_id=stable_id(
            "plg",
            title,
            evidence,
            citation.artifact_id if citation is not None else "",
            citation.sha256 if citation is not None else "",
        ),
        title=title,
        severity=severity,
        confidence=0.72,
        tactic=tactic,
        evidence=evidence[:8],
        recommendation="Open the cited artifact and confirm the signal before acting.",
        technique_id=technique_id,
        confidence_low=0.55,
        confidence_high=0.85,
        citations=[citation] if citation is not None and citation.is_complete() else [],
        origin="detector",
        review_status="unverified",
    )


_USER_WRITABLE = re.compile(
    r"\\(temp|tmp|appdata|downloads|users\\public|perflogs|\$recycle\.bin|windows\\tasks|programdata)\\",
    re.IGNORECASE,
)
_LOLBIN = re.compile(
    r"\b(mshta|regsvr32|rundll32|certutil|bitsadmin|wmic|installutil|msbuild|cmstp)(\.exe)?\b.*"
    r"(https?:|javascript:|scrobj|/i:|-urlcache|/transfer|process call create)",
    re.IGNORECASE,
)
_ENCODED_PS = re.compile(r"powershell(\.exe)?\b.*\s-(e|en|enc|encodedcommand)\s", re.IGNORECASE)


def _suspicious_process(item: ArtifactEvent) -> str:
    """Name why a process start is worth an analyst's time, or return ''."""
    fields = " ".join(str(item.metadata.get(key) or "") for key in (
        "path", "image", "Image", "process", "command_line", "CommandLine", "cmdline", "parent_image",
    ))
    text = f"{fields} {item.description}"
    if _ENCODED_PS.search(text):
        return "encoded PowerShell"
    if _LOLBIN.search(text):
        return "system binary used to fetch or run code"
    if _USER_WRITABLE.search(fields):
        return "ran from a user-writable folder"
    return ""


_INFRA_PORTS = {53: "DNS", 123: "NTP", 67: "DHCP", 68: "DHCP", 137: "NetBIOS name", 5353: "mDNS"}


def _routine_connection(item: ArtifactEvent) -> str:
    """Return a label for infrastructure or internal traffic, or ''."""
    raw_port = item.metadata.get("dst_port", item.metadata.get("DestinationPort"))
    try:
        port = int(str(raw_port).strip())
    except (TypeError, ValueError):
        port = -1
    if port in _INFRA_PORTS:
        return f"routine {_INFRA_PORTS[port]}"
    raw_ip = str(item.metadata.get("dst_ip") or item.metadata.get("DestinationIp") or "").strip()
    try:
        address = ipaddress.ip_address(raw_ip)
    except ValueError:
        return ""
    if address.is_loopback or address.is_link_local or address.is_multicast:
        return "local traffic"
    return ""


def _is_sysmon(item: ArtifactEvent) -> bool:
    """Sysmon by source name, event type, or the EVTX provider and channel."""
    meta = item.metadata
    text = " ".join(str(meta.get(key) or "") for key in ("provider", "channel", "source"))
    return "sysmon" in f"{item.source} {item.event_type} {text}".lower()


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
            if not _is_sysmon(item):
                continue
            if "process" in item.event_type.lower() or str(item.metadata.get("event_id")) == "1":
                reason = _suspicious_process(item)
                findings.append(
                    _finding(
                        title=f"Sysmon process execution: {reason}" if reason else "Sysmon process execution (routine)",
                        severity="medium" if reason else "low",
                        tactic="execution",
                        evidence=[item.description, f"source={item.source}"],
                        technique_id="T1059",
                        citation=citation_from_event(item),
                    )
                )
            elif "network" in item.event_type.lower() or str(item.metadata.get("event_id")) == "3":
                routine = _routine_connection(item)
                findings.append(
                    _finding(
                        title=f"Sysmon network connection ({routine})" if routine else "Sysmon network connection signal",
                        severity="low" if routine else "medium",
                        tactic="command-and-control",
                        evidence=[item.description, f"source={item.source}"],
                        technique_id="T1071",
                        citation=citation_from_event(item),
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
                        citation=citation_from_event(item),
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
                        citation=citation_from_event(item),
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
                    citation=citation_from_event(item),
                )
            )
            if len(findings) >= 100:
                break
        return findings


_AUTORUN_KEY = re.compile(
    r"\\(run|runonce|runonceex|runservices|runservicesonce)(\\|$)"
    r"|\\winlogon\\(shell|userinit|notify)"
    r"|\\image file execution options\\[^\\]+\\debugger"
    r"|\\explorer\\shell folders\\startup"
    r"|\\currentcontrolset\\services\\[^\\]+\\imagepath",
    re.IGNORECASE,
)
_STARTUP_FOLDER = re.compile(r"\\start menu\\programs\\startup\\", re.IGNORECASE)


class PersistenceDetector:
    """Autostart locations written by registry, file, task, or service events.

    Events that carry a Windows event ID are left to the event-ID map, so
    a 4698 is not reported twice.
    """

    name = "builtin-persistence-detector"

    def detect(
        self,
        artifacts: list[ArtifactEvent],
        binary_features: list[BinaryFeature],
        timeline: list[TimelineEvent],
    ) -> list[Finding]:
        del binary_features, timeline
        findings: list[Finding] = []
        for item in artifacts:
            if item.metadata.get("event_id") not in (None, ""):
                continue
            kind = item.event_type.lower()
            path = str(item.metadata.get("path") or item.metadata.get("target") or "")
            title = technique = ""
            if "registry" in kind and _AUTORUN_KEY.search(path):
                title, technique = "Autostart registry key written", "T1547.001"
            elif ("file" in kind or "create" in kind) and _STARTUP_FOLDER.search(path):
                title, technique = "File written to a Startup folder", "T1547.001"
            elif "scheduled_task" in kind or "schtask" in kind:
                title, technique = "Scheduled task created", "T1053.005"
            elif "service" in kind and ("install" in kind or "create" in kind):
                title, technique = "Service installed", "T1543.003"
            if not title:
                continue
            findings.append(
                _finding(
                    title=title,
                    severity="high",
                    tactic="persistence",
                    evidence=[item.description, f"source={item.source}"] if item.description else [f"source={item.source}"],
                    technique_id=technique,
                    citation=citation_from_event(item),
                )
            )
            if len(findings) >= 100:
                break
        return findings
