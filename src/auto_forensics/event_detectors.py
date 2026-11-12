from __future__ import annotations

import logging

from .citations import citation_from_event
from .ids import stable_id
from .models import ArtifactEvent, Finding

logger = logging.getLogger(__name__)

# Maps Windows Event IDs to (severity, tactic, technique_id, description, recommendation).
_EVENT_MAP: dict[int, tuple[str, str, str, str, str]] = {
    # Service / task persistence
    7045: ("high",     "persistence",          "T1543.003", "New service installed",              "Investigate service binary, path, and creating process."),
    4698: ("high",     "persistence",          "T1053.005", "Scheduled task created",             "Review task action, trigger, and creator account."),
    4702: ("medium",   "persistence",          "T1053.005", "Scheduled task updated",             "Compare old and new task definitions for payload changes."),
    # Process execution
    # Process creation and PowerShell logging are telemetry: present on every
    # audited host. They are kept as low context findings; the content rules in
    # windows_rules.py raise the suspicious ones (encoded commands, Mimikatz...).
    4688: ("low",      "execution",            "T1059",     "New process created",                "Validate process lineage and command line for suspicious patterns."),
    # Credential access
    4625: ("medium",   "credential-access",    "T1110",     "Account logon failure",              "Check for brute-force patterns; correlate with 4771/4776."),
    4648: ("high",     "lateral-movement",     "T1550.002", "Logon using explicit credentials",   "Investigate credential use outside of expected service accounts."),
    4776: ("medium",   "credential-access",    "T1110.003", "NTLM authentication attempt",        "Review for pass-the-hash indicators or unusual source hosts."),
    4771: ("medium",   "credential-access",    "T1110.003", "Kerberos pre-auth failure",          "Check for password spray or account enumeration."),
    # Logon / logoff
    4624: ("low",      "initial-access",       "",          "Successful account logon",           "Validate logon type and source address against baseline."),
    4634: ("low",      "initial-access",       "",          "Account logoff",                     "Correlate with logon events for session duration anomalies."),
    4647: ("low",      "initial-access",       "",          "User-initiated logoff",              "Correlate with logon events."),
    # Account management
    4720: ("high",     "persistence",          "T1136.001", "User account created",               "Verify account creation was authorized; inspect creator."),
    4722: ("medium",   "persistence",          "T1078",     "User account enabled",               "Verify re-enabling was authorized."),
    4723: ("low",      "credential-access",    "T1110",     "Password change attempt",            "Correlate with account for unexpected self-resets."),
    4724: ("medium",   "credential-access",    "T1098",     "Password reset by admin",            "Verify administrator action was authorized."),
    4728: ("high",     "privilege-escalation", "T1098",     "Member added to security group",     "Check group membership change; privilege escalation risk."),
    4732: ("high",     "privilege-escalation", "T1098",     "Member added to local group",        "Check local admin group membership change."),
    4756: ("high",     "privilege-escalation", "T1098",     "Member added to universal group",    "Review membership and group scope changes."),
    # Audit policy / log clearing
    1102: ("critical", "defense-evasion",      "T1070.001", "Security audit log cleared",         "Investigate who cleared logs and correlate with other events."),
    4719: ("high",     "defense-evasion",      "T1562.002", "System audit policy changed",        "Review policy change; disabling audit logging is a red flag."),
    # PowerShell / script block
    4103: ("low",      "execution",            "T1059.001", "PowerShell pipeline execution",      "Review PowerShell command and module details."),
    4104: ("low",      "execution",            "T1059.001", "PowerShell script block logged",     "Inspect script block for obfuscation or download cradles."),
    # WMI
    5857: ("medium",   "execution",            "T1047",     "WMI activity detected",              "Review WMI namespace, query, and calling process."),
    5858: ("medium",   "execution",            "T1047",     "WMI error",                          "WMI errors may indicate failed lateral movement or persistence."),
    5859: ("high",     "persistence",          "T1546.003", "WMI filter registered",              "Investigate WMI event subscription for persistence."),
    5861: ("high",     "persistence",          "T1546.003", "WMI subscription bound",             "Permanent WMI subscription; strong persistence indicator."),
    # Network / firewall
    5156: ("low",      "command-and-control",  "",          "Windows Filtering Platform allowed", "Review process and remote IP against known-good baselines."),
    5158: ("low",      "command-and-control",  "",          "Firewall permitted connection",      "Correlate with process and destination."),
    # Object access / file system
    4663: ("low",      "collection",           "T1005",     "Object access attempt",              "Review accessed object and process for data collection patterns."),
    4670: ("medium",   "defense-evasion",      "T1222",     "Object permissions changed",         "Investigate permission change on sensitive files or keys."),
}


def _coerce_event_id(raw: object) -> int | None:
    """Accept int or string event IDs; return None if unparseable."""
    if isinstance(raw, int):
        return raw
    if isinstance(raw, str):
        try:
            return int(raw.strip())
        except ValueError:
            return None
    return None


def _plain_title(event_id: int | str, event_type: str) -> str:
    """'audit_log_cleared' -> 'Audit log cleared (Windows event 1102)'."""
    words = " ".join(str(event_type or "").replace("_", " ").split())[:80]
    return f"{words[:1].upper()}{words[1:]} (Windows event {event_id})" if words else f"Windows event {event_id}"


def findings_from_artifact_events(artifacts: list[ArtifactEvent], limit: int = 500) -> list[Finding]:
    """One finding per event ID per source file, citing the first event.

    A busy log holds thousands of events with the same ID; one finding per
    event would bury the analyst. The count is added to the recommendation.
    """
    findings: list[Finding] = []
    first: dict[tuple[int, str], Finding] = {}
    counts: dict[tuple[int, str], int] = {}
    for item in artifacts:
        raw_id = item.metadata.get("event_id")
        event_id = _coerce_event_id(raw_id)
        if event_id is None:
            continue
        mapping = _EVENT_MAP.get(event_id)
        if mapping is None:
            continue
        severity, tactic, technique_id, default_desc, recommendation = mapping
        # Use the artifact's own description if available, else fall back to the map description.
        description = item.description if item.description else default_desc
        technique_id = str(item.metadata.get("attack_technique_id") or technique_id)
        tactic_final = str(item.metadata.get("attack_tactic") or tactic)
        pointer = citation_from_event(item)
        key = (event_id, str(item.metadata.get("source_file") or item.source))
        counts[key] = counts.get(key, 0) + 1
        if key in first:
            continue
        finding = Finding(
            finding_id=stable_id("evt", event_id, item.artifact_id, description),
            title=_plain_title(event_id, item.event_type),
            severity=severity,
            confidence=0.7,
            tactic=tactic_final,
            evidence=[description, f"source={item.source}", f"artifact_id={item.artifact_id}"],
            recommendation=recommendation,
            technique_id=technique_id,
            sub_technique=str(item.metadata.get("attack_sub_technique") or ""),
            confidence_low=0.55,
            confidence_high=0.85,
            citations=[pointer] if pointer is not None else [],
            origin="detector",
            review_status="unverified",
        )
        first[key] = finding
        findings.append(finding)
        if len(findings) >= limit:
            logger.debug("findings_from_artifact_events: limit %d reached, stopping early", limit)
            break
    for key, finding in first.items():
        if counts[key] > 1:
            finding.recommendation += f" {counts[key] - 1} more event(s) with this ID in the same file."
    return findings
