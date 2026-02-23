from __future__ import annotations

import logging
import uuid

from .models import ArtifactEvent, Finding

logger = logging.getLogger(__name__)

# Maps Windows Event IDs to (severity, tactic, technique_id, description, recommendation).
_EVENT_MAP: dict[int, tuple[str, str, str, str, str]] = {
    # Service / task persistence
    7045: ("high",     "persistence",          "T1543.003", "New service installed",              "Investigate service binary, path, and creating process."),
    4697: ("high",     "defense-evasion",      "T1543.003", "Service deleted",                    "Attacker may be removing a service after use; correlate with 7045."),
    4698: ("high",     "persistence",          "T1053.005", "Scheduled task created",             "Review task action, trigger, and creator account."),
    4699: ("high",     "defense-evasion",      "T1053.005", "Scheduled task deleted",             "Task deletion may indicate cleanup after payload execution."),
    4702: ("medium",   "persistence",          "T1053.005", "Scheduled task updated",             "Compare old and new task definitions for payload changes."),
    # Process execution
    4688: ("medium",   "execution",            "T1059",     "New process created",                "Validate process lineage and command line for suspicious patterns."),
    # Credential access
    4625: ("medium",   "credential-access",    "T1110",     "Account logon failure",              "Check for brute-force patterns; correlate with 4771/4776."),
    4648: ("high",     "lateral-movement",     "T1550.002", "Logon using explicit credentials",   "Investigate credential use outside of expected service accounts."),
    4649: ("high",     "credential-access",    "T1558",     "Replay attack detected",             "Kerberos replay detected; investigate source and targeted accounts."),
    4768: ("medium",   "credential-access",    "T1558.001", "Kerberos TGT requested",             "Correlate with anomalous source IPs or accounts for AS-REP roasting."),
    4769: ("medium",   "credential-access",    "T1558.003", "Kerberos service ticket requested",  "High volume or unusual service names may indicate Kerberoasting."),
    4776: ("medium",   "credential-access",    "T1110.003", "NTLM authentication attempt",        "Review for pass-the-hash indicators or unusual source hosts."),
    4771: ("medium",   "credential-access",    "T1110.003", "Kerberos pre-auth failure",          "Check for password spray or account enumeration."),
    # Logon / logoff
    4624: ("low",      "initial-access",       "",          "Successful account logon",           "Validate logon type and source address against baseline."),
    4634: ("low",      "initial-access",       "",          "Account logoff",                     "Correlate with logon events for session duration anomalies."),
    4647: ("low",      "initial-access",       "",          "User-initiated logoff",              "Correlate with logon events."),
    4672: ("medium",   "privilege-escalation", "T1078.002", "Special privileges assigned to logon","Investigate whether the privileged logon was expected and authorized."),
    4673: ("medium",   "privilege-escalation", "T1078.002", "Privileged service called",          "Review which privilege was invoked and by which process."),
    # Account management
    4720: ("high",     "persistence",          "T1136.001", "User account created",               "Verify account creation was authorized; inspect creator."),
    4722: ("medium",   "persistence",          "T1078",     "User account enabled",               "Verify re-enabling was authorized."),
    4723: ("low",      "credential-access",    "T1110",     "Password change attempt",            "Correlate with account for unexpected self-resets."),
    4724: ("medium",   "credential-access",    "T1098",     "Password reset by admin",            "Verify administrator action was authorized."),
    4725: ("high",     "impact",               "T1531",     "User account disabled",              "Verify whether account was disabled as part of an attack."),
    4726: ("high",     "impact",               "T1531",     "User account deleted",               "Account deletion may indicate attacker cleanup; correlate with 4720."),
    4728: ("high",     "privilege-escalation", "T1098",     "Member added to security group",     "Check group membership change; privilege escalation risk."),
    4729: ("high",     "defense-evasion",      "T1098",     "Member removed from security group", "Removal may indicate attacker cleanup or privilege revocation."),
    4732: ("high",     "privilege-escalation", "T1098",     "Member added to local group",        "Check local admin group membership change."),
    4733: ("high",     "defense-evasion",      "T1098",     "Member removed from local group",    "Correlate with 4732; may indicate cleanup after privilege escalation."),
    4738: ("high",     "persistence",          "T1098",     "User account changed",               "Review changed attributes (flags, SID history, logon hours) for tampering."),
    4756: ("high",     "privilege-escalation", "T1098",     "Member added to universal group",    "Review membership and group scope changes."),
    4765: ("critical", "privilege-escalation", "T1134",     "SID history added to account",       "SID history can be abused for domain persistence; investigate immediately."),
    4766: ("high",     "privilege-escalation", "T1134",     "SID history add attempt failed",     "Failed SID history manipulation; correlate with successful 4765 events."),
    # Audit policy / log clearing
    1100: ("high",     "defense-evasion",      "T1070.001", "Event log service shutdown",         "Unexpected log service stop may indicate attacker covering tracks."),
    1102: ("critical", "defense-evasion",      "T1070.001", "Security audit log cleared",         "Investigate who cleared logs and correlate with other events."),
    4719: ("high",     "defense-evasion",      "T1562.002", "System audit policy changed",        "Review policy change; disabling audit logging is a red flag."),
    4907: ("medium",   "defense-evasion",      "T1562",     "Audit policy on object changed",     "Object-level audit change may hide accesses to sensitive resources."),
    4946: ("high",     "defense-evasion",      "T1562.004", "Windows Firewall rule added",        "New firewall exception may expose services or allow C2 traffic."),
    4947: ("high",     "defense-evasion",      "T1562.004", "Windows Firewall rule modified",     "Rule modification may weaken network segmentation controls."),
    4950: ("medium",   "defense-evasion",      "T1562.004", "Windows Firewall setting changed",   "Review changed setting for weakened inbound/outbound policy."),
    # PowerShell / script block
    4103: ("medium",   "execution",            "T1059.001", "PowerShell pipeline execution",      "Review PowerShell command and module details."),
    4104: ("high",     "execution",            "T1059.001", "PowerShell script block logged",     "Inspect script block for obfuscation or download cradles."),
    # WMI
    5857: ("medium",   "execution",            "T1047",     "WMI activity detected",              "Review WMI namespace, query, and calling process."),
    5858: ("medium",   "execution",            "T1047",     "WMI error",                          "WMI errors may indicate failed lateral movement or persistence."),
    5859: ("high",     "persistence",          "T1546.003", "WMI filter registered",              "Investigate WMI event subscription for persistence."),
    5861: ("high",     "persistence",          "T1546.003", "WMI subscription bound",             "Permanent WMI subscription; strong persistence indicator."),
    # Network / firewall / share access
    5140: ("high",     "lateral-movement",     "T1021.002", "Network share accessed",             "Review share name and accessing account; common lateral movement vector."),
    5145: ("medium",   "lateral-movement",     "T1021.002", "Network share object access check",  "Correlate with 5140; repeated checks may indicate discovery/staging."),
    5156: ("low",      "command-and-control",  "",          "Windows Filtering Platform allowed", "Review process and remote IP against known-good baselines."),
    5158: ("low",      "command-and-control",  "",          "Firewall permitted connection",      "Correlate with process and destination."),
    # Object access / file system
    4656: ("low",      "collection",           "T1083",     "Object handle requested",            "Repeated handle requests on sensitive paths may indicate staging/exfil."),
    4657: ("medium",   "persistence",          "T1112",     "Registry value modified",            "Inspect key path and new data for persistence or configuration tampering."),
    4660: ("medium",   "defense-evasion",      "T1485",     "Object deleted",                     "Deletion of logs, evidence files, or tools may indicate attacker cleanup."),
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


def findings_from_artifact_events(artifacts: list[ArtifactEvent], limit: int = 500) -> list[Finding]:
    findings: list[Finding] = []
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
        finding = Finding(
            finding_id=f"evt-{uuid.uuid4().hex[:12]}",
            title=f"Event {event_id}: {item.event_type}",
            severity=severity,
            confidence=0.7,
            tactic=tactic_final,
            evidence=[description, f"source={item.source}", f"artifact_id={item.artifact_id}"],
            recommendation=recommendation,
            technique_id=technique_id,
            sub_technique=str(item.metadata.get("attack_sub_technique") or ""),
            confidence_low=0.55,
            confidence_high=0.85,
        )
        findings.append(finding)
        if len(findings) >= limit:
            logger.debug("findings_from_artifact_events: limit %d reached, stopping early", limit)
            break
    return findings
