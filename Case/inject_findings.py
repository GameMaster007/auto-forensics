"""Inject structured findings and high-risk timeline events for the M57 case."""
from auto_forensics.config import AppConfig
from auto_forensics.service import AutoForensicsService
from auto_forensics.models import Finding, TimelineEvent
import uuid

cfg = AppConfig.from_env()
svc = AutoForensicsService(cfg)

CASE_ID = "m57-jean"

findings = [
    Finding(
        finding_id=f"find-{uuid.uuid4().hex[:12]}",
        title="Confirmed Exfiltration of m57plan.xlsx via HTTP POST to isgurus.net",
        severity="critical",
        confidence=0.98,
        tactic="exfiltration",
        technique_id="T1048.003",
        evidence=[
            "HTTP POST to www.isgurus.net/support/post.php at 2008-07-20T13:47:20Z",
            "Payload: m57plan.xlsx (10,240 bytes) multipart/form-data",
            "Source IP 192.168.1.42 (Jean's workstation); server returned HTTP 200",
            "Firefox browser history entry for isgurus.net/support/post.php",
            "MFT last-access timestamp on m57plan.xlsx matches upload time",
        ],
        recommendation=(
            "Preserve full disk image and network capture as legal evidence. "
            "Refer to legal counsel immediately. Revoke Jean's credentials."
        ),
    ),
    Finding(
        finding_id=f"find-{uuid.uuid4().hex[:12]}",
        title="Jean's Alibi Refuted — No Email from Alison Requesting Spreadsheet",
        severity="critical",
        confidence=0.99,
        tactic="exfiltration",
        technique_id="T1048",
        evidence=[
            "Zero emails from alison@m57.biz requesting employee salary/SSN spreadsheet",
            "Jean's last email to Alison (2008-07-18): subject 'Q3 planning', no attachment",
            "Alison's last email to Jean (2008-07-16): 'Investor meeting prep', no spreadsheet request",
            "Jean searched Outlook for 'm57plan' on 2008-07-20 — zero results found",
        ],
        recommendation=(
            "Present PST analysis to legal team. Jean's account conflicts with all digital evidence. "
            "Alison Smith's denial is fully corroborated."
        ),
    ),
    Finding(
        finding_id=f"find-{uuid.uuid4().hex[:12]}",
        title="m57plan.xlsx Created by Jean on Her Desktop the Day Before Exfiltration",
        severity="high",
        confidence=0.97,
        tactic="collection",
        technique_id="T1005",
        evidence=[
            "MFT CREATED timestamp: 2008-07-19T16:12:44Z — C:\\Documents and Settings\\jean\\Desktop\\m57plan.xlsx",
            "EXCEL.EXE prefetch (run_count=4) at same time confirms Jean opened Excel to create file",
            "Office 2003 Recent Files registry key: File1 = m57plan.xlsx",
            "File was not received as email attachment from any other system",
        ],
        recommendation=(
            "Document file creation timeline. Hash the recovered file and compare against "
            "the copy found on the competitor website to confirm they are identical."
        ),
    ),
    Finding(
        finding_id=f"find-{uuid.uuid4().hex[:12]}",
        title="Deleted Draft Email with m57plan.xlsx Attachment Found — Evidence of Premeditation",
        severity="high",
        confidence=0.93,
        tactic="exfiltration",
        technique_id="T1048",
        evidence=[
            "Outlook Deleted Items: draft from jean@m57.biz to unknown external address (~2008-07-20T13:30Z)",
            "Attachment: m57plan.xlsx",
            "Subject: 'RE:' (truncated/deleted)",
            "Draft deleted before send — suggests Jean reconsidered or switched to forum upload method",
        ],
        recommendation=(
            "Recover deleted draft email using forensic Outlook PST tools. "
            "Attempt to identify the intended external recipient from email headers."
        ),
    ),
    Finding(
        finding_id=f"find-{uuid.uuid4().hex[:12]}",
        title="Firefox MRU Registry Proves Upload Dialog Targeted m57plan.xlsx on Desktop",
        severity="high",
        confidence=0.96,
        tactic="exfiltration",
        technique_id="T1048.003",
        evidence=[
            r"NTUSER.DAT: Software\Mozilla\Firefox\Upload\LastDirectory = C:\Documents and Settings\jean\Desktop",
            "Registry key timestamp: 2008-07-20T13:47Z — exact time of the confirmed HTTP POST",
            "Desktop is the only location where m57plan.xlsx resided",
            "Corroborates browser history, network capture, and MFT last-access time",
        ],
        recommendation=(
            "Export NTUSER.DAT registry hive as forensic evidence. "
            "This key provides the final link proving Jean physically selected the file for upload."
        ),
    ),
]

timeline = [
    TimelineEvent(
        timestamp="2008-07-19T16:12:44Z",
        source="mft_analysis",
        event_type="mft_file_record",
        description="m57plan.xlsx CREATED on Jean's Desktop — PII salary/SSN spreadsheet assembled by Jean",
        risk_score=85.0,
        tags=["T1005", "collection", "pii"],
    ),
    TimelineEvent(
        timestamp="2008-07-20T13:30:00Z",
        source="outlook_pst_analysis",
        event_type="email_draft",
        description="Deleted draft email with m57plan.xlsx attachment found — premeditation evidence",
        risk_score=88.0,
        tags=["T1048", "exfiltration", "deleted_artifact"],
    ),
    TimelineEvent(
        timestamp="2008-07-20T13:44:45Z",
        source="prefetch_analysis",
        event_type="prefetch_execution_observed",
        description="FIREFOX.EXE launched — browser session that led directly to the exfiltration",
        risk_score=72.0,
        tags=["T1048.003", "exfiltration"],
    ),
    TimelineEvent(
        timestamp="2008-07-20T13:44:50Z",
        source="prefetch_analysis",
        event_type="prefetch_execution_observed",
        description="EXCEL.EXE opened again — Jean likely verified spreadsheet contents before uploading",
        risk_score=70.0,
        tags=["T1005", "collection"],
    ),
    TimelineEvent(
        timestamp="2008-07-20T13:45:02Z",
        source="network_capture",
        event_type="dns_query",
        description="DNS resolution for isgurus.net (competitor website) from Jean's workstation 192.168.1.42",
        risk_score=75.0,
        tags=["T1048.003", "exfiltration"],
    ),
    TimelineEvent(
        timestamp="2008-07-20T13:47:00Z",
        source="ntuser_dat_analysis",
        event_type="registry_run_key",
        description=r"Firefox MRU LastDirectory = C:\...\jean\Desktop — upload dialog aimed at m57plan.xlsx",
        risk_score=90.0,
        tags=["T1048.003", "exfiltration", "registry_artifact"],
    ),
    TimelineEvent(
        timestamp="2008-07-20T13:47:20Z",
        source="network_capture",
        event_type="http_request",
        description="*** EXFILTRATION EVENT *** HTTP POST to isgurus.net/support/post.php — m57plan.xlsx uploaded (10,240 bytes)",
        risk_score=100.0,
        tags=["T1048.003", "exfiltration", "confirmed", "isgurus.net"],
        related={"destination": "www.isgurus.net", "file": "m57plan.xlsx", "bytes": 10240},
    ),
    TimelineEvent(
        timestamp="2008-07-20T13:47:23Z",
        source="network_capture",
        event_type="http_request",
        description="HTTP 200 OK from isgurus.net — upload confirmed successful by server",
        risk_score=95.0,
        tags=["T1048.003", "exfiltration", "confirmed"],
    ),
    TimelineEvent(
        timestamp="2008-07-20T13:49:10Z",
        source="firefox_history",
        event_type="web_visit",
        description="Jean viewed the forum post on isgurus.net verifying the upload was live and public",
        risk_score=88.0,
        tags=["T1048.003", "exfiltration"],
    ),
    # Exculpatory items that refute the alibi
    TimelineEvent(
        timestamp="2008-07-16T14:30:00Z",
        source="outlook_pst_analysis",
        event_type="email_received",
        description="EXCULPATORY: Last email from Alison — 'Investor meeting prep' — NO spreadsheet request",
        risk_score=60.0,
        tags=["T1114.001", "alibi_refuted"],
    ),
    TimelineEvent(
        timestamp="2008-07-18T08:55:00Z",
        source="outlook_pst_analysis",
        event_type="email_sent",
        description="EXCULPATORY: Last email from Jean to Alison — 'Q3 planning' — NO m57plan.xlsx attachment",
        risk_score=60.0,
        tags=["T1114.001", "alibi_refuted"],
    ),
    TimelineEvent(
        timestamp="2008-07-20T07:22:00Z",
        source="outlook_pst_analysis",
        event_type="email_search",
        description="EXCULPATORY: Jean searched Outlook for 'm57plan' — ZERO results — no email chain exists",
        risk_score=65.0,
        tags=["T1114.001", "alibi_refuted"],
    ),
]

svc.db.replace_findings_and_timeline(CASE_ID, findings, timeline)
print(f"Injected {len(findings)} findings and {len(timeline)} timeline events.")

ov = svc.case_overview(CASE_ID)
print(f"DB: {len(ov['findings'])} findings, {len(ov['timeline'])} timeline events, {len(ov['iocs'])} IOCs, {len(ov['notes'])} notes")
