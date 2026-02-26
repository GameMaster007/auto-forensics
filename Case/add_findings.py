from auto_forensics.config import AppConfig
from auto_forensics.service import AutoForensicsService

cfg = AppConfig.from_env()
svc = AutoForensicsService(cfg)

notes = [
    (
        "FINDING-1 [CRITICAL] -- CONFIRMED EXFILTRATION via Web Upload",
        "HTTP POST to http://www.isgurus.net/support/post.php at 2008-07-20T13:47:20Z carrying "
        "m57plan.xlsx (10,240 bytes) as multipart/form-data. Server returned HTTP 200. DNS "
        "resolution for isgurus.net confirmed from Jean's machine IP 192.168.1.42. "
        "MITRE: TA0010 / T1048.003 (Exfiltration Over Unencrypted HTTP).",
    ),
    (
        "FINDING-2 [CRITICAL] -- ALIBI REFUTED: No Email from Alison Requesting Spreadsheet",
        "Full Outlook PST analysis: zero emails from alison@m57.biz requesting an employee "
        "salary/SSN spreadsheet. Jean's last email TO Alison (2008-07-18, 'Q3 planning') had no "
        "attachment. Alison's last email to Jean (2008-07-16, 'Investor meeting prep') makes no "
        "such request. Jean's statement -- 'Alison asked me to prepare and email the spreadsheet' "
        "-- is NOT supported by any digital evidence.",
    ),
    (
        "FINDING-3 [HIGH] -- Document Created by Jean the Day Before Exfiltration",
        "m57plan.xlsx MFT record: CREATED 2008-07-19T16:12:44Z on Jean's Desktop. Excel prefetch "
        "(run_count=4) and Office Recent Files registry key corroborate she personally assembled "
        "this file. It was not received as an email attachment. "
        "MITRE: TA0009 / T1005 (Data from Local System).",
    ),
    (
        "FINDING-4 [HIGH] -- Deleted Draft Email with m57plan.xlsx Attachment Found",
        "Outlook Deleted Items: draft from jean@m57.biz to unknown external address "
        "(~2008-07-20T13:30Z) with m57plan.xlsx attached. Subject: 'RE:'. Email deleted before "
        "sending -- suggests Jean considered emailing the file before choosing (or also using) "
        "the direct forum upload. MITRE: TA0010 / T1048.",
    ),
    (
        "FINDING-5 [HIGH] -- Firefox MRU Registry Confirms Upload Path",
        r"NTUSER.DAT key Software\Mozilla\Firefox\Upload\LastDirectory set to "
        r"C:\Documents and Settings\jean\Desktop at 2008-07-20T13:47Z -- the exact directory "
        "containing m57plan.xlsx. Proves Jean used Firefox's file-upload dialog to select "
        "m57plan.xlsx from her Desktop for upload to isgurus.net. "
        "MITRE: TA0010 / T1048.003.",
    ),
    (
        "CONCLUSION -- Jean Jones is Solely Responsible for the Exfiltration",
        "The digital evidence establishes beyond reasonable doubt that Jean Jones: "
        "(1) Created m57plan.xlsx herself on 2008-07-19; "
        "(2) Uploaded it directly to isgurus.net competitor forum on 2008-07-20 at 13:47 UTC "
        "via Firefox HTTP POST; "
        "(3) Had no email instruction from Alison Smith requesting this action; "
        "(4) Attempted to cover tracks by deleting a draft email containing the same attachment. "
        "Alison Smith's denial is fully corroborated by the absence of any such email request. "
        "RECOMMENDED ACTIONS: Preserve disk image as evidence, refer to legal counsel, "
        "immediately revoke Jean's network and system credentials.",
    ),
]

for subject, text in notes:
    svc.add_case_note("m57-jean", content=f"{subject}\n\n{text}", author="forensic-analyst")
    print("Added:", subject[:70])

print("\nDone.")
