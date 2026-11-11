"""Generate ordinary Windows activity and count the alerts it raises.

Every event here is something a normal office machine or domain controller
does: people open Office and browsers, updaters run, security agents read
LSASS, vendors install services, admins run scripts. None of it is an
attack, so every medium-or-higher finding is a false alarm.

Events use the real Windows field names (Image, CommandLine, TargetObject,
GrantedAccess...) and carry ``event_id`` and ``provider`` so the same rules
that read EVTX read them.

    python lab/benign.py --out /tmp/benign --events 20000 --seed 3
    python lab/benign.py --out /tmp/benign --score     # run the autopilot and count alerts
"""

from __future__ import annotations

import argparse
import json
import random
import shutil
import tempfile
from collections import Counter
from pathlib import Path

SYSMON = "Microsoft-Windows-Sysmon"
SEC = "Microsoft-Windows-Security-Auditing"
USERS = ["alice", "bob", "carol", "dmitri", "erin"]
PF = r"C:\Program Files"
PF86 = r"C:\Program Files (x86)"
SYS = r"C:\Windows\System32"


def _u(rng: random.Random) -> str:
    return rng.choice(USERS)


def proc(rng: random.Random, image: str, cmd: str, parent: str, user: str | None = None) -> dict:
    return {"event_id": 1, "provider": SYSMON, "Image": image, "CommandLine": cmd, "ParentImage": parent,
            "User": f"CORP\\{user or _u(rng)}", "OriginalFileName": image.rsplit("\\", 1)[-1],
            "IntegrityLevel": "Medium"}


def office_and_browsers(rng: random.Random) -> dict:
    user = _u(rng)
    choice = rng.randrange(9)
    explorer = r"C:\Windows\explorer.exe"
    if choice == 0:
        return proc(rng, rf"{PF}\Google\Chrome\Application\chrome.exe",
                    rf'"{PF}\Google\Chrome\Application\chrome.exe" --type=renderer --lang=en-GB', explorer, user)
    if choice == 1:
        return proc(rng, rf"{PF}\Microsoft Office\root\Office16\WINWORD.EXE",
                    rf'"{PF}\Microsoft Office\root\Office16\WINWORD.EXE" /n "C:\Users\{user}\Documents\Q3 report.docx"',
                    explorer, user)
    if choice == 2:
        return proc(rng, rf"{PF}\Microsoft Office\root\Office16\EXCEL.EXE",
                    rf'"{PF}\Microsoft Office\root\Office16\EXCEL.EXE" "C:\Users\{user}\Desktop\budget.xlsx"',
                    explorer, user)
    if choice == 3:
        return proc(rng, rf"C:\Users\{user}\AppData\Local\Microsoft\Teams\current\Teams.exe",
                    rf'"C:\Users\{user}\AppData\Local\Microsoft\Teams\current\Teams.exe" --system-initiated',
                    explorer, user)
    if choice == 4:
        return proc(rng, rf"C:\Users\{user}\AppData\Local\Microsoft\OneDrive\OneDrive.exe",
                    rf'"C:\Users\{user}\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background', explorer, user)
    if choice == 5:
        return proc(rng, rf"{PF86}\Microsoft\Edge\Application\msedge.exe",
                    rf'"{PF86}\Microsoft\Edge\Application\msedge.exe" --profile-directory=Default', explorer, user)
    if choice == 6:
        return proc(rng, rf"{SYS}\notepad.exe", rf'"{SYS}\notepad.exe" C:\Users\{user}\Documents\todo.txt',
                    explorer, user)
    if choice == 7:
        return proc(rng, rf"{PF}\Microsoft Office\root\Office16\OUTLOOK.EXE",
                    rf'"{PF}\Microsoft Office\root\Office16\OUTLOOK.EXE"', explorer, user)
    return proc(rng, rf"{PF}\Adobe\Acrobat DC\Acrobat\Acrobat.exe",
                rf'"{PF}\Adobe\Acrobat DC\Acrobat\Acrobat.exe" "C:\Users\{user}\Downloads\invoice-2026-03.pdf"',
                explorer, user)


def system_and_updates(rng: random.Random) -> dict:
    choice = rng.randrange(10)
    svchost = rf"{SYS}\svchost.exe"
    services = rf"{SYS}\services.exe"
    if choice == 0:
        return proc(rng, svchost, rf"{SYS}\svchost.exe -k netsvcs -p -s Schedule", services, "SYSTEM")
    if choice == 1:
        return proc(rng, rf"{SYS}\taskhostw.exe", "taskhostw.exe Install $(Arg0)", svchost, "SYSTEM")
    if choice == 2:
        return proc(rng, rf"{PF}\Windows Defender\MpCmdRun.exe",
                    rf'"{PF}\Windows Defender\MpCmdRun.exe" -SignatureUpdate -ScheduleJob', svchost, "SYSTEM")
    if choice == 3:
        return proc(rng, rf"{PF86}\Google\Update\GoogleUpdate.exe",
                    rf'"{PF86}\Google\Update\GoogleUpdate.exe" /ua /installsource scheduler', svchost, "SYSTEM")
    if choice == 4:
        return proc(rng, rf"{SYS}\msiexec.exe", r"C:\Windows\system32\msiexec.exe /V", services, "SYSTEM")
    if choice == 5:
        return proc(rng, rf"{SYS}\wuauclt.exe", rf'"{SYS}\wuauclt.exe" /RunHandlerComServer', svchost, "SYSTEM")
    if choice == 6:
        return proc(rng, rf"{SYS}\conhost.exe", r"\??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1",
                    rf"{SYS}\cmd.exe")
    if choice == 7:
        return proc(rng, rf"{SYS}\SearchProtocolHost.exe",
                    rf'"{SYS}\SearchProtocolHost.exe" Global\UsGthrFltPipeMssGthrPipe1', rf"{SYS}\SearchIndexer.exe",
                    "SYSTEM")
    if choice == 8:
        return proc(rng, rf"{SYS}\WerFault.exe", rf"{SYS}\WerFault.exe -u -p 4120 -s 512", svchost)
    return proc(rng, rf"{SYS}\rundll32.exe", rf"{SYS}\rundll32.exe shell32.dll,Control_RunDLL desk.cpl",
                r"C:\Windows\explorer.exe")


def admin_work(rng: random.Random) -> dict:
    """Things IT staff do every day. Some resemble attacker commands."""
    choice = rng.randrange(8)
    cmd = rf"{SYS}\cmd.exe"
    ps = rf"{SYS}\WindowsPowerShell\v1.0\powershell.exe"
    if choice == 0:
        return proc(rng, rf"{SYS}\ipconfig.exe", "ipconfig /all", cmd, "it-admin")
    if choice == 1:
        return proc(rng, ps, rf'"{ps}" -NoProfile -ExecutionPolicy Bypass -File \\fs01\it$\scripts\inventory.ps1',
                    rf"{SYS}\svchost.exe", "it-admin")
    if choice == 2:
        return proc(rng, rf"{SYS}\gpupdate.exe", "gpupdate /force", cmd, "it-admin")
    if choice == 3:
        return proc(rng, rf"{SYS}\net.exe", "net use Z: \\\\fs01\\shared /persistent:yes", cmd, "it-admin")
    if choice == 4:
        return proc(rng, rf"{SYS}\sc.exe", "sc query wuauserv", cmd, "it-admin")
    if choice == 5:
        return proc(rng, rf"{SYS}\whoami.exe", "whoami", cmd, "it-admin")
    if choice == 6:
        return proc(rng, rf"{SYS}\schtasks.exe", "schtasks /query /fo LIST", cmd, "it-admin")
    return proc(rng, rf"{SYS}\tasklist.exe", "tasklist", cmd, "it-admin")


def other_sysmon(rng: random.Random) -> dict:
    user = _u(rng)
    choice = rng.randrange(11)
    if choice == 0:
        return {"event_id": 3, "provider": SYSMON, "Image": rf"{PF}\Google\Chrome\Application\chrome.exe",
                "DestinationIp": f"142.250.{rng.randrange(256)}.{rng.randrange(256)}", "DestinationPort": "443"}
    if choice == 1:
        return {"event_id": 3, "provider": SYSMON, "Image": rf"{SYS}\svchost.exe", "DestinationIp": "10.0.0.10",
                "DestinationPort": "53"}
    if choice == 2:
        return {"event_id": 3, "provider": SYSMON,
                "Image": rf"C:\Users\{user}\AppData\Local\Microsoft\OneDrive\OneDrive.exe",
                "DestinationIp": "13.107.42.12", "DestinationPort": "443"}
    if choice == 3:
        return {"event_id": 10, "provider": SYSMON, "SourceImage": rf"{SYS}\svchost.exe",
                "TargetImage": rf"{SYS}\lsass.exe", "GrantedAccess": "0x1000", "CallTrace": "ntdll.dll+9d4c4"}
    if choice == 4:
        # Endpoint security agents read LSASS as part of normal operation.
        return {"event_id": 10, "provider": SYSMON,
                "SourceImage": rng.choice([rf"{PF}\CrowdStrike\CSFalconService.exe",
                                           rf"{PF}\Windows Defender Advanced Threat Protection\MsSense.exe",
                                           rf"{PF}\SentinelOne\Sentinel Agent\SentinelAgent.exe"]),
                "TargetImage": rf"{SYS}\lsass.exe", "GrantedAccess": "0x1010", "CallTrace": "ntdll.dll+9d4c4"}
    if choice == 5:
        return {"event_id": 11, "provider": SYSMON, "Image": rf"{PF}\Google\Chrome\Application\chrome.exe",
                "TargetFilename": rf"C:\Users\{user}\Downloads\report-{rng.randrange(999)}.pdf"}
    if choice == 6:
        return {"event_id": 11, "provider": SYSMON, "Image": rf"{SYS}\WerFault.exe",
                "TargetFilename": r"C:\ProgramData\Microsoft\Windows\WER\Temp\WER4F2A.tmp.dmp"}
    if choice == 7:
        return {"event_id": 13, "provider": SYSMON, "Image": r"C:\Windows\explorer.exe", "EventType": "SetValue",
                "TargetObject": r"HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.docx",
                "Details": "Binary Data"}
    if choice == 8:
        # Installers register their own autostart entries.
        name, path = rng.choice([("OneDrive", rf'"C:\Users\{user}\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background'),
                                 ("com.squirrel.Teams.Teams", rf'"C:\Users\{user}\AppData\Local\Microsoft\Teams\Update.exe" --processStart "Teams.exe"'),
                                 ("SecurityHealth", r"%windir%\system32\SecurityHealthSystray.exe")])
        return {"event_id": 13, "provider": SYSMON, "Image": rng.choice([rf"{SYS}\msiexec.exe", r"C:\Windows\explorer.exe"]),
                "EventType": "SetValue",
                "TargetObject": rf"HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run\{name}",
                "Details": path}
    if choice == 9:
        return {"event_id": 7, "provider": SYSMON, "Image": rf"{PF}\Microsoft Office\root\Office16\WINWORD.EXE",
                "ImageLoaded": rf"{SYS}\ole32.dll", "Signed": "true"}
    return {"event_id": 7, "provider": SYSMON, "Image": rf"C:\Users\{user}\AppData\Local\Microsoft\Teams\current\Teams.exe",
            "ImageLoaded": rf"C:\Users\{user}\AppData\Local\Microsoft\Teams\current\ffmpeg.dll", "Signed": "true"}


def security_and_system(rng: random.Random) -> dict:
    user = _u(rng)
    choice = rng.randrange(13)
    if choice == 0:
        return {"event_id": 4624, "provider": SEC, "LogonType": rng.choice(["2", "3", "5", "7", "11"]),
                "TargetUserName": user, "IpAddress": rng.choice(["-", "10.0.0.21", "10.0.0.35"]),
                "LogonProcessName": "User32", "AuthenticationPackageName": "Negotiate"}
    if choice == 1:
        return {"event_id": 4624, "provider": SEC, "LogonType": "3", "TargetUserName": "WS-17$",
                "IpAddress": "10.0.0.17", "AuthenticationPackageName": "Kerberos"}
    if choice == 2:
        return {"event_id": 4625, "provider": SEC, "TargetUserName": user, "Status": "0xc000006d",
                "IpAddress": "10.0.0.21", "LogonType": "2"}
    if choice == 3:
        return {"event_id": 4672, "provider": SEC, "SubjectUserName": "it-admin", "PrivilegeList": "SeDebugPrivilege"}
    if choice == 4:
        return {"event_id": 4769, "provider": SEC, "ServiceName": "fs01$", "TicketEncryptionType": "0x12",
                "TargetUserName": f"{user}@CORP.LOCAL"}
    if choice == 5:
        return {"event_id": 4798, "provider": SEC, "TargetUserName": user, "SubjectUserName": user,
                "CallerProcessName": rf"{SYS}\mmc.exe"}
    if choice == 6:
        return {"event_id": 4799, "provider": SEC, "TargetUserName": "Administrators",
                "SubjectUserName": "WS-17$", "CallerProcessName": rf"{SYS}\svchost.exe"}
    if choice == 7:
        return {"event_id": 5136, "provider": SEC, "AttributeLDAPDisplayName": "description",
                "ObjectDN": f"CN={user},OU=Staff,DC=corp,DC=local", "ObjectClass": "user"}
    if choice == 8:
        return {"event_id": 4738, "provider": SEC, "TargetUserName": user, "AllowedToDelegateTo": "-",
                "ServicePrincipalNames": "-", "SubjectUserName": "it-admin"}
    if choice == 9:
        # A vendor installs its service; this happens on every patch day.
        return {"event_id": 7045, "provider": "Service Control Manager",
                "ServiceName": rng.choice(["Google Update Service", "Adobe Acrobat Update Service", "Zoom Sharing Service"]),
                "ImagePath": rng.choice([rf'"{PF86}\Google\Update\GoogleUpdate.exe" /svc',
                                         rf'"{PF86}\Common Files\Adobe\ARM\1.0\armsvc.exe"',
                                         rf'"{PF}\Zoom\bin\CptService.exe"']),
                "StartType": "auto start", "AccountName": "LocalSystem"}
    if choice == 10:
        return {"event_id": 7036, "provider": "Service Control Manager",
                "param1": rng.choice(["Windows Update", "Windows Event Log", "Print Spooler"]), "param2": "running"}
    if choice == 11:
        return {"event_id": 4104, "provider": "Microsoft-Windows-PowerShell",
                "ScriptBlockText": rng.choice(["Get-Service | Where-Object Status -eq 'Running'",
                                               "Get-ChildItem C:\\Logs -Filter *.log | Remove-Item -WhatIf",
                                               "Import-Module ActiveDirectory; Get-ADUser -Filter * -SearchBase 'OU=Staff,DC=corp,DC=local'"])}
    return {"event_id": 60, "provider": "Microsoft-Windows-Bits-Client",
            "url": rng.choice(["http://download.windowsupdate.com/c/msdownload/update/x.cab",
                               "https://g.live.com/odclientsettings/ProdV2"])}


def generate(out: Path, events: int, seed: int) -> None:
    rng = random.Random(seed)
    makers = [(office_and_browsers, 30), (system_and_updates, 20), (admin_work, 6), (other_sysmon, 24),
              (security_and_system, 20)]
    population = [maker for maker, weight in makers for _ in range(weight)]
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    batch: list[dict] = []
    part = 0
    for index in range(events):
        event = rng.choice(population)(rng)
        event.setdefault("timestamp", f"2026-03-{1 + index % 28:02d}T{8 + index % 10:02d}:{index % 60:02d}:00Z")
        event.setdefault("event_type", f"windows_event_{event['event_id']}")
        event.setdefault("description", "")
        event.setdefault("source", event["provider"])
        batch.append(event)
        if len(batch) == 2000:
            (out / f"events_{part:02d}.json").write_text(json.dumps(batch), encoding="utf-8")
            batch, part = [], part + 1
    if batch:
        (out / f"events_{part:02d}.json").write_text(json.dumps(batch), encoding="utf-8")


def score(evidence: Path) -> dict:
    from auto_forensics_autopilot.orchestrator import start

    with tempfile.TemporaryDirectory(prefix="af-benign-") as tmp:
        draft = start(input_dir=evidence, output_dir=Path(tmp) / "run", case_id="benign", llm="off")
    events = sum(len(json.loads(p.read_text())) for p in evidence.glob("*.json"))
    serious = [f for f in draft["findings"] if f["severity"] in {"medium", "high", "critical"}]
    return {
        "events": events,
        "serious_findings": len(serious),
        "per_10k_events": round(len(serious) * 10_000 / max(events, 1), 2),
        "by_title": Counter(f["title"] for f in serious).most_common(),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--events", type=int, default=20000)
    parser.add_argument("--seed", type=int, default=3)
    parser.add_argument("--score", action="store_true", help="Score an existing folder instead of generating.")
    args = parser.parse_args(argv)
    if not args.score:
        generate(args.out, args.events, args.seed)
    print(json.dumps(score(args.out), indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
