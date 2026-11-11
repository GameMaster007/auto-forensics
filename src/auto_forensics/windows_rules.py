"""Behaviour rules for Windows event logs (Sysmon, Security, System, PowerShell).

Each rule names the event IDs it applies to, an optional provider, and
regular expressions that must match named event fields. Field names
follow the Windows XML schema (``Image``, ``CommandLine``,
``TargetObject``...). Process rules apply to both Sysmon event 1 and
Security event 4688 by reading either field name.

Rules describe behaviour, not sample files: they look for what an
attacker has to do (dump LSASS, write an autorun key, spawn a shell from
Office), so they also fire on data the rules were not written against.

A finding cites the event's file and record number. Its evidence holds
only metadata, so the verifier treats it as a detector finding and
re-reads the cited record; no evidence text becomes a claim.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

from .citations import citation_from_event
from .ids import stable_id
from .models import ArtifactEvent, BinaryFeature, Finding, TimelineEvent

SYSMON = "sysmon"
I = re.IGNORECASE


def rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, I)


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: str
    tactic: str
    technique: str
    event_ids: frozenset[int]
    # field name -> pattern; every entry must match. A field name may list
    # alternatives separated by "|" (first present field is used).
    match: dict[str, re.Pattern[str]] = field(default_factory=dict)
    # field name -> pattern; none may match.
    exclude: dict[str, re.Pattern[str]] = field(default_factory=dict)
    provider: str = ""  # substring of provider or channel, lowercase
    # Extra test across fields that a regex on one field cannot express.
    check: Callable[[dict[str, Any]], bool] | None = None

    def applies(self, event_id: int, provider: str) -> bool:
        return event_id in self.event_ids and (not self.provider or self.provider in provider)


def _ids(*values: int) -> frozenset[int]:
    return frozenset(values)


PROC = _ids(1, 4688)
IMAGE = "Image|NewProcessName"
CMD = "CommandLine|ProcessCommandLine"
PARENT = "ParentImage|ParentProcessName"

# Access masks are written with or without leading zeros (0x1fffff, 0x001fffff).
LSASS_ACCESS = r"^0x0*(1010|1410|1438|143a|147a|1fffff|1f0fff|1f1fff|1f2fff|1f3fff|40|1400|410|10)$"
VM_READ = 0x10
USER_DIR = r"\\(temp|tmp|downloads|users\\public|perflogs|desktop|appdata\\(local|roaming)|programdata)\\"
AUTO_ELEVATE = (r"\\(eventvwr|fodhelper|computerdefaults|sdclt|slui|wsreset|cmstp|changepk|sysprep|wusa|"
                r"pkgmgr|dism|mmc|taskmgr|osk|perfmon|cliconfg|winsat|bthudtask|dccw|iscsicpl|"
                r"systemsettingsadminflows|tpmvscmgr|recdisc)\.exe$")


def _mask(value: object) -> int:
    try:
        return int(str(value).strip(), 16)
    except ValueError:
        return 0

RULES: tuple[Rule, ...] = (
    # ---------------- execution ----------------
    Rule("ps-encoded", "PowerShell with an encoded or hidden command", "high", "execution", "T1059.001", PROC,
         {CMD: rx(r"(powershell|pwsh).*(\s-(e|en|enc|enco|encodedcommand)\s+[a-z0-9+/=]{8,}|"
                  r"-w(indowstyle)?\s+hid(den)?\b|-nop\b.*-ep?\s+bypass)")}),
    Rule("ps-download", "PowerShell download cradle", "high", "execution", "T1059.001", PROC,
         {CMD: rx(r"(downloadstring|downloadfile|downloaddata|invoke-webrequest|iwr\s|net\.webclient|"
                  r"start-bitstransfer|invoke-restmethod)")}),
    Rule("script-from-office", "Office or script host started a shell", "high", "execution", "T1204.002", PROC,
         {PARENT: rx(r"\\(winword|excel|powerpnt|outlook|msaccess|mspub|onenote|wscript|cscript|mshta|hh)\.exe$"),
          IMAGE: rx(r"\\(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|"
                    r"schtasks|wmic|msbuild)\.exe$")}),
    Rule("lolbin-proxy", "System binary used to fetch or proxy-execute code", "high", "defense-evasion", "T1218", PROC,
         {CMD: rx(r"(mshta(\.exe)?\s+(https?|javascript|vbscript):|regsvr32.*(/i:|scrobj)|"
                  r"rundll32(\.exe)?\s+[^,]*,\s*(#\d+|[a-z]*entry|runhtmlapplication)|rundll32.*javascript:|"
                  r"certutil.*(-urlcache|-decode|-verifyctl)|bitsadmin.*/(transfer|addfile)|"
                  r"msiexec.*(/q|/i)\s*https?:|installutil.*(/u|/logfile=)|odbcconf.*/a|cmstp.*/s|"
                  r"pcalua.*-a|forfiles.*/c|msbuild(\.exe)?\s+\S+\.(xml|csproj|proj)|"
                  r"control(\.exe)?\s+\S+\.cpl|mavinject|syncappvpublishingserver|"
                  r"wmic.*(process\s+call\s+create|/format:)|"
                  r"(zipfldr|advpack|pcwutl|url|ieframe|shdocvw|shell32|setupapi|syssetup|ieadvpack)(\.dll)?\s*,\s*"
                  r"(routethecall|registerocx|launchapplication|fileprotocolhandler|openurl|shellexec_rundll|"
                  r"launchinfsection|installhinfsection|setupinfobjectinstallaction)|"
                  r"desktopimgdownldr.*/lockscreenurl:|ftp(\.exe)?\s+.*-s:|explorer(\.exe)?\s+/root,|"
                  r"(wscript|cscript)(\.exe)?\S*\s+/e:(vbs|jscript|vbscript)\s+\S+\.(?!vbs|js)\w+)")}),
    Rule("odd-parent-shell", "Shell started by a browser, server or update process", "high", "execution", "T1059",
         PROC, {PARENT: rx(r"\\(iexplore|chrome|firefox|msedge|opera|acrord32|acrobat|ftp|wuauclt|spoolsv|lsass|"
                           r"searchindexer|w3wp|sqlservr|httpd|nginx|tomcat\d*|java|javaw|php-cgi|"
                           r"umworkerprocess|winlogon)\.exe$"),
                IMAGE: rx(r"\\(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|"
                          r"whoami|net1?)\.exe$")}),
    Rule("svchost-shell", "Shell started directly by a service host", "medium", "execution", "T1059", PROC,
         {PARENT: rx(r"\\svchost\.exe$"), IMAGE: rx(r"\\(cmd|powershell|pwsh)\.exe$")}),
    Rule("wmi-spawn", "WMI provider host started a shell (remote WMI execution)", "high", "execution", "T1047", PROC,
         {PARENT: rx(r"\\wmiprvse\.exe$"), IMAGE: rx(r"\\(cmd|powershell|pwsh|rundll32|mshta|regsvr32)\.exe$")}),
    Rule("user-writable-exec", "Program ran from a user-writable folder", "medium", "execution", "T1204", PROC,
         {IMAGE: rx(r"\\(temp|tmp|downloads|users\\public|perflogs|\$recycle\.bin|programdata|appdata\\roaming)\\"
                    r"[^\\]+\.(exe|scr|com|pif)$")}),
    Rule("scripted-shell", "Script interpreter ran a script from a user-writable folder", "medium", "execution",
         "T1059.005", PROC,
         {IMAGE: rx(r"\\(wscript|cscript|mshta)\.exe$"),
          CMD: rx(r"\\(temp|downloads|users\\public|appdata)\\[^\"]+\.(vbs|vbe|js|jse|hta|wsf)")}),
    Rule("psh-scriptblock", "Suspicious PowerShell script block", "high", "execution", "T1059.001", _ids(4104),
         {"ScriptBlockText": rx(r"(invoke-mimikatz|invoke-shellcode|invoke-reflectivepeinjection|amsiutils|"
                                r"amsiinitfailed|\[reflection\.assembly\]::load|frombase64string.*(iex|invoke-expression)|"
                                r"(iex|invoke-expression).*(downloadstring|webclient)|invoke-kerberoast|"
                                r"get-gpppassword|powerview|sharphound|invoke-bloodhound|virtualalloc|"
                                r"-bxor\s|system\.reflection\.emit)")}),
    Rule("mssql-xp-cmdshell", "SQL Server xp_cmdshell enabled or used", "high", "execution", "T1505.001",
         _ids(15457, 15281, 33205), {"Data|param1|EventData": rx(r"xp_cmdshell")}, provider="mssql"),
    # ---------------- persistence ----------------
    Rule("schtasks-create", "Scheduled task created from the command line", "high", "persistence", "T1053.005", PROC,
         {CMD: rx(r"schtasks(\.exe)?.*\s/create\b|\bat(\.exe)?\s+\\\\|\bat(\.exe)?\s+\d{1,2}:\d{2}")}),
    Rule("service-create-cmd", "Service created or changed from the command line", "high", "persistence",
         "T1543.003", PROC, {CMD: rx(r"\bsc(\.exe)?\s+(\\\\\S+\s+)?(create|config)\b.*binpath")}),
    Rule("reg-run-cmd", "Autorun registry key added from the command line", "high", "persistence", "T1547.001", PROC,
         {CMD: rx(r"reg(\.exe)?\s+add\s+.*\\(run|runonce|winlogon|image file execution options)\b")}),
    Rule("registry-autorun", "Autostart registry value set", "high", "persistence", "T1547.001", _ids(12, 13, 14),
         {"TargetObject": rx(r"\\currentversion\\(run|runonce|runonceex|policies\\explorer\\run)\\|"
                             r"\\winlogon\\(shell|userinit|notify|taskman)|\\appinit_dlls|"
                             r"\\explorer\\(user )?shell folders\\(common )?startup|"
                             r"\\control\\session manager\\bootexecute|"
                             r"\\currentcontrolset\\control\\lsa\\(security packages|notification packages|"
                             r"authentication packages)|\\netsh\\")}, provider=SYSMON),
    Rule("registry-ifeo", "Debugger or exit monitor set for a program (IFEO hijack)", "high", "persistence",
         "T1546.012", _ids(12, 13, 14),
         {"TargetObject": rx(r"\\image file execution options\\[^\\]+\\(debugger|globalflag)|"
                             r"\\silentprocessexit\\[^\\]+\\monitorprocess")}, provider=SYSMON),
    Rule("registry-com-hijack", "COM object registered in the user hive (COM hijack)", "medium", "persistence",
         "T1546.015", _ids(12, 13, 14),
         {"TargetObject": rx(r"\\(hkcu|hku\\[^\\]+)\\software\\classes\\clsid\\[^\\]+\\(inprocserver32|localserver32)|"
                             r"_classes\\clsid\\[^\\]+\\(inprocserver32|localserver32)")}, provider=SYSMON),
    Rule("registry-service", "Service image path written in the registry", "high", "persistence", "T1543.003",
         _ids(12, 13, 14), {"TargetObject": rx(r"\\currentcontrolset\\services\\[^\\]+\\(imagepath|"
                                                r"parameters\\servicedll)$")},
         {"Image": rx(r"\\(services|msiexec|trustedinstaller|tiworker|svchost)\.exe$")}, provider=SYSMON),
    Rule("startup-file", "File written to a Startup folder", "high", "persistence", "T1547.001", _ids(11),
         {"TargetFilename": rx(r"\\start menu\\programs\\startup\\")}, provider=SYSMON),
    Rule("wmi-subscription", "WMI event subscription created", "high", "persistence", "T1546.003", _ids(19, 20, 21),
         {}, provider=SYSMON),
    Rule("service-install-suspicious", "Service installed that runs a shell or a file from a share/temp folder",
         "high", "lateral-movement", "T1569.002", _ids(7045, 4697),
         {"ImagePath|ServiceFileName": rx(r"(cmd(\.exe)?\s*/c|%comspec%|powershell|\\\\127\.0\.0\.1\\|admin\$|"
                                          r"\\temp\\|\\windows\\[a-z0-9]{8}\.exe|psexesvc|remcom|paexec|"
                                          r"\.bat\b|echo\s)")}),
    Rule("bits-job", "BITS job transferred a file", "medium", "persistence", "T1197", _ids(59, 60),
         {"url|RemoteName": rx(r"https?://")}, provider="bits"),
    # ---------------- privilege escalation ----------------
    Rule("uac-bypass-registry", "UAC bypass handler registered", "high", "privilege-escalation", "T1548.002",
         _ids(12, 13, 14),
         {"TargetObject": rx(r"\\(ms-settings|mscfile|exefile|folder|launcher\.systemsettings)\\shell\\open\\command|"
                             r"\\environment\\windir|\\currentversion\\app paths\\control\.exe")}, provider=SYSMON),
    Rule("uac-bypass-parent", "Auto-elevating Windows binary started a shell (UAC bypass)", "high",
         "privilege-escalation", "T1548.002", PROC,
         {PARENT: rx(r"\\(fodhelper|computerdefaults|eventvwr|sdclt|slui|wsreset|cmstp|changepk)\.exe$"),
          IMAGE: rx(r"\\(cmd|powershell|pwsh|mshta|rundll32|regsvr32|wscript|cscript)\.exe$|\\temp\\")}),
    Rule("uac-com-shell", "COM surrogate or MMC started a shell (elevation abuse)", "high", "privilege-escalation",
         "T1548.002", PROC, {PARENT: rx(r"\\(dllhost|mmc)\.exe$"),
                             IMAGE: rx(r"\\(cmd|powershell|pwsh|rundll32|regsvr32|mshta|wscript|cscript)\.exe$")}),
    Rule("autoelevate-from-user-folder", "Auto-elevating Windows binary launched by a program in a user folder",
         "medium", "privilege-escalation", "T1548.002", PROC,
         {IMAGE: rx(AUTO_ELEVATE), PARENT: rx(USER_DIR)}),
    Rule("autoelevate-dll-hijack", "Auto-elevating Windows binary loaded a DLL from a user-writable folder", "high",
         "privilege-escalation", "T1548.002", _ids(7),
         {"Image": rx(AUTO_ELEVATE), "ImageLoaded": rx(USER_DIR)}, provider=SYSMON),
    Rule("dll-sideload", "Windows binary loaded a DLL from a user-writable folder (side-loading)", "high",
         "defense-evasion", "T1574.002", _ids(7),
         {"Image": rx(r"\\windows\\(system32|syswow64)\\"), "ImageLoaded": rx(USER_DIR)},
         {"Image": rx(AUTO_ELEVATE + r"|\\(msiexec|dllhost|rundll32|regsvr32|consent)\.exe$")}, provider=SYSMON),
    Rule("pipe-impersonation", "Named pipe disguised inside another path (potato-style privilege escalation)",
         "high", "privilege-escalation", "T1134.001", _ids(17, 18),
         {"PipeName": rx(r"^\\[^\\]+\\pipe\\")}, provider=SYSMON),
    Rule("getsystem-pipe", "Service command writes to a named pipe (getsystem)", "high", "privilege-escalation",
         "T1134.001", PROC, {CMD: rx(r"echo\s+\S+\s*>\s*\\\\\.\\pipe\\")}),
    Rule("token-manipulation", "Process created with alternate credentials or a stolen token", "medium",
         "privilege-escalation", "T1134", PROC, {CMD: rx(r"\brunas(\.exe)?\s+/(user|netonly)|psexec.*\s-s\s")}),
    Rule("remote-thread", "Thread injected into another process", "high", "defense-evasion", "T1055", _ids(8),
         {}, {"SourceImage": rx(r"\\(csrss|wininit|services|svchost|msmpeng|vmtoolsd)\.exe$")}, provider=SYSMON),
    Rule("process-access-inject", "Process opened another with injection rights", "medium", "defense-evasion",
         "T1055", _ids(10),
         {"GrantedAccess": rx(r"^0x0*(1f0fff|1fffff|1f3fff|143a|1438)$"),
          "CallTrace": rx(r"unknown")}, {"TargetImage": rx(r"\\lsass\.exe$")}, provider=SYSMON),
    # ---------------- defense evasion ----------------
    Rule("log-cleared-cmd", "Event logs cleared from the command line", "high", "defense-evasion", "T1070.001", PROC,
         {CMD: rx(r"wevtutil(\.exe)?\s+(cl|clear-log)\b|clear-eventlog|remove-eventlog")}),
    Rule("log-cleared-system", "System event log cleared", "high", "defense-evasion", "T1070.001", _ids(104),
         {}, provider="eventlog"),
    Rule("shadow-delete", "Shadow copies or backups deleted", "high", "impact", "T1490", PROC,
         {CMD: rx(r"vssadmin.*delete\s+shadows|wmic.*shadowcopy\s+delete|wbadmin.*delete\s+(catalog|backup)|"
                  r"bcdedit.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)|"
                  r"fsutil.*usn\s+deletejournal")}),
    Rule("av-tamper", "Security tooling disabled or excluded", "high", "defense-evasion", "T1562.001", PROC,
         {CMD: rx(r"set-mppreference.*-(disable\w+|exclusion\w+)|add-mppreference.*-exclusion|"
                  r"sc(\.exe)?\s+(stop|delete|config)\s+(windefend|sense|wdboot|wdfilter)|"
                  r"netsh.*(advfirewall\s+set\s+\w+\s+state\s+off|firewall\s+set\s+opmode\s+disable)|"
                  r"taskkill.*(msmpeng|mssense|cylance|carbonblack|csfalcon)")}),
    Rule("av-tamper-registry", "Security tooling disabled in the registry", "high", "defense-evasion", "T1562.001",
         _ids(12, 13, 14), {"TargetObject": rx(r"\\windows defender\\.*(disableantispyware|disablerealtimemonitoring|"
                                               r"\\exclusions\\)|\\amsi\\providers|wdigest\\uselogoncredential")},
         provider=SYSMON),
    Rule("uac-disabled", "User Account Control switched off", "high", "defense-evasion", "T1548.002", _ids(12, 13, 14),
         {"TargetObject": rx(r"\\policies\\system\\(enablelua|consentpromptbehavioradmin|promptonsecuredesktop)$"),
          "Details": rx(r"0x0+\)?$")}, provider=SYSMON),
    Rule("ps-logging-disabled", "PowerShell logging or language mode weakened", "high", "defense-evasion",
         "T1562.002", _ids(12, 13, 14),
         {"TargetObject": rx(r"\\powershell\\(scriptblocklogging\\enablescriptblocklogging|"
                              r"modulelogging\\enablemodulelogging|transcription\\enabletranscripting)$|"
                              r"__pslockdownpolicy$")},
         provider=SYSMON, check=lambda m: "pslockdownpolicy" in str(m.get("TargetObject", "")).lower()
         or str(m.get("Details", "")).lower().rstrip(")").endswith("0x00000000")),
    Rule("ps-execution-policy", "PowerShell execution policy set to allow any script", "medium", "defense-evasion",
         "T1059.001", _ids(12, 13, 14), {"TargetObject": rx(r"\\shellids\\microsoft\.powershell\\executionpolicy$"),
                                "Details": rx(r"^(unrestricted|bypass)$")}, provider=SYSMON),
    Rule("office-macro-guard-off", "Office macro or VBA project protection switched off", "medium", "defense-evasion",
         "T1562.001", _ids(12, 13, 14),
         {"TargetObject": rx(r"\\office\\[\d.]+\\\w+\\security\\(accessvbom|vbawarnings)$"),
          "Details": rx(r"0x0+1\)?$")}, provider=SYSMON),
    Rule("event-channel-disabled", "Event log channel disabled", "medium", "defense-evasion", "T1562.002", _ids(12, 13, 14),
         {"TargetObject": rx(r"\\winevt\\channels\\[^\\]+\\enabled$"), "Details": rx(r"0x0+\)?$")},
         provider=SYSMON),
    Rule("mru-cleared", "Recent-activity history deleted from the registry", "medium", "defense-evasion",
         "T1070", _ids(12, 13, 14), {"TargetObject": rx(r"\\explorer\\(runmru|typedpaths|recentdocs|comdlg32)"),
                           "EventType": rx(r"^delete")}, provider=SYSMON),
    Rule("port-proxy", "Port forwarding rule added (netsh portproxy)", "high", "command-and-control", "T1090",
         _ids(12, 13, 14), {"TargetObject": rx(r"\\services\\portproxy\\v[46]tov[46]\\")}, provider=SYSMON),
    Rule("port-proxy-cmd", "Port forwarding rule added from the command line", "high", "command-and-control", "T1090",
         PROC, {CMD: rx(r"netsh(\.exe)?\s+(interface\s+portproxy|i\s+p)\s+(add|a)\b")}),
    Rule("new-share", "Network share created", "medium", "lateral-movement", "T1135", _ids(12, 13, 14),
         {"TargetObject": rx(r"\\lanmanserver\\shares\\[^\\]+$")},
         {"TargetObject": rx(r"\\shares\\security$")}, provider=SYSMON),
    Rule("null-session-pipe", "Anonymous access opened to a named pipe or share", "high", "lateral-movement",
         "T1021.002", _ids(12, 13, 14),
         {"TargetObject": rx(r"\\lanmanserver\\parameters\\(nullsessionpipes|nullsessionshares|"
                              r"restrictnullsessaccess)$")}, provider=SYSMON),
    Rule("rid-hijack", "Local account record changed by a process other than LSASS (RID hijack)", "high",
         "persistence", "T1098", _ids(12, 13, 14), {"TargetObject": rx(r"\\sam\\sam\\domains\\account\\users\\")},
         {"Image": rx(r"\\lsass\.exe$")}, provider=SYSMON),
    Rule("hidden-account", "Hidden local account created (name ends with $)", "high", "persistence", "T1564.002",
         _ids(12, 13, 14), {"TargetObject": rx(r"\\sam\\domains\\account\\users\\names\\[^\\]+\$(\\|$)|"
                                      r"\\winlogon\\specialaccounts\\userlist\\")}, provider=SYSMON),
    Rule("local-account-created", "Local account created", "medium", "persistence", "T1136.001", _ids(12, 13, 14),
         {"TargetObject": rx(r"\\sam\\domains\\account\\users\\names\\[^\\$]+(\\\(default\))?$"),
          "EventType": rx(r"^createkey$")}, provider=SYSMON),
    Rule("builtin-admin-changed", "Built-in Administrator account changed", "medium", "persistence", "T1098", _ids(12, 13, 14),
         {"TargetObject": rx(r"\\sam\\domains\\account\\users\\000001f4\\(f|v|forcepasswordreset)$")},
         provider=SYSMON),
    Rule("masquerade-renamed", "Renamed system tool (file name does not match the original name)", "high",
         "defense-evasion", "T1036.003", _ids(1),
         {"OriginalFileName": rx(r"^(cmd|powershell|psexec|psexesvc|procdump|rundll32|regsvr32|mshta|"
                                 r"certutil|wmic|net1?|whoami|nltest)\.exe(\.mui)?$")},
         provider=SYSMON, check=lambda m: _renamed(m)),
    Rule("hidden-file", "File hidden or protected with attrib", "medium", "defense-evasion", "T1564.001", PROC,
         {CMD: rx(r"attrib(\.exe)?\s+.*\+(h|s)\b")}),
    Rule("unsigned-driver", "Driver loaded that is not validly signed", "high", "defense-evasion", "T1014", _ids(6),
         {"Signed|SignatureStatus": rx(r"^(false|unavailable|expired|revoked)")}, provider=SYSMON),
    # ---------------- credential access ----------------
    # Any mask with VM_READ (0x10) or DUP_HANDLE (0x40) can expose LSASS memory.
    Rule("lsass-access", "LSASS memory opened by another process", "critical", "credential-access", "T1003.001",
         _ids(10), {"TargetImage": rx(r"\\lsass\.exe$")},
         {"SourceImage": rx(r"\\(wmiprvse|svchost|msmpeng|mssense|csrss|wininit|lsm|taskmgr|vmtoolsd|"
                            r"mrt|searchindexer|wmiadap)\.exe$")}, provider=SYSMON,
         check=lambda m: bool(_mask(m.get("GrantedAccess")) & (VM_READ | 0x40))),
    Rule("lsass-handle", "LSASS opened with read access (Security audit)", "critical", "credential-access",
         "T1003.001", _ids(4656, 4663), {"ObjectName": rx(r"\\lsass\.exe$")},
         {"ProcessName": rx(r"\\(wininit|csrss|svchost|lsm|msmpeng|mssense|services|wmiprvse|taskmgr)\.exe$")},
         check=lambda m: bool(_mask(m.get("AccessMask")) & VM_READ)),
    Rule("lsass-writes-file", "LSASS wrote a log or dump file (malicious security package)", "critical",
         "credential-access", "T1547.005", _ids(11),
         {"Image": rx(r"\\lsass\.exe$"), "TargetFilename": rx(r"\.(log|txt|dmp|tmp)$")}, provider=SYSMON),
    Rule("process-memory-read", "Program in a user-writable folder read another process's memory", "medium",
         "credential-access", "T1003", _ids(10),
         {"SourceImage": rx(r"\\(temp|tmp|downloads|users\\public|desktop|appdata)\\")},
         {"TargetImage": rx(r"\\(conhost|werfault)\.exe$")}, provider=SYSMON,
         check=lambda m: bool(_mask(m.get("GrantedAccess")) & VM_READ)),
    Rule("lsass-dump-cmd", "LSASS dump or credential theft tool on the command line", "critical",
         "credential-access", "T1003.001", PROC,
         {CMD: rx(r"(procdump.*(lsass|-ma\s+\d+)|comsvcs(\.dll)?.*minidump|sekurlsa::|lsadump::|"
                  r"kerberos::(golden|ptt|list)|mimikatz|pypykatz|nanodump|out-minidump|"
                  r"rdrleakdiag.*fullmemdmp|sqldumper.*0x0110|createdump.*-f)")}),
    Rule("hive-dump", "SAM, SYSTEM or SECURITY hive saved", "critical", "credential-access", "T1003.002", PROC,
         {CMD: rx(r"reg(\.exe)?\s+(save|export)\s+hklm\\(sam|system|security)\b|"
                  r"\\(windows\\system32\\config\\sam|ntds\\ntds\.dit)")}),
    Rule("ntds-dump", "Active Directory database copied (ntdsutil / shadow copy)", "critical", "credential-access",
         "T1003.003", PROC,
         {CMD: rx(r"ntdsutil.*(ifm|ac\s+i(n(stance)?)?\s+ntds|create\s+full)|vssadmin.*create\s+shadow|"
                  r"wmic.*shadowcopy\s+call\s+create|esentutl.*(ntds|/vss)|"
                  r"copy\s+\\\\\?\\globalroot\\device\\harddiskvolumeshadowcopy")}),
    Rule("ntds-esent", "AD database snapshot or copy logged by ESENT (ntdsutil)", "high", "credential-access",
         "T1003.003", _ids(216, 325, 326, 327), {}, provider="esent"),
    Rule("credential-dump-file", "Credential dump file written", "critical", "credential-access", "T1003", _ids(11),
         {"TargetFilename": rx(r"lsass[^\\]*\.(dmp|zip|bin)$|\\ntds\.dit$|\\(sam|system|security)(\.(hiv|save|bak))?$|"
                               r"debug\d*\.bin$")}, provider=SYSMON),
    Rule("dcsync", "Directory replication requested by a non-DC account (DCSync)", "critical", "credential-access",
         "T1003.006", _ids(4662),
         {"Properties": rx(r"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|"
                           r"89e95b76-444d-4c62-991a-0facbeda640c")},
         {"SubjectUserName": rx(r"\$$")}),
    Rule("kerberoast", "Kerberos service ticket requested with weak RC4 encryption", "high", "credential-access",
         "T1558.003", _ids(4769), {"TicketEncryptionType": rx(r"^0x17$")},
         {"ServiceName": rx(r"(\$|krbtgt)$")}),
    Rule("asrep-roast", "Kerberos TGT issued without pre-authentication", "high", "credential-access", "T1558.004",
         _ids(4768), {"PreAuthType": rx(r"^0$"), "TicketEncryptionType": rx(r"^0x17$")}),
    Rule("vault-access", "Credential vault or browser store accessed by a script or tool", "high",
         "credential-access", "T1555", PROC,
         {CMD: rx(r"(vaultcmd|cmdkey\s+/list|get-vaultcredential|\\login data|\\cookies\b|lazagne|"
                  r"credentialfileview|webbrowserpassview)")}),
    Rule("efs-coerce", "Remote authentication coercion over RPC (PetitPotam-style)", "high", "credential-access",
         "T1187", _ids(5145), {"RelativeTargetName": rx(r"^(efsrpc|lsass|spoolss)$"),
                               "IpAddress|SourceAddress": rx(r"\d")}),
    Rule("ntlm-auth-anon-coerce", "Machine account authenticated from an unexpected host (relay/coercion)", "medium",
         "credential-access", "T1557.001", _ids(4624),
         {"TargetUserName": rx(r"\$$"), "AuthenticationPackageName": rx(r"^ntlm$"), "LogonType": rx(r"^3$")},
         {"IpAddress": rx(r"^(-|127\.0\.0\.1|::1|)$")}),
    # ---------------- discovery ----------------
    Rule("domain-discovery", "Domain, account or trust discovery command", "medium", "discovery", "T1087.002", PROC,
         {CMD: rx(r"\bnet1?(\.exe)?\s+(user|group|localgroup|accounts)\b.*(/domain|admins)|nltest.*/(dclist|"
                  r"domain_trusts|dsgetdc)|dsquery|adfind|get-addomain|get-aduser|get-netuser|"
                  r"get-domain(user|group|computer|controller)|sharphound|bloodhound|"
                  r"\bsetspn(\.exe)?\s+-[ql]|klist\s+tgt|whoami\s+/(all|groups|priv)")}),
    Rule("recon-burst", "Host reconnaissance command", "medium", "discovery", "T1082", PROC,
         {CMD: rx(r"\b(systeminfo|quser|qwinsta|tasklist\s+/(v|svc)|ipconfig\s+/all|arp\s+-a|route\s+print|"
                  r"netstat\s+-(an|ano)|net\s+(share|session|view|use)|wmic\s+.*(qfe|product|service|"
                  r"useraccount|group)\s|get-wmiobject|reg\s+query\s+hk)")},
         {PARENT: rx(r"\\(explorer)\.exe$")}),
    Rule("sam-enum", "Remote SAM enumeration", "medium", "discovery", "T1087.001", _ids(4661, 5145),
         {"ObjectName|RelativeTargetName": rx(r"(sam_domain|sam_alias|sam_group|^samr$)")},
         {"SubjectUserName": rx(r"\$$")}),
    # ---------------- lateral movement ----------------
    Rule("admin-share-write", "File written over an admin share", "high", "lateral-movement", "T1021.002",
         _ids(5145, 5140), {"ShareName": rx(r"\\(admin|c|ipc)\$$"),
                            "RelativeTargetName": rx(r"\.(exe|dll|bat|ps1|vbs|sys)$|psexesvc|remcom|paexec|"
                                                     r"svcctl|atsvc")}),
    Rule("psexec-pipe", "PsExec-style named pipe", "high", "lateral-movement", "T1021.002", _ids(17, 18),
         {"PipeName": rx(r"\\(psexesvc|remcom|paexec|csexec)|-stdin|-stdout|-stderr")}, provider=SYSMON),
    Rule("c2-pipe", "Named pipe used by known attack frameworks", "high", "command-and-control", "T1071",
         _ids(17, 18), {"PipeName": rx(r"\\(msagent_|postex_|status_|mojo\.5688\.8052|interprocess_|"
                                       r"win_svc|ntsvcs|scerpc|lsarpc_|isapi_|samr_|msse-\d|"
                                       r"wkssvc_|spoolss_|demoagent)")}, provider=SYSMON),
    Rule("pth-logon", "Logon with new credentials (pass-the-hash pattern)", "high", "lateral-movement", "T1550.002",
         _ids(4624), {"LogonType": rx(r"^9$"), "LogonProcessName": rx(r"^seclogo")}),
    Rule("explicit-cred-remote", "Explicit credentials used to reach another host", "medium", "lateral-movement",
         "T1078", _ids(4648), {"TargetServerName": rx(r"^(?!localhost$)[a-z0-9.\-]+$")},
         {"SubjectUserName": rx(r"\$$")}),
    Rule("remote-exec-tools", "Remote execution tool on the command line", "high", "lateral-movement", "T1021",
         PROC, {CMD: rx(r"(psexec|paexec|winrs(\.exe)?\s+-r|invoke-command\s+-computername|enter-pssession|"
                        r"wmic\s+/node:|mstsc.*/restrictedadmin|sharprdp|invoke-wmimethod.*-computer)")}),
    Rule("rdp-tunnel", "RDP tunnelled through a local port forward", "high", "command-and-control", "T1572",
         _ids(4624, 1149), {"IpAddress|Param3": rx(r"^(127\.0\.0\.1|::1)$")},
         check=lambda m: str(m.get("event_id")) == "1149" or str(m.get("LogonType")) == "10"),
    Rule("winrm-shell", "Remote WinRM shell opened on this host", "medium", "lateral-movement", "T1021.006",
         _ids(91), {}, provider="winrm"),
    Rule("dcom-remote-launch", "Remote DCOM activation attempted", "medium", "lateral-movement", "T1021.003",
         _ids(10016), {"param2": rx(r"^remote$"), "param3": rx(r"launch|activation")}, provider="distributedcom"),
    Rule("winrm-spawn", "WinRM host started a shell (remote PowerShell)", "high", "lateral-movement", "T1021.006",
         PROC, {PARENT: rx(r"\\(wsmprovhost|winrshost)\.exe$")}),
    # ---------------- command and control ----------------
    Rule("lolbin-network", "Script host or system tool connected out", "high", "command-and-control", "T1105",
         _ids(3), {"Image": rx(r"\\(powershell|pwsh|mshta|rundll32|regsvr32|certutil|bitsadmin|wscript|cscript|"
                               r"msbuild|installutil|cmstp|notepad|calc)\.exe$")},
         {"DestinationIp": rx(r"^(127\.|10\.|192\.168\.|::1|169\.254\.)"),
          "DestinationPort": rx(r"^(53|137|138|445|135|389|88)$")}, provider=SYSMON),
    Rule("user-writable-network", "Program in a user-writable folder connected out", "high", "command-and-control",
         "T1071", _ids(3), {"Image": rx(r"\\(temp|tmp|downloads|users\\public|perflogs|appdata)\\")},
         {"DestinationPort": rx(r"^(53|137|138)$")}, provider=SYSMON),
    Rule("tool-transfer-cmd", "Tool transfer with a system utility", "medium", "command-and-control", "T1105", PROC,
         {CMD: rx(r"(curl|wget)(\.exe)?\s+.*https?://|copy\s+\\\\[^\\]+\\[a-z]\$|"
                  r"expand\s+\\\\|esentutl.*/y\s+\\\\")}),
    # ---------------- collection / exfiltration ----------------
    Rule("archive-staging", "Data archived with a password or in bulk for staging", "medium", "collection",
         "T1560.001", PROC, {CMD: rx(r"(7z|7za|rar|winrar)(\.exe)?\s+a\s+.*(-p|-hp)|compress-archive.*-destination")}),
    Rule("clipboard-screen", "Screen or clipboard capture by script", "medium", "collection", "T1113", PROC,
         {CMD: rx(r"(get-clipboard|copyfromscreen|screenshot|nircmd.*savescreenshot)")}),
    Rule("exfil-tools", "Data sent out with a cloud or file transfer tool", "high", "exfiltration", "T1567", PROC,
         {CMD: rx(r"(rclone(\.exe)?\s+(copy|sync)|megacmd|mega-put|dropbox_uploader|"
                  r"ftp(\.exe)?\s+-s:|pscp|scp\s+.*@)")}),
)


def _renamed(metadata: dict[str, Any]) -> bool:
    image = str(metadata.get("Image") or "").replace("/", "\\").rsplit("\\", 1)[-1].lower()
    original = str(metadata.get("OriginalFileName") or "").lower().removesuffix(".mui")
    return bool(image and original) and image != original


def _field(metadata: dict[str, Any], names: str) -> str | None:
    for name in names.split("|"):
        for key in (name, name.lower()):
            if key in metadata and metadata[key] not in (None, ""):
                return str(metadata[key])
    return None


def _provider(event: ArtifactEvent) -> str:
    meta = event.metadata
    return " ".join(str(meta.get(key) or "") for key in ("provider", "channel")).lower()


def _event_id(event: ArtifactEvent) -> int | None:
    raw = event.metadata.get("event_id")
    try:
        return int(str(raw).strip())
    except (TypeError, ValueError):
        return None


def rule_matches(rule: Rule, event: ArtifactEvent) -> bool:
    event_id = _event_id(event)
    if event_id is None or not rule.applies(event_id, _provider(event)):
        return False
    for names, pattern in rule.match.items():
        value = _field(event.metadata, names)
        if value is None or not pattern.search(value):
            return False
    for names, pattern in rule.exclude.items():
        value = _field(event.metadata, names)
        if value is not None and pattern.search(value):
            return False
    return rule.check is None or rule.check(event.metadata)


class WindowsRuleDetector:
    """Apply ``RULES`` to parsed Windows events. One finding per rule per file."""

    name = "builtin-windows-rules"
    max_findings = 400

    def detect(
        self,
        artifacts: list[ArtifactEvent],
        binary_features: list[BinaryFeature],
        timeline: list[TimelineEvent],
    ) -> list[Finding]:
        del binary_features, timeline
        findings: list[Finding] = []
        counts: dict[tuple[str, str], int] = {}
        firsts: dict[tuple[str, str], Finding] = {}
        for event in artifacts:
            if _event_id(event) is None:
                continue
            for rule in RULES:
                if not rule_matches(rule, event):
                    continue
                citation = citation_from_event(event)
                if citation is None:
                    continue
                key = (rule.rule_id, citation.source_file)
                counts[key] = counts.get(key, 0) + 1
                if key in firsts:
                    continue
                finding = Finding(
                    finding_id=stable_id("win", rule.rule_id, citation.sha256, citation.row),
                    title=rule.title,
                    severity=rule.severity,
                    confidence=0.75,
                    tactic=rule.tactic,
                    technique_id=rule.technique,
                    evidence=[f"source={event.source}", f"artifact_id={event.artifact_id}",
                              f"event_type={event.event_type}"],
                    recommendation="Open the cited event, confirm the behaviour, and scope other hosts for it.",
                    confidence_low=0.6,
                    confidence_high=0.9,
                    citations=[citation],
                    origin="detector",
                )
                firsts[key] = finding
                findings.append(finding)
                if len(findings) >= self.max_findings:
                    return findings
        for (rule_id, source), finding in firsts.items():
            extra = counts[(rule_id, source)] - 1
            if extra:
                finding.recommendation += f" {extra} more matching event(s) in the same file."
        return findings
