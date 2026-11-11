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
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable

from .citations import citation_from_event
from .ids import stable_id
from .models import ArtifactEvent, BinaryFeature, Finding, TimelineEvent

SYSMON = "sysmon"
I = re.IGNORECASE


# ".*" between two parts of a rule makes matching quadratic or worse on long
# attacker-controlled fields. Every unbounded gap becomes a bounded one. With
# fields capped at FIELD_LIMIT the cost stays small; padding beyond the gap is
# itself reported by the "long-command-line" rule.
GAP = r"[^\n]{0,2000}"


def rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern.replace(".*", GAP), I)


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
    # Volume rules: report only when at least ``min_count`` events in one file
    # match, and, if ``distinct`` names a field, at least ``min_distinct``
    # different values of it (for example many user names in a spray).
    min_count: int = 1
    distinct: str = ""
    min_distinct: int = 1
    # With ``window_seconds`` the counts above must fall inside one sliding
    # time window, per value of ``group_by`` (for example per source IP).
    window_seconds: int = 0
    group_by: str = ""

    def applies(self, event_id: int, provider: str) -> bool:
        return event_id in self.event_ids and (not self.provider or self.provider in provider)


def _ids(*values: int) -> frozenset[int]:
    return frozenset(values)


PROC = _ids(1, 4688)
IMAGE = "Image|NewProcessName"
CMD = "CommandLine|ProcessCommandLine"
PARENT = "ParentImage|ParentProcessName"

VM_READ = 0x10
FIELD_LIMIT = 8 * 1024
LONG_FIELDS = {"ScriptBlockText", "Payload", "Data"}
COMMAND_FIELDS = {"CommandLine", "ProcessCommandLine", "ParentCommandLine", "ImagePath", "ServiceFileName"}
LONG_COMMAND = 2000
_WHITESPACE_RUN = re.compile(r"[ \t]{2,}")
LONG_FIELD_LIMIT = 64 * 1024
_PS_FLAGS = re.compile(r"\s-(e|en|enc|enco|encodedcommand)\s+[a-z0-9+/=]{8,}|-w(indowstyle)?\s+hid(den)?\b|"
                       r"-nop\b[^\n]{0,200}-ep?\s+bypass", re.IGNORECASE)
# Endpoint security products read LSASS as part of normal work. Matched by their
# install folder, not by name alone, so a renamed tool elsewhere still fires.
INSTALLED_SECURITY_TOOL = (r"^c:\\program files( \(x86\))?\\(crowdstrike|windows defender|"
                           r"windows defender advanced threat protection|sentinelone|cylance|carbon black|"
                           r"confer|sophos|eset|kaspersky lab|mcafee|symantec|trend micro|bitdefender|"
                           r"palo alto networks|vmware\\vmware tools|microsoft monitoring agent)\\")
# Per-user apps that install into AppData by design.
KNOWN_USER_APPS = (r"\\appdata\\local\\(microsoft\\(onedrive|teams|edge|windowsapps)|slack|discord|"
                   r"zoom|webex|grammarly|programs\\(microsoft vs code|python|opera))\\|"
                   r"\\appdata\\roaming\\(zoom|spotify|dropbox)\\")
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
         {CMD: rx(r"\b(powershell|pwsh)(\.exe)?\b")},
         check=lambda m: bool(_PS_FLAGS.search(str(_field(m, CMD) or "")[:FIELD_LIMIT]))),
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
    # Scheduled tasks start shells with arguments; a bare interactive shell under svchost is a reverse-shell pattern.
    Rule("svchost-shell", "Interactive shell started directly by a service host", "medium", "execution", "T1059", PROC,
         {PARENT: rx(r"\\svchost\.exe$"), IMAGE: rx(r"\\(cmd|powershell|pwsh)\.exe$"),
          CMD: rx(r"^\"?([a-z]:\\[^\"]*\\)?(cmd|powershell|pwsh)(\.exe)?\"?\s*$")}),
    Rule("wmi-spawn", "WMI provider host started a shell (remote WMI execution)", "high", "execution", "T1047", PROC,
         {PARENT: rx(r"\\wmiprvse\.exe$"), IMAGE: rx(r"\\(cmd|powershell|pwsh|rundll32|mshta|regsvr32)\.exe$")}),
    Rule("user-writable-exec", "Program ran from a user-writable folder", "medium", "execution", "T1204", PROC,
         {IMAGE: rx(r"\\(temp|tmp|downloads|users\\public|perflogs|\$recycle\.bin|programdata|appdata\\roaming)\\"
                    r"[^\\]+\.(exe|scr|com|pif)$")}),
    Rule("scripted-shell", "Script interpreter ran a script from a user-writable folder", "medium", "execution",
         "T1059.005", PROC,
         {IMAGE: rx(r"\\(wscript|cscript|mshta)\.exe$"),
          CMD: rx(r"\\(temp|downloads|users\\public|appdata)\\[^\"]+\.(vbs|vbe|js|jse|hta|wsf)")}),
    Rule("psh-obfuscation", "Obfuscated PowerShell (split strings, backticks, char codes)", "high", "execution",
         "T1027", _ids(4104, 4103, 800),
         {"ScriptBlockText|Payload|Data": rx(r"(\(\s*'[a-z-]{1,4}'\s*\+\s*'[a-z-]{1,4}'.*){2,}|"
                                             r"([a-z]`){2,}[a-z]|(\[char\]\s*\d{2,3}\s*[,+]\s*){4,}|"
                                             r"-join\s*\(?\s*\[char\[\]\]|-bxor\s+0x|"
                                             r"\.replace\(\s*'[^']{1,4}'\s*,\s*''\s*\).*iex")}),
    Rule("psh-scriptblock", "Suspicious PowerShell script block", "high", "execution", "T1059.001",
         _ids(4104, 4103, 800),
         {"ScriptBlockText|Payload|Data": rx(r"(invoke-mimikatz|invoke-shellcode|invoke-reflectivepeinjection|amsiutils|"
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
                             r"authentication packages)|\\netsh\\")}, provider=SYSMON,
         check=lambda m: not _benign_autorun(m)),
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
    # Windows, Office and browsers use BITS for their own updates; those hosts are not reported.
    Rule("bits-job", "BITS job fetched a file from a non-vendor host or ran a local program", "medium",
         "persistence", "T1197", _ids(59, 60),
         {"url|RemoteName": rx(r"^(https?://|[a-z]:\\|\\\\)")},
         {"url|RemoteName": rx(r"^https?://([^/:?#@\\]+\.)?(microsoft\.com|windowsupdate\.com|update\.microsoft\.com|"
                               r"msn\.com|msn-com\.akamaized\.net|live\.com|onenote\.net|sfx\.ms|office\.com|"
                               r"office\.net|msedge\.net|bing\.com|gvt1\.com|google\.com|gstatic\.com|"
                               r"mozilla\.net|adobe\.com|dell\.com|hp\.com|lenovo\.com)(:\d+)?/")},
         provider="bits"),
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
    Rule("boot-debug-signing", "Kernel debugging or test signing enabled at boot", "high", "defense-evasion",
         "T1553.006", _ids(4826), {}, provider="security-auditing",
         check=lambda m: "%%1842" in (str(m.get("KernelDebug")), str(m.get("TestSigning")),
                                       str(m.get("DisableIntegrityChecks")))),
    Rule("eventlog-service-down", "Windows Event Log service stopped or crashed", "high", "defense-evasion",
         "T1562.002", _ids(7036, 7031, 7034), {"param1": rx(r"^windows event log$")},
         {"param2": rx(r"^running$")}, provider="service control manager"),
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
         or bool(re.search(r"0x0+\)?$", str(m.get("Details", "")).lower()))),
    Rule("ps-execution-policy", "PowerShell execution policy set to allow any script", "medium", "defense-evasion",
         "T1059.001", _ids(12, 13, 14), {"TargetObject": rx(r"\\shellids\\microsoft\.powershell\\executionpolicy$"),
                                "Details": rx(r"^(unrestricted|bypass)$")}, provider=SYSMON),
    Rule("office-macro-guard-off", "Office macro or VBA project protection switched off", "medium", "defense-evasion",
         "T1562.001", _ids(12, 13, 14),
         {"TargetObject": rx(r"\\office\\[\d.]+\\\w+\\security\\(accessvbom|vbawarnings)$"),
          "Details": rx(r"0x0*1\)?$")}, provider=SYSMON),
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
                                 r"certutil|wmic|net1?|whoami|nltest)\.exe(\.mui)?$|^psexec\.c$")},
         provider=SYSMON, check=lambda m: _renamed(m)),
    Rule("compile-after-delivery", "Code compiled on the host into a program in a user folder", "medium",
         "defense-evasion", "T1027.004", PROC,
         {IMAGE: rx(r"\\(csc|vbc|jsc|ilasm)\.exe$"),
          CMD: rx(r"/out:\s*\"?([a-z]:\\(users|programdata|windows\\temp)\\[^\"]{0,260}|[^\\\s\":]{1,260})"
                  r"\.(exe|dll)\b")},
         {PARENT: rx(r"\\(msbuild|devenv|vbcscompiler|dotnet)\.exe$")}),
    Rule("ps-downgrade", "PowerShell version 2 engine started (bypasses script logging)", "high", "defense-evasion",
         "T1562.010", _ids(400), {"Data": rx(r"engineversion=2\.")}, provider="powershell"),
    Rule("cve-exploit-audit", "Windows logged an attempt to exploit a known vulnerability", "high", "initial-access",
         "T1190", _ids(1), {"CVEID": rx(r"cve-\d{4}-\d+")}, provider="audit-cve"),
    Rule("cmd-obfuscation", "Obfuscated command line (carets, variable substrings, split quotes)", "high",
         "defense-evasion", "T1027.010", PROC,
         {CMD: rx(r"(\w\^){3,}\w|%[a-z_]{2,40}:~-?\d{1,4}(,-?\d{1,4})?%(.{0,40}%[a-z_]{2,40}:~-?\d{1,4}"
                  r"(,-?\d{1,4})?%){2,}|(\w\"\"){3,}\w|\bset\s+\w{1,20}=[^&]{1,80}&{1,2}\s*set\s+\w{1,20}="
                  r"[^&]{1,80}&{1,2}\s*call\s+%|cmd(\.exe)?\s+/v:on\b.{0,200}![a-z_]{1,40}:~")}),
    Rule("long-command-line", "Unusually long command line (padding can hide content from rules)", "medium",
         "defense-evasion", "T1027", PROC, {CMD: rx(r".")},
         {IMAGE: rx(r"^[a-z]:\\program files( \(x86\))?\\")},
         check=lambda m: len(_WHITESPACE_RUN.sub(" ", str(m.get("CommandLine") or m.get("ProcessCommandLine") or "")))
         > LONG_COMMAND),
    Rule("hidden-file", "File hidden or protected with attrib", "medium", "defense-evasion", "T1564.001", PROC,
         {CMD: rx(r"attrib(\.exe)?\s+.*\+(h|s)\b")}),
    Rule("unsigned-driver", "Driver loaded that is not validly signed", "high", "defense-evasion", "T1014", _ids(6),
         {"Signed|SignatureStatus": rx(r"^(false|unavailable|expired|revoked)")}, provider=SYSMON),
    # ---------------- credential access ----------------
    # Any mask with VM_READ (0x10) or DUP_HANDLE (0x40) can expose LSASS memory.
    Rule("lsass-access", "LSASS memory opened by another process", "critical", "credential-access", "T1003.001",
         _ids(10), {"TargetImage": rx(r"\\lsass\.exe$")},
         {"SourceImage": rx(r"\\(wmiprvse|svchost|msmpeng|mssense|csrss|wininit|lsm|taskmgr|vmtoolsd|"
                            r"mrt|searchindexer|wmiadap)\.exe$|" + INSTALLED_SECURITY_TOOL)}, provider=SYSMON,
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
    Rule("silent-exit-lsass", "LSASS dumped through the silent process exit mechanism", "critical",
         "credential-access", "T1003.001", _ids(3001), {"param1": rx(r"\\lsass\.exe$")}, provider="processexitmonitor"),
    Rule("dsrm-password", "Directory Services Restore Mode password set", "high", "persistence", "T1098",
         _ids(4794), {}, provider="security-auditing"),
    Rule("sid-history", "SID history added to an account", "critical", "privilege-escalation", "T1134.005",
         _ids(4765, 4766), {}, provider="security-auditing"),
    Rule("sedebug-enabled", "Debug privilege enabled by a program outside Windows", "medium", "privilege-escalation",
         "T1134", _ids(4703), {"EnabledPrivilegeList": rx(r"sedebugprivilege")},
         {"ProcessName": rx(r"^c:\\(windows\\(system32|syswow64|servicing|winsxs)|program files( \(x86\))?)\\")},
         provider="security-auditing"),
    Rule("mssql-sa-failure", "Failed SQL Server login to the sa account", "medium", "credential-access", "T1110",
         _ids(18456), {"Data": rx(r"^sa\b")}, provider="mssql"),
    # ---------------- Active Directory changes (Security log on a DC) ----------------
    Rule("ad-delegation-set", "Kerberos delegation configured on an account", "high", "privilege-escalation",
         "T1098", _ids(4738, 4742), {"AllowedToDelegateTo": rx(r"^(?!-$).+")}, provider="security-auditing"),
    Rule("ad-dcshadow-spn", "Global catalog SPN added to a computer account (DCShadow)", "high", "defense-evasion",
         "T1207", _ids(4742), {"ServicePrincipalNames": rx(r"\bGC/|E3514235-4B06-11D1-AB04-00C04FC2DCD2")},
         provider="security-auditing"),
    Rule("ad-sensitive-attribute", "Sensitive Active Directory attribute changed", "high", "persistence", "T1098",
         _ids(5136), {"AttributeLDAPDisplayName": rx(
             r"^(msds-keycredentiallink|msds-allowedtoactonbehalfofotheridentity|msds-allowedtodelegateto|"
             r"sidhistory|serviceprincipalname|scriptpath|msds-supportedencryptiontypes|useraccountcontrol|"
             r"admincount|primarygroupid|altsecurityidentities)$")}, provider="security-auditing"),
    Rule("ad-adminsdholder", "AdminSDHolder permissions changed", "critical", "persistence", "T1098", _ids(5136),
         {"ObjectDN": rx(r"cn=adminsdholder,")}, provider="security-auditing"),
    Rule("ad-gpo-changed", "Group Policy object changed", "medium", "defense-evasion", "T1484.001", _ids(5136),
         {"ObjectClass": rx(r"^grouppolicycontainer$"),
          "AttributeLDAPDisplayName": rx(r"^(gpcmachineextensionnames|gpcuserextensionnames|gpcfilesyspath|versionnumber)$")},
         provider="security-auditing"),
    Rule("gpp-password-read", "Group Policy Preferences file with stored passwords read from SYSVOL", "high",
         "credential-access", "T1552.006", _ids(5145, 4663),
         {"RelativeTargetName|ObjectName": rx(r"(groups|services|scheduledtasks|datasources|drives|printers)\.xml$"),
          "ShareName|ObjectName": rx(r"sysvol")}, provider="security-auditing"),
    Rule("ntds-sam-file-access", "AD database or SAM hive file opened", "high", "credential-access", "T1003.003",
         _ids(4663, 4656), {"ObjectName": rx(r"\\ntds\.dit$|\\config\\(sam|security|system)$")},
         {"ProcessName": rx(r"\\(lsass|ntfrs|dfsrs|wbengine|vssvc|svchost|msmpeng)\.exe$")},
         provider="security-auditing"),
    # ---------------- volume rules ----------------
    Rule("password-guessing", "Repeated failed logons (password guessing)", "medium", "credential-access", "T1110.001",
         _ids(4625, 4771, 4776), {}, provider="security-auditing", min_count=10, window_seconds=600,
         group_by="TargetUserName",
         check=lambda m: str(m.get("event_id")) == "4625" or str(m.get("Status", "")).lower() not in {"0x0", ""}),
    Rule("password-spray", "Failed logons across many accounts (password spraying)", "high", "credential-access",
         "T1110.003", _ids(4625, 4771, 4776), {}, provider="security-auditing", min_count=5,
         distinct="TargetUserName", min_distinct=5, window_seconds=900, group_by="IpAddress",
         check=lambda m: str(m.get("event_id")) == "4625" or str(m.get("Status", "")).lower() not in {"0x0", ""}),
    Rule("account-lockouts", "Several accounts locked out", "medium", "credential-access", "T1110", _ids(4740), {},
         provider="security-auditing", min_count=3, distinct="TargetUserName", min_distinct=2, window_seconds=3600),
    Rule("mssql-brute-force", "Repeated failed SQL Server logins", "medium", "credential-access", "T1110",
         _ids(18456), {}, provider="mssql", min_count=5, window_seconds=600),
    # ---------------- discovery ----------------
    Rule("domain-discovery", "Domain, account or trust discovery command", "medium", "discovery", "T1087.002", PROC,
         {CMD: rx(r"\bnet1?(\.exe)?\s+(user|group|localgroup|accounts)\b.*(/domain|admins)|nltest.*/(dclist|"
                  r"domain_trusts|dsgetdc)|dsquery|adfind|get-addomain|get-aduser|get-netuser|"
                  r"get-domain(user|group|computer|controller)|sharphound|bloodhound|"
                  r"\bsetspn(\.exe)?\s+-[ql]|klist\s+tgt|whoami\s+/(all|groups|priv)")}),
    # One recon command is everyday admin work; several different ones in a few minutes is a pattern.
    Rule("recon-burst", "Burst of host reconnaissance commands", "medium", "discovery", "T1082", PROC,
         {CMD: rx(r"\b(systeminfo|quser|qwinsta|tasklist\s+/(v|svc)|ipconfig\s+/all|arp\s+-a|route\s+print|"
                  r"netstat\s+-(an|ano)|net\s+(share|session|view|use)|wmic\s+.*(qfe|product|service|"
                  r"useraccount|group)\s|get-wmiobject|reg\s+query\s+hk)")},
         {PARENT: rx(r"\\(explorer)\.exe$")}, min_count=3, distinct="CommandLine|ProcessCommandLine",
         min_distinct=3, window_seconds=300),
    Rule("local-group-enum", "Local users or privileged groups enumerated by a command-line tool", "medium",
         "discovery", "T1069.001", _ids(4798, 4799),
         {"CallerProcessName": rx(r"\\(net1?|powershell|pwsh|wmic|cmd|rundll32|dsquery|whoami)\.exe$|^-$")},
         {"SubjectUserName": rx(r"\$$")}, provider="security-auditing"),
    Rule("msi-from-url", "Windows Installer package run from a URL", "medium", "execution", "T1218.007",
         _ids(1040, 1042, 11707, 1033), {"Data": rx(r"https?://")}, provider="msiinstaller"),
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
         {"DestinationPort": rx(r"^(53|137|138)$"), "Image": rx(KNOWN_USER_APPS)}, provider=SYSMON),
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


_AUTORUN_RISKY = re.compile(
    r"(powershell|pwsh|cmd(\.exe)?\s*/c|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|"
    r"\\(temp|tmp|users\\public|perflogs|programdata|downloads)\\|\.(vbs|js|jse|hta|bat|ps1|scr)\b|https?://)",
    re.IGNORECASE)
_AUTORUN_INSTALLED = re.compile(
    r"^\s*\"?(c:\\program files( \(x86\))?\\|c:\\windows\\system32\\|%windir%\\system32\\|"
    r"%programfiles(\(x86\))?%\\)|" + KNOWN_USER_APPS, re.IGNORECASE)


def _benign_autorun(metadata: dict[str, Any]) -> bool:
    """An autorun value that starts an installed or well-known app, with no script or LOLBin in it."""
    target = str(metadata.get("TargetObject") or "").lower()
    if "\\run" not in target:
        return False  # Winlogon, LSA, BootExecute and similar are always worth a look.
    details = str(metadata.get("Details") or "")
    if not details or details.lower() in {"binary data", "(empty)"} or _AUTORUN_RISKY.search(details):
        return False
    return bool(_AUTORUN_INSTALLED.search(details))


def _renamed(metadata: dict[str, Any]) -> bool:
    image = str(metadata.get("Image") or "").replace("/", "\\").rsplit("\\", 1)[-1].lower()
    original = str(metadata.get("OriginalFileName") or "").lower().removesuffix(".mui")
    return bool(image and original) and image != original


def _field(metadata: dict[str, Any], names: str) -> str | None:
    """First present field, cut to a size that keeps matching fast on hostile input."""
    for name in names.split("|"):
        for key in (name, name.lower()):
            if key in metadata and metadata[key] not in (None, ""):
                limit = LONG_FIELD_LIMIT if name in LONG_FIELDS else FIELD_LIMIT
                value = str(metadata[key])
                if name in COMMAND_FIELDS:
                    # Runs of spaces or tabs are the cheapest padding; collapse them before matching.
                    value = _WHITESPACE_RUN.sub(" ", value)
                return value[:limit]
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


def _seconds(timestamp: str | None) -> float | None:
    if not timestamp:
        return None
    try:
        return datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


class _Windows:
    """Sliding time windows for volume rules, per rule, file, and group."""

    def __init__(self) -> None:
        self._events: dict[tuple[str, str, str], deque[tuple[float, str]]] = {}

    def add(self, rule: Rule, source: str, event: ArtifactEvent) -> bool:
        """Record one match; return True once the window holds enough events."""
        moment = _seconds(event.timestamp)
        if moment is None:
            return False
        group = str(_field(event.metadata, rule.group_by) or "") if rule.group_by else ""
        value = str(_field(event.metadata, rule.distinct) or "").lower() if rule.distinct else ""
        queue = self._events.setdefault((rule.rule_id, source, group.lower()), deque())
        queue.append((moment, value))
        # Events are not always in time order; keep the window sorted and trim it.
        if len(queue) > 1 and queue[-2][0] > moment:
            ordered = sorted(queue)
            queue.clear()
            queue.extend(ordered)
        latest = queue[-1][0]
        while queue and latest - queue[0][0] > rule.window_seconds:
            queue.popleft()
        if len(queue) < rule.min_count:
            return False
        return not rule.distinct or len({item[1] for item in queue}) >= rule.min_distinct


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
        values: dict[tuple[str, str], set[str]] = {}
        firsts: dict[tuple[str, str], Finding] = {}
        windows = _Windows()
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
                if rule.distinct:
                    values.setdefault(key, set()).add(str(_field(event.metadata, rule.distinct) or "").lower())
                if key in firsts:
                    continue
                if rule.window_seconds:
                    if not windows.add(rule, citation.source_file, event):
                        continue
                else:
                    if counts[key] < rule.min_count:
                        continue
                    if rule.distinct and len(values.get(key, ())) < rule.min_distinct:
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
            total = counts[(rule_id, source)]
            distinct = len(values.get((rule_id, source), ()))
            if distinct > 1:
                finding.recommendation += f" {total} matching events across {distinct} accounts in the same file."
            elif total > 1:
                finding.recommendation += f" {total - 1} more matching event(s) in the same file."
        return findings
