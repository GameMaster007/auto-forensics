; ╔═══════════════════════════════════════════════════════════════════════╗
; ║  Auto Forensics — Inno Setup 6 Installer Script                     ║
; ╚═══════════════════════════════════════════════════════════════════════╝
;
; Build with:
;   "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer\autoforensics.iss
;
; Prerequisites:
;   - Run build_app.cmd first to create dist\AutoForensics\

#define MyAppName      "Auto Forensics"
#define MyAppVersion   "1.0.0"
#define MyAppPublisher "Auto Forensics Team"
#define MyAppURL       "https://github.com/auto-forensics/auto-forensics"
#define MyAppExeName   "AutoForensics.exe"
#define MyCliExeName   "auto-forensics.exe"
#define MyDistDir      "..\dist\AutoForensics"

[Setup]
AppId={{F3A2B8C1-7D4E-4F9A-B3C2-E1D5F6A7B8C9}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/issues
AppUpdatesURL={#MyAppURL}/releases
DefaultDirName={autopf}\Auto Forensics
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
LicenseFile=..\LICENSE
; InfoBeforeFile lets us show a "Read Me" before install
; InfoBeforeFile=..\README.md
; Require elevation so we can register context menus and write Program Files
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog
OutputDir=..\dist\installer
OutputBaseFilename=AutoForensics-{#MyAppVersion}-Setup
SetupIconFile=..\assets\icon.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
WizardResizable=yes
WizardImageFile=compiler:WizModernImage-IS.bmp
WizardSmallImageFile=compiler:WizModernSmallImage-IS.bmp
DisableProgramGroupPage=no
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName}
VersionInfoVersion={#MyAppVersion}.0
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription={#MyAppName} Installer
VersionInfoProductName={#MyAppName}
VersionInfoProductVersion={#MyAppVersion}
AllowDowngrade=no
; Show estimated required disk space
ExtraDiskSpaceRequired=10485760
; Close the app before upgrading
CloseApplications=yes
CloseApplicationsFilter=AutoForensics.exe,auto-forensics.exe
; Restart apps after upgrade
RestartApplications=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon";    Description: "{cm:CreateDesktopIcon}";                     GroupDescription: "{cm:AdditionalIcons}"
Name: "addtopath";      Description: "Add command-line tools to system PATH";      GroupDescription: "Command line"; Flags: checkedonce
Name: "contextmenu";    Description: "Add ""Scan with Auto Forensics"" to right-click menu"; GroupDescription: "Windows Explorer"; Flags: checkedonce
Name: "fileassoc";      Description: "Associate .afcase files with Auto Forensics"; GroupDescription: "File associations"; Flags: checkedonce
Name: "autostart";      Description: "Launch at Windows startup (minimised to tray)"; GroupDescription: "Startup"; Flags: unchecked

[Files]
; ── Application bundle from PyInstaller ─────────────────────────────────
Source: "{#MyDistDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

; ── Examples ────────────────────────────────────────────────────────────
Source: "..\examples\*"; DestDir: "{app}\examples"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
; ── Start Menu ──────────────────────────────────────────────────────────
Name: "{group}\{#MyAppName}";                  Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\assets\icon.ico"; Comment: "Launch Auto Forensics"
Name: "{group}\{#MyAppName} (Server Only)";    Filename: "{app}\{#MyAppExeName}"; Parameters: "--no-browser --no-splash"; IconFilename: "{app}\assets\icon.ico"; Comment: "Start server without opening browser"
Name: "{group}\{#MyAppName} Command Line";     Filename: "cmd.exe"; Parameters: "/k ""{app}\{#MyCliExeName}"" --help"; WorkingDir: "{userdocs}"; IconFilename: "{app}\assets\icon.ico"; Comment: "Open CLI"
Name: "{group}\Data Directory";                Filename: "{%USERPROFILE}\.auto_forensics"; Comment: "Open your cases and data directory"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"

; ── Desktop (optional) ──────────────────────────────────────────────────
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\assets\icon.ico"; Tasks: desktopicon; Comment: "Launch Auto Forensics"

[Registry]
; ── Application metadata ────────────────────────────────────────────────
Root: HKLM; Subkey: "SOFTWARE\{#MyAppPublisher}\{#MyAppName}"; ValueType: string; ValueName: "InstallPath"; ValueData: "{app}"; Flags: uninsdeletekey
Root: HKLM; Subkey: "SOFTWARE\{#MyAppPublisher}\{#MyAppName}"; ValueType: string; ValueName: "Version";     ValueData: "{#MyAppVersion}"

; ── PATH registration (optional) ────────────────────────────────────────
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Check: NeedsAddPath('{app}'); Tasks: addtopath

; ── Auto-start (optional) ───────────────────────────────────────────────
Root: HKCU; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "AutoForensics"; ValueData: """{app}\{#MyAppExeName}"" --no-splash"; Flags: uninsdeletevalue; Tasks: autostart

; ── Context menu: Scan file ─────────────────────────────────────────────
Root: HKCR; Subkey: "*\shell\AutoForensicsScan";         ValueType: string; ValueData: "Scan with Auto Forensics"; Flags: uninsdeletekey; Tasks: contextmenu
Root: HKCR; Subkey: "*\shell\AutoForensicsScan";         ValueType: string; ValueName: "Icon"; ValueData: "{app}\assets\icon.ico"; Tasks: contextmenu
Root: HKCR; Subkey: "*\shell\AutoForensicsScan\command";  ValueType: string; ValueData: """{app}\{#MyCliExeName}"" scan --path ""%1"""; Tasks: contextmenu

; ── Context menu: Scan directory ────────────────────────────────────────
Root: HKCR; Subkey: "Directory\shell\AutoForensicsScanDir";         ValueType: string; ValueData: "Scan directory with Auto Forensics"; Flags: uninsdeletekey; Tasks: contextmenu
Root: HKCR; Subkey: "Directory\shell\AutoForensicsScanDir";         ValueType: string; ValueName: "Icon"; ValueData: "{app}\assets\icon.ico"; Tasks: contextmenu
Root: HKCR; Subkey: "Directory\shell\AutoForensicsScanDir\command";  ValueType: string; ValueData: """{app}\{#MyCliExeName}"" scan-dir --path ""%1"""; Tasks: contextmenu

; ── Context menu: Scan from directory background ────────────────────────
Root: HKCR; Subkey: "Directory\Background\shell\AutoForensicsScanDir";         ValueType: string; ValueData: "Scan directory with Auto Forensics"; Flags: uninsdeletekey; Tasks: contextmenu
Root: HKCR; Subkey: "Directory\Background\shell\AutoForensicsScanDir";         ValueType: string; ValueName: "Icon"; ValueData: "{app}\assets\icon.ico"; Tasks: contextmenu
Root: HKCR; Subkey: "Directory\Background\shell\AutoForensicsScanDir\command";  ValueType: string; ValueData: """{app}\{#MyCliExeName}"" scan-dir --path ""%V"""; Tasks: contextmenu

; ── .afcase file association (optional) ─────────────────────────────────
Root: HKCR; Subkey: ".afcase";                                                    ValueType: string; ValueData: "AutoForensics.CaseArchive"; Flags: uninsdeletekey; Tasks: fileassoc
Root: HKCR; Subkey: "AutoForensics.CaseArchive";                                  ValueType: string; ValueData: "Auto Forensics Case Archive"; Flags: uninsdeletekey; Tasks: fileassoc
Root: HKCR; Subkey: "AutoForensics.CaseArchive\DefaultIcon";                      ValueType: string; ValueData: "{app}\assets\icon.ico,0"; Tasks: fileassoc
Root: HKCR; Subkey: "AutoForensics.CaseArchive\shell\open";                       ValueType: string; ValueData: "Open with Auto Forensics"; Tasks: fileassoc
Root: HKCR; Subkey: "AutoForensics.CaseArchive\shell\open\command";               ValueType: string; ValueData: """{app}\{#MyCliExeName}"" import --archive ""%1"""; Tasks: fileassoc

[Run]
; ── Post-install: create data directories ───────────────────────────────
Filename: "{app}\{#MyCliExeName}"; Parameters: "config"; Flags: runhidden nowait; StatusMsg: "Initializing data directories..."

; ── Launch after install ────────────────────────────────────────────────
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent unchecked

[UninstallDelete]
; Clean up any generated files in the install directory
Type: filesandordirs; Name: "{app}\__pycache__"
Type: filesandordirs; Name: "{app}\logs"

[Code]
// ── Helper: check if a path is already in PATH ────────────────────────
function NeedsAddPath(Param: string): boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKEY_LOCAL_MACHINE,
    'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
    'Path', OrigPath)
  then begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Uppercase(Param) + ';', ';' + Uppercase(OrigPath) + ';') = 0;
end;

// ── Helper: remove our entry from PATH on uninstall ───────────────────
procedure RemoveFromPath();
var
  OrigPath, AppDir: string;
  P: Integer;
begin
  AppDir := ExpandConstant('{app}');
  if RegQueryStringValue(HKEY_LOCAL_MACHINE,
    'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
    'Path', OrigPath) then
  begin
    P := Pos(';' + Uppercase(AppDir), Uppercase(OrigPath));
    if P > 0 then
    begin
      Delete(OrigPath, P, Length(AppDir) + 1);
      RegWriteStringValue(HKEY_LOCAL_MACHINE,
        'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
        'Path', OrigPath);
    end;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
  begin
    RemoveFromPath();
  end;
end;

// ── Customise welcome text ────────────────────────────────────────────
procedure InitializeWizard;
begin
  WizardForm.WelcomeLabel2.Caption :=
    'This will install Auto Forensics v' + '{#MyAppVersion}' +
    ' on your computer.' + #13#10 + #13#10 +
    'Auto Forensics is an autonomous digital forensics platform ' +
    'that ingests evidence, analyses binaries, detects threats, ' +
    'and generates detailed case reports.' + #13#10 + #13#10 +
    'Features:' + #13#10 +
    '  - System tray with one-click dashboard access' + #13#10 +
    '  - Right-click "Scan" integration in Explorer' + #13#10 +
    '  - 30+ command-line tools for forensic analysis' + #13#10 +
    '  - AI-assisted malware triage and reporting' + #13#10 + #13#10 +
    'Click Next to continue, or Cancel to exit.';
end;
