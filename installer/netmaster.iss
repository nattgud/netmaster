; Inno Setup script for NetMaster-Setup.exe. Built by .github/workflows/release.yml:
;   iscc /DAppVersion=1.2.3 installer\netmaster.iss
; The real work is done by scripts\install-service.ps1 (Python, packages, firewall, background task, tray icon).

#ifndef AppVersion
  #define AppVersion "0.0.0-dev"
#endif

[Setup]
AppId={{6F1D2B9E-6C3A-4D8E-9B57-2E7C1A0B4F21}
AppName=NetMaster
AppVersion={#AppVersion}
AppPublisher=nattgud
AppPublisherURL=https://github.com/nattgud/netmaster
AppSupportURL=https://github.com/nattgud/netmaster/issues
DefaultDirName={autopf}\NetMaster
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\dist
OutputBaseFilename=NetMaster-Setup
SetupIconFile=netmaster.ico
UninstallDisplayIcon={app}\installer\netmaster.ico
LicenseFile=..\LICENSE
WizardStyle=modern
Compression=lzma2
SolidCompression=yes
CloseApplications=no

[Files]
Source: "..\netmaster\*"; DestDir: "{app}\netmaster"; Excludes: "__pycache__"; Flags: recursesubdirs ignoreversion
Source: "..\web\*"; DestDir: "{app}\web"; Flags: recursesubdirs ignoreversion
Source: "..\scripts\*"; DestDir: "{app}\scripts"; Excludes: "__pycache__,deploy.ps1,add-deploy-key.ps1"; Flags: recursesubdirs ignoreversion
Source: "..\requirements.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "netmaster.ico"; DestDir: "{app}\installer"; Flags: ignoreversion

[InstallDelete]
; Old code is replaced as a whole. data\, .venv and config.toml are kept.
Type: filesandordirs; Name: "{app}\netmaster"
Type: filesandordirs; Name: "{app}\web"
Type: filesandordirs; Name: "{app}\scripts"

[Icons]
Name: "{autoprograms}\NetMaster"; Filename: "http://localhost:8000"; IconFilename: "{app}\installer\netmaster.ico"
Name: "{autoprograms}\NetMaster tray icon"; Filename: "{app}\.venv\Scripts\pythonw.exe"; Parameters: """{app}\scripts\tray.pyw"""; WorkingDir: "{app}"; IconFilename: "{app}\installer\netmaster.ico"

[Run]
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\scripts\install-service.ps1"" -NoTrayStart"; WorkingDir: "{app}"; StatusMsg: "Setting up Python and the NetMaster service (this can take a few minutes)..."; Flags: waituntilterminated
Filename: "{app}\.venv\Scripts\pythonw.exe"; Parameters: """{app}\scripts\tray.pyw"""; WorkingDir: "{app}"; Description: "Show the NetMaster icon in the taskbar"; Flags: postinstall nowait runasoriginaluser
Filename: "http://localhost:8000"; Description: "Open NetMaster"; Flags: postinstall shellexec nowait runasoriginaluser

[UninstallRun]
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\scripts\uninstall-service.ps1"""; RunOnceId: "NetMasterService"; Flags: runhidden waituntilterminated

[UninstallDelete]
; The database and settings in data\ are left; delete the folder by hand to remove everything.
Type: filesandordirs; Name: "{app}\.venv"
Type: filesandordirs; Name: "{app}\netmaster"
Type: filesandordirs; Name: "{app}\scripts"

[Code]
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Code: Integer;
begin
  // Stop a running NetMaster and tray icon before files are replaced.
  Exec('powershell.exe',
    '-NoProfile -Command "Stop-ScheduledTask -TaskName NetMaster -ErrorAction SilentlyContinue; ' +
    'Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like ''*-m netmaster*'' -or $_.CommandLine -like ''*tray.pyw*'' } | ' +
    'ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }"',
    '', SW_HIDE, ewWaitUntilTerminated, Code);
  Result := '';
end;

procedure CurPageChanged(CurPageID: Integer);
var
  SetupCode: AnsiString;
begin
  if CurPageID = wpFinished then
    if LoadStringFromFile(ExpandConstant('{app}\data\setup-code.txt'), SetupCode) then
    begin
      SetupCode := Trim(SetupCode);
      if SetupCode <> '' then
        WizardForm.FinishedLabel.Caption := WizardForm.FinishedLabel.Caption + #13#10#13#10 +
          'Setup code: ' + SetupCode + #13#10 +
          'Open NetMaster on this computer to choose a password. You need the code only if you ' +
          'set the password from another device. The tray icon shows it too.';
    end;
end;
