; ADK Cyber AI (.NET) — Windows Installer Script
; Inno Setup 6.x — build with: ISCC.exe /DAppVersion=v3.0 installer.iss
; Output: Output\ADK_Cyber_AI_Setup_vX.X.exe
;
; Same AppId as the v2 (Python) installer so installing v3 upgrades an
; existing v2 install in place — including via the v2 in-app auto-updater
; (which runs this installer with /SILENT after verifying its SHA-256 and
; Authenticode signature).

#ifndef AppVersion
  #define AppVersion "3.0.0"
#endif

[Setup]
AppId={{A3F7C2D1-84BE-4E9F-B6A2-1D5C3E8F0247}
AppName=ADK Cyber AI
AppVersion={#AppVersion}
AppPublisher=ADK Cyber, LLC
AppPublisherURL=https://adkcyber.com/adk-cyber-ai.html
AppSupportURL=mailto:support@adkcyber.com
AppUpdatesURL=https://adkcyber.com/adk-cyber-ai.html

DefaultDirName={autopf}\ADK Cyber AI
DefaultGroupName=ADK Cyber AI
DisableProgramGroupPage=yes

OutputDir=Output
OutputBaseFilename=ADK_Cyber_AI_Setup_{#AppVersion}
SetupIconFile=pan_copilot.ico

Compression=lzma2/ultra64
SolidCompression=yes
LZMAUseSeparateProcess=yes

WizardStyle=modern

MinVersion=10.0
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequiredOverridesAllowed=dialog
RestartIfNeededByRun=no

UninstallDisplayName=ADK Cyber AI
UninstallDisplayIcon={app}\PAN Copilot.exe

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"; Flags: checkedonce

[Files]
; Everything from the dotnet publish folder
Source: "publish\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[InstallDelete]
; Upgrading from the v2 (Python/PyInstaller) build: remove its bundle dir so
; stale Python runtime files don't linger next to the .NET exe.
Type: filesandordirs; Name: "{app}\_internal"

[Icons]
Name: "{group}\ADK Cyber AI"; Filename: "{app}\PAN Copilot.exe"; Comment: "AI Assistant for Palo Alto Networks Engineers"
Name: "{group}\Uninstall ADK Cyber AI"; Filename: "{uninstallexe}"
Name: "{autodesktop}\ADK Cyber AI"; Filename: "{app}\PAN Copilot.exe"; Comment: "AI Assistant for Palo Alto Networks Engineers"; Tasks: desktopicon

[Run]
; Interactive installs only — silent updates relaunch via CurStepChanged below
Filename: "{app}\PAN Copilot.exe"; Description: "Launch ADK Cyber AI"; Flags: nowait postinstall skipifsilent

[Code]
// Shut down any running instance before installing. The v3 app is a native
// WPF window owned by PAN Copilot.exe, so killing the image name is enough.
// The v2 (Python) build also ran as PAN Copilot.exe plus an Edge --app window;
// keep the Edge-window fallback so v2→v3 upgrades close it cleanly.
function InitializeSetup(): Boolean;
var
  ResultCode : Integer;
  ScriptFile : String;
begin
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/IM "PAN Copilot.exe"',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM "PAN Copilot.exe"',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  // v2 leftover: close any Edge/Chrome app window titled "ADK Cyber AI*"
  ScriptFile := ExpandConstant('{tmp}') + '\close_adk.ps1';
  SaveStringToFile(ScriptFile,
    'Get-Process msedge,chrome -ErrorAction SilentlyContinue |' + #13#10 +
    '  Where-Object { $_.MainWindowTitle -like "ADK Cyber AI*" } |' + #13#10 +
    '  ForEach-Object { $_.CloseMainWindow() | Out-Null }' + #13#10 +
    'Start-Sleep -Milliseconds 600' + #13#10 +
    'Get-Process msedge,chrome -ErrorAction SilentlyContinue |' + #13#10 +
    '  Where-Object { $_.MainWindowTitle -like "ADK Cyber AI*" } |' + #13#10 +
    '  Stop-Process -Force -ErrorAction SilentlyContinue',
    False);
  Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    '-NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + ScriptFile + '"',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  Sleep(1500);
  Result := True;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
  ExePath: String;
begin
  { In-app updates run the installer with /SILENT, which skips [Run] (skipifsilent).
    Relaunch here so the user gets the new build without manual start. }
  if CurStep = ssPostInstall then
  begin
    if WizardSilent then
    begin
      ExePath := ExpandConstant('{app}\PAN Copilot.exe');
      if FileExists(ExePath) then
        Exec(ExePath, '', ExpandConstant('{app}'), SW_SHOW, ewNoWait, ResultCode);
    end;
  end;
end;
