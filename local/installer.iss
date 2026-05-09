; PAN Copilot â€” Windows Installer Script
; Inno Setup 6.x
; Build with: ISCC.exe installer.iss
; Output: Output\PAN_Copilot_Setup_vX.X.X.exe

#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif

[Setup]
AppId={{A3F7C2D1-84BE-4E9F-B6A2-1D5C3E8F0247}
AppName=ADK Cyber AI
AppVersion={#AppVersion}
AppPublisher=ADK Cyber, LLC
AppPublisherURL=https://adkcyber.com/adk-cyber-ai.html
AppSupportURL=mailto:support@adkcyber.com
AppUpdatesURL=https://adkcyber.com/adk-cyber-ai.html

; Install to Program Files\ADK Cyber AI
DefaultDirName={autopf}\ADK Cyber AI
DefaultGroupName=ADK Cyber AI
DisableProgramGroupPage=yes

; Output installer exe
OutputDir=Output
OutputBaseFilename=PAN_Copilot_Setup_{#AppVersion}
SetupIconFile=..\local\pan_copilot.ico

; Compression
Compression=lzma2/ultra64
SolidCompression=yes
LZMAUseSeparateProcess=yes

; Appearance
WizardStyle=modern
WizardSmallImageFile=

; Require Windows 10 or later (64-bit)
MinVersion=10.0
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64

; Allow non-admin install to user's AppData if no admin rights
PrivilegesRequiredOverridesAllowed=dialog

; Don't restart after install
RestartIfNeededByRun=no

; Uninstaller
UninstallDisplayName=ADK Cyber AI
UninstallDisplayIcon={app}\PAN Copilot.exe

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"; Flags: checkedonce

[Files]
; Everything from the PyInstaller dist folder
Source: "dist\PAN Copilot\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
; Start Menu
Name: "{group}\ADK Cyber AI"; Filename: "{app}\PAN Copilot.exe"; Comment: "AI Assistant for Palo Alto Networks Engineers"
Name: "{group}\Uninstall ADK Cyber AI"; Filename: "{uninstallexe}"

; Desktop (optional)
Name: "{autodesktop}\ADK Cyber AI"; Filename: "{app}\PAN Copilot.exe"; Comment: "AI Assistant for Palo Alto Networks Engineers"; Tasks: desktopicon

[Run]
; Offer to launch after install
Filename: "{app}\PAN Copilot.exe"; Description: "Launch ADK Cyber AI"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Nothing extra needed â€” standard uninstaller removes all installed files

[Code]
// Shut down any running ADK Cyber AI instance before installation begins.
// Runs before Inno Setup touches a single file.
//
// Strategy (layered, most-reliable first):
//   1. Read the browser PID written by pan_copilot.py to %TEMP%\adk_cyber_ai_edge.pid
//      and kill that specific process — precise, works even when Edge is shared.
//   2. Kill PAN Copilot.exe by image name (graceful then force).
//   3. Write a PowerShell script to a temp file and execute it — avoids command-line
//      quoting issues; finds any remaining Edge/Chrome window titled "ADK Cyber AI*"
//      and sends WM_CLOSE, then force-kills if still alive.
//   4. Sleep 2 s for Windows to release all file handles.

function InitializeSetup(): Boolean;
var
  ResultCode : Integer;
  PidFile    : String;
  PidStr     : AnsiString;  { LoadStringFromFile requires AnsiString }
  ScriptFile : String;
begin
  // ── Step 1: kill browser by saved PID ──────────────────────────────────────
  PidFile := ExpandConstant('{%TEMP}') + '\adk_cyber_ai_edge.pid';
  if FileExists(PidFile) then begin
    if LoadStringFromFile(PidFile, PidStr) then begin
      PidStr := Trim(String(PidStr));
      if PidStr <> '' then
        Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /PID ' + String(PidStr),
          '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    end;
    DeleteFile(PidFile);
  end;

  // ── Step 2: kill server process by image name ───────────────────────────────
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/IM "PAN Copilot.exe"',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM "PAN Copilot.exe"',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  // ── Step 3: PowerShell fallback — close any remaining ADK Cyber AI window ──
  // Write script to a temp file so no command-line quoting issues arise.
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

  // ── Step 4: final pause for file-handle release ─────────────────────────────
  Sleep(2000);

  Result := True;
end;

