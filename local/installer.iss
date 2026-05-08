; PAN Copilot â€” Windows Installer Script
; Inno Setup 6.x
; Build with: ISCC.exe installer.iss
; Output: Output\PAN_Copilot_Setup_vX.X.X.exe

#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif

[Setup]
AppId={{A3F7C2D1-84BE-4E9F-B6A2-1D5C3E8F0247}
AppName=PAN Copilot
AppVersion={#AppVersion}
AppPublisher=ADK Cyber, LLC
AppPublisherURL=https://adkcyber.com/pan-copilot.html
AppSupportURL=mailto:support@adkcyber.com
AppUpdatesURL=https://adkcyber.com/pan-copilot.html

; Install to Program Files\PAN Copilot
DefaultDirName={autopf}\PAN Copilot
DefaultGroupName=PAN Copilot
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
UninstallDisplayName=PAN Copilot
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
Name: "{group}\PAN Copilot"; Filename: "{app}\PAN Copilot.exe"; Comment: "AI Assistant for Palo Alto Networks Engineers"
Name: "{group}\Uninstall PAN Copilot"; Filename: "{uninstallexe}"

; Desktop (optional)
Name: "{autodesktop}\PAN Copilot"; Filename: "{app}\PAN Copilot.exe"; Comment: "AI Assistant for Palo Alto Networks Engineers"; Tasks: desktopicon

[Run]
; Offer to launch after install
Filename: "{app}\PAN Copilot.exe"; Description: "Launch PAN Copilot"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Nothing extra needed â€” standard uninstaller removes all installed files

[Code]
// Show a friendly finish message
procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    // Nothing extra needed
  end;
end;

