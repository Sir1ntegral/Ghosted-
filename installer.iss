; Ghosted — Inno Setup installer.
; Build the onedir bundle first (build.ps1 -> dist\Ghosted\), then:  ISCC.exe installer.iss
; Produces installer_out\Ghosted-Setup.exe (per-user, no admin required).

#define AppName "Ghosted"
#define AppVer  "0.1.0"
#ifndef SourceDir
  #define SourceDir "dist\Ghosted"
#endif

[Setup]
AppName={#AppName}
AppVersion={#AppVer}
AppPublisher=Sir1ntegral
AppPublisherURL=https://github.com/Sir1ntegral/Ghosted-
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
UninstallDisplayIcon={app}\Ghosted.exe
UninstallDisplayName={#AppName}
OutputDir=installer_out
OutputBaseFilename=Ghosted-Setup
SetupIconFile=assets\ghost_rabbit.ico
WizardStyle=modern
Compression=lzma2/max
SolidCompression=yes
PrivilegesRequired=lowest
ArchitecturesInstallIn64BitMode=x64compatible
DisableProgramGroupPage=yes

[Tasks]
Name: "desktopicon"; Description: "Create a Desktop shortcut"; GroupDescription: "Additional icons:"

[Files]
; the whole onedir bundle (Ghosted.exe + _internal\, includes bundled Tor)
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion
; the ghost-rabbit icon for shortcuts
Source: "assets\ghost_rabbit.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Ghosted"; Filename: "{app}\Ghosted.exe"; IconFilename: "{app}\ghost_rabbit.ico"
Name: "{group}\Uninstall Ghosted"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Ghosted"; Filename: "{app}\Ghosted.exe"; IconFilename: "{app}\ghost_rabbit.ico"; Tasks: desktopicon

[Run]
Filename: "{app}\Ghosted.exe"; Description: "Launch Ghosted now"; Flags: nowait postinstall skipifsilent
