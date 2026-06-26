; RabbitGhost — Inno Setup installer.
; Compile after building the onedir exe:  ISCC.exe installer.iss
; Produces installer_out\RabbitGhost-Setup.exe (per-user, no admin required).

#define AppName "RabbitGhost"
#define AppVer  "0.1.0"

[Setup]
AppName={#AppName}
AppVersion={#AppVer}
AppPublisher=Lucy / RabbitProject
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
UninstallDisplayIcon={app}\RabbitGhost.exe
UninstallDisplayName={#AppName}
OutputDir=installer_out
OutputBaseFilename=RabbitGhost-Setup
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
; the whole onedir bundle (RabbitGhost.exe + _internal\)
Source: "dist\RabbitGhost\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion
; the ghost-rabbit icon for shortcuts
Source: "assets\ghost_rabbit.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Rabbit Ghost"; Filename: "{app}\RabbitGhost.exe"; IconFilename: "{app}\ghost_rabbit.ico"
Name: "{group}\Uninstall Rabbit Ghost"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Rabbit Ghost"; Filename: "{app}\RabbitGhost.exe"; IconFilename: "{app}\ghost_rabbit.ico"; Tasks: desktopicon

[Run]
Filename: "{app}\RabbitGhost.exe"; Description: "Launch Rabbit Ghost now"; Flags: nowait postinstall skipifsilent
