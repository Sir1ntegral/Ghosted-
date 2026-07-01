# Ghosted — compile the Inno Setup installer and SIGN it, so the downloaded
# Ghosted-Setup.exe is itself signed (not only the app exe inside it).
#
# Run AFTER build.ps1 has produced dist\Ghosted. Signing uses the same certificate
# configuration as build.ps1 (GHOSTED_SIGN_AZURE_JSON / _PFX / _THUMBPRINT; see sign.ps1).
$ErrorActionPreference = "Stop"
$repo = $PSScriptRoot

if (-not (Test-Path "$repo\dist\Ghosted\Ghosted.exe")) {
    throw "dist\Ghosted\Ghosted.exe missing — run .\build.ps1 first."
}

# locate ISCC (Inno Setup 6): PATH, Program Files, or per-user install
$iscc = (Get-Command ISCC.exe -ErrorAction SilentlyContinue).Source
if (-not $iscc) {
    foreach ($c in @("$env:ProgramFiles\Inno Setup 6\ISCC.exe",
                     "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
                     "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe")) {
        if (Test-Path $c) { $iscc = $c; break }
    }
}
if (-not $iscc) {
    throw "ISCC.exe not found — install Inno Setup 6 (winget install -e --id JRSoftware.InnoSetup)."
}
Write-Host "[iscc] $iscc"

& $iscc "$repo\installer.iss"
if ($LASTEXITCODE -ne 0) { throw "ISCC failed (exit $LASTEXITCODE)." }

$installer = "$repo\installer_out\Ghosted-Setup.exe"
if (-not (Test-Path $installer)) { throw "installer not produced: $installer" }

# sign the installer itself with the same certificate as the app exe
. "$repo\sign.ps1"
Sign-File $installer

Write-Host "Installer ready -> $installer"
