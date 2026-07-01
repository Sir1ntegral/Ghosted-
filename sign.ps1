# Ghosted — shared Authenticode signing helper (dot-sourced by build.ps1 + build-installer.ps1).
#
# Sign-File is INERT until a certificate is configured. Set ONE of the following
# (checked in this order); with none set, signing is skipped (unsigned output):
#   Azure Artifact Signing (cloud, no hardware token):
#     $env:GHOSTED_SIGN_AZURE_JSON = 'C:\path\metadata.json'   (Endpoint/Account/Profile)
#     $env:GHOSTED_SIGN_AZURE_DLIB = '...Azure.CodeSigning.Dlib.dll'  (optional; auto-located)
#   -- or -- a .pfx file:  $env:GHOSTED_SIGN_PFX + $env:GHOSTED_SIGN_PASS
#   -- or -- a cert in the local store:  $env:GHOSTED_SIGN_THUMBPRINT
# Optional: $env:GHOSTED_SIGN_TS overrides the RFC3161 timestamp URL.

function Find-SignTool {
    $st = (Get-Command signtool.exe -ErrorAction SilentlyContinue).Source
    if (-not $st) {
        $cand = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
                Sort-Object FullName -Descending | Select-Object -First 1
        if ($cand) { $st = $cand.FullName }
    }
    return $st
}
function Find-AzureDlib {
    if ($env:GHOSTED_SIGN_AZURE_DLIB -and (Test-Path $env:GHOSTED_SIGN_AZURE_DLIB)) { return $env:GHOSTED_SIGN_AZURE_DLIB }
    $roots = @("${env:ProgramFiles(x86)}\Microsoft\ArtifactSigningClientTools",
               "$env:ProgramFiles\Microsoft\ArtifactSigningClientTools",
               "${env:ProgramFiles(x86)}\Microsoft Artifact Signing Client Tools",
               "$env:LOCALAPPDATA\Microsoft\MicrosoftTrustedSigningClientTools",
               "$env:USERPROFILE\.dotnet\tools")
    foreach ($r in $roots) {
        if (Test-Path $r) {
            $d = Get-ChildItem $r -Recurse -Filter "Azure.CodeSigning.Dlib.dll" -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($d) { return $d.FullName }
        }
    }
    return $null
}
function Sign-File([string]$path) {
    $azJson = $env:GHOSTED_SIGN_AZURE_JSON
    $pfx = $env:GHOSTED_SIGN_PFX
    $thumb = $env:GHOSTED_SIGN_THUMBPRINT
    if (-not $azJson -and -not $pfx -and -not $thumb) {
        Write-Host "[sign] no certificate configured -> skipping (set GHOSTED_SIGN_AZURE_JSON, GHOSTED_SIGN_PFX, or GHOSTED_SIGN_THUMBPRINT)"
        return
    }
    $signtool = Find-SignTool
    if (-not $signtool) { Write-Host "[sign] signtool.exe not found (install the Windows SDK) -> skipping"; return }

    if ($azJson) {
        # Azure Artifact Signing (formerly Trusted Signing) — cloud via signtool dlib.
        if (-not (Test-Path $azJson)) { throw "[sign] GHOSTED_SIGN_AZURE_JSON not found: $azJson" }
        $dlib = Find-AzureDlib
        if (-not $dlib) { throw "[sign] Azure.CodeSigning.Dlib.dll not found (winget install Microsoft.Azure.ArtifactSigningClientTools, or set GHOSTED_SIGN_AZURE_DLIB)" }
        $ts = if ($env:GHOSTED_SIGN_TS) { $env:GHOSTED_SIGN_TS } else { "http://timestamp.acs.microsoft.com" }
        Write-Host "[sign] Azure Artifact Signing via $dlib"
        & $signtool sign /v /fd SHA256 /tr $ts /td SHA256 /dlib $dlib /dmdf $azJson $path
    }
    else {
        $ts = if ($env:GHOSTED_SIGN_TS) { $env:GHOSTED_SIGN_TS } else { "http://timestamp.digicert.com" }
        if ($pfx) {
            & $signtool sign /fd SHA256 /f $pfx /p $env:GHOSTED_SIGN_PASS /tr $ts /td SHA256 $path
        } else {
            & $signtool sign /fd SHA256 /sha1 $thumb /tr $ts /td SHA256 $path
        }
    }
    if ($LASTEXITCODE -eq 0) { Write-Host "[sign] signed $path" }
    else { throw "signtool failed (exit $LASTEXITCODE) for $path" }
}
