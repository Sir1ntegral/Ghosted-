# Ghosted — PyInstaller build (onedir, ghost-rabbit icon). Standalone: NO rabbit mind.
#
#   .\build.ps1            # FULL build (includes numpy/scipy -> meaning-ranking works)
#   .\build.ps1 -Lean      # LEAN build (excludes numpy/scipy -> lexical ranking only, smaller)
#
# Requires: pyinstaller + the runtime deps (curl_cffi, beautifulsoup4, Pillow) installed.
param(
    [switch]$Lean
)
$ErrorActionPreference = "Stop"
$repo = $PSScriptRoot

$env:PYTHONPATH = "$repo\src"
$tmp = "$repo\.build-tmp"; New-Item -ItemType Directory -Force $tmp | Out-Null
$env:TMP = $tmp; $env:TEMP = $tmp

$icon = "$repo\assets\ghost_rabbit.ico"
$model = "$repo\src\ghosted\data\semantic_model.json"

$args = @(
    "--noconfirm", "--clean", "--onedir", "--name", "Ghosted",
    "--icon", $icon,
    "--paths", "$repo\src",
    "--collect-submodules", "ghosted", "--collect-data", "ghosted",
    "--collect-all", "curl_cffi"
)
# Belt-and-suspenders: explicitly ship the trained model + the icon as data so the
# packaged app keeps meaning-ranking and the shortcut icon even if collect-data misses.
if (Test-Path $model) { $args += @("--add-data", "$model;ghosted/data") }
if (Test-Path $icon) { $args += @("--add-data", "$icon;.") }

# Bundle Tor so the anonymized browser works 100% out of the box (no Tor Browser
# needed on the user's machine). tor.py finds the bundled binary at _MEIPASS/tor/tor.exe.
# Source: $env:GHOSTED_TOR_BUNDLE, else the Tor Browser default location. Not committed
# to the repo (redistributed at build time under Tor's free license).
$torExe = $env:GHOSTED_TOR_BUNDLE
if (-not $torExe -or -not (Test-Path $torExe)) {
    $torExe = Join-Path $HOME "Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe"
}
if (Test-Path $torExe) {
    $args += @("--add-binary", "$torExe;tor")
    Write-Host "[tor] bundling $torExe"
    $torPt = Join-Path (Split-Path $torExe) "PluggableTransports"
    if (Test-Path $torPt) { $args += @("--add-data", "$torPt;tor/PluggableTransports") }
} else {
    Write-Host "[tor] no tor.exe found to bundle -> Tor egress will need Tor Browser/PATH at runtime"
}

# Optional runtime libs — collected only when installed (each gates a capability;
# the app degrades cleanly without them, so a missing one must not break the build).
foreach ($opt in @("bs4", "rapidocr_onnxruntime", "pypdf", "docx")) {
    $present = $false
    try { python -c "import $opt" 2>$null; $present = ($LASTEXITCODE -eq 0) } catch {}
    if ($present) { $args += @("--collect-all", $opt) }
}

# Heavy modules never needed by Ghosted — always excluded.
$alwaysExclude = @(
    "pandas", "matplotlib", "xarray", "h5py", "pyarrow", "dask", "distributed",
    "patsy", "sympy", "statsmodels", "numba", "bokeh", "tables", "numexpr",
    "sklearn", "Cython", "sqlalchemy", "torch", "playwright", "selenium",
    "PyQt5", "PyQt6", "PySide2", "PySide6", "IPython", "jupyter", "notebook", "tkinter"
)
# numpy/scipy power the semantic meaning-ranking — kept in FULL, dropped in LEAN.
if ($Lean) { $alwaysExclude += @("numpy", "scipy") }
foreach ($m in $alwaysExclude) { $args += @("--exclude-module", $m) }

$args += @(
    "--distpath", "$repo\dist", "--workpath", "$repo\build", "--specpath", "$repo",
    "$repo\src\ghosted\console.py"
)

python -m PyInstaller @args
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed (exit $LASTEXITCODE) — see output above." }
if (-not (Test-Path "$repo\dist\Ghosted\Ghosted.exe")) {
    throw "PyInstaller reported success but $repo\dist\Ghosted\Ghosted.exe is missing."
}

# ── Code signing (Authenticode) — INERT until a certificate is provided ──────────────
# An unsigned binary triggers SmartScreen / App Control warnings, which for a security
# tool reads as untrustworthy. Configure ONE of the following (checked in this order):
#   Azure Artifact Signing (cloud EV — instant SmartScreen trust, no hardware token):
#     $env:GHOSTED_SIGN_AZURE_JSON = 'C:\path\metadata.json'   (Endpoint/Account/Profile)
#     $env:GHOSTED_SIGN_AZURE_DLIB = '...Azure.CodeSigning.Dlib.dll'  (optional; auto-located)
#     Needs: winget install Microsoft.Azure.ArtifactSigningClientTools + `az login` (or a
#     service principal) holding the Certificate Profile Signer role. See SIGNING.md.
#   -- or -- a .pfx file:  $env:GHOSTED_SIGN_PFX + $env:GHOSTED_SIGN_PASS
#   -- or -- a cert in the local store:  $env:GHOSTED_SIGN_THUMBPRINT
# With none set the build simply skips signing (unsigned exe, same as before).
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
    $roots = @("$env:ProgramFiles\Microsoft Artifact Signing Client Tools",
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
        # Azure Artifact Signing (formerly Trusted Signing) — cloud EV via signtool dlib.
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
Sign-File "$repo\dist\Ghosted\Ghosted.exe"

Write-Host "Build complete -> $repo\dist\Ghosted\Ghosted.exe"
