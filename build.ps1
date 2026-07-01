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
# tool reads as untrustworthy. Configure ONE of the following to sign automatically:
#   $env:GHOSTED_SIGN_PFX  = 'C:\path\to\cert.pfx'   $env:GHOSTED_SIGN_PASS = 'pfx-password'
#   -- or --  $env:GHOSTED_SIGN_THUMBPRINT = '<thumbprint of a cert in the local store>'
# With neither set the build simply skips signing (unsigned exe, same as before).
function Sign-File([string]$path) {
    $pfx = $env:GHOSTED_SIGN_PFX
    $thumb = $env:GHOSTED_SIGN_THUMBPRINT
    if (-not $pfx -and -not $thumb) {
        Write-Host "[sign] no certificate configured -> skipping (set GHOSTED_SIGN_PFX or GHOSTED_SIGN_THUMBPRINT to enable)"
        return
    }
    $signtool = (Get-Command signtool.exe -ErrorAction SilentlyContinue).Source
    if (-not $signtool) {
        $cand = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
                Sort-Object FullName -Descending | Select-Object -First 1
        if ($cand) { $signtool = $cand.FullName }
    }
    if (-not $signtool) { Write-Host "[sign] signtool.exe not found (install the Windows SDK) -> skipping"; return }
    $ts = if ($env:GHOSTED_SIGN_TS) { $env:GHOSTED_SIGN_TS } else { "http://timestamp.digicert.com" }
    if ($pfx) {
        & $signtool sign /fd SHA256 /f $pfx /p $env:GHOSTED_SIGN_PASS /tr $ts /td SHA256 $path
    } else {
        & $signtool sign /fd SHA256 /sha1 $thumb /tr $ts /td SHA256 $path
    }
    if ($LASTEXITCODE -eq 0) { Write-Host "[sign] signed $path" }
    else { throw "signtool failed (exit $LASTEXITCODE) for $path" }
}
Sign-File "$repo\dist\Ghosted\Ghosted.exe"

Write-Host "Build complete -> $repo\dist\Ghosted\Ghosted.exe"
