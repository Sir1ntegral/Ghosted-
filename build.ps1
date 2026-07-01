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

# ── Code signing (Authenticode) — shared with build-installer.ps1 via sign.ps1 ───────
# Sign-File is inert until a certificate is configured (GHOSTED_SIGN_AZURE_JSON / _PFX /
# _THUMBPRINT); see sign.ps1 + SIGNING.md. With none set, the exe is left unsigned.
. "$repo\sign.ps1"
Sign-File "$repo\dist\Ghosted\Ghosted.exe"

Write-Host "Build complete -> $repo\dist\Ghosted\Ghosted.exe"
Write-Host "Next: .\build-installer.ps1  (compiles + signs installer_out\Ghosted-Setup.exe)"
