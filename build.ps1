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
Write-Host "Build complete -> $repo\dist\Ghosted\Ghosted.exe"
