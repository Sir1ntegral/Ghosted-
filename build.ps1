# RabbitGhost — PyInstaller build (onedir, ghost-rabbit icon).
#
#   .\build.ps1            # FULL build (includes numpy/scipy -> meaning-ranking works)
#   .\build.ps1 -Lean      # LEAN build (excludes numpy/scipy -> lexical ranking only, smaller)
#
# Requires: the `rabbit` mind on RABBIT_HOME, pyinstaller + curl_cffi installed.
param(
    [string]$RabbitHome,
    [switch]$Lean
)
$ErrorActionPreference = "Stop"
$repo = $PSScriptRoot

# Adapt to whichever rabbit tree exists (canonical first, then the -clean archive).
if (-not $RabbitHome) {
    foreach ($cand in @(
            "$HOME\Desktop\RabbitProject",
            "$HOME\Desktop\RabbitProject-clean")) {
        if (Test-Path (Join-Path $cand "rabbit\__init__.py")) { $RabbitHome = $cand; break }
    }
}
if (-not $RabbitHome -or -not (Test-Path (Join-Path $RabbitHome "rabbit\__init__.py"))) {
    throw "rabbit mind not found. Pass -RabbitHome <path-to-tree-containing-rabbit\>."
}
Write-Host "RabbitHome = $RabbitHome   (variant: $([bool]$Lean ? 'LEAN' : 'FULL'))"

$env:PYTHONPATH = "$repo\src;$RabbitHome"
$tmp = "$repo\.build-tmp"; New-Item -ItemType Directory -Force $tmp | Out-Null
$env:TMP = $tmp; $env:TEMP = $tmp

$icon = "$repo\assets\ghost_rabbit.ico"
$model = "$repo\src\ghosted\data\semantic_model.json"

$args = @(
    "--noconfirm", "--clean", "--onedir", "--name", "RabbitGhost",
    "--icon", $icon,
    "--paths", "$repo\src", "--paths", $RabbitHome,
    "--collect-submodules", "ghosted", "--collect-data", "ghosted",
    "--collect-submodules", "rabbit.security.ghost",
    "--hidden-import", "rabbit.research.sovereign_browser_engine",
    "--hidden-import", "rabbit.network.sovereign_wireguard",
    "--hidden-import", "rabbit.core.crypto",
    "--hidden-import", "rabbit.core.sovereign_downloader",
    "--hidden-import", "rabbit.council.dominance",
    "--hidden-import", "rabbit.core.sovereign_semantic",
    "--hidden-import", "rabbit.perception.sovereign_ocr",
    "--collect-all", "curl_cffi"
)
# Belt-and-suspenders: explicitly ship the trained model + the icon as data so the
# packaged app keeps meaning-ranking and the shortcut icon even if collect-data misses.
if (Test-Path $model) { $args += @("--add-data", "$model;ghosted/data") }
if (Test-Path $icon) { $args += @("--add-data", "$icon;.") }

# Heavy modules never needed by RabbitGhost — always excluded.
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
if (-not (Test-Path "$repo\dist\RabbitGhost\RabbitGhost.exe")) {
    throw "PyInstaller reported success but $repo\dist\RabbitGhost\RabbitGhost.exe is missing."
}
Write-Host "Build complete -> $repo\dist\RabbitGhost\RabbitGhost.exe"
