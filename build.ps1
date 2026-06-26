# RabbitGhost — lean PyInstaller build (onedir, ghost-rabbit icon).
# Requires: the `rabbit` mind on RABBIT_HOME, pyinstaller + curl_cffi installed.
param(
    [string]$RabbitHome = "C:\Users\Admin\Desktop\RabbitProject-clean"
)
$ErrorActionPreference = "Stop"
$repo = $PSScriptRoot
$env:PYTHONPATH = "$repo\src;$RabbitHome"
$tmp = "$repo\.build-tmp"; New-Item -ItemType Directory -Force $tmp | Out-Null
$env:TMP = $tmp; $env:TEMP = $tmp

python -m PyInstaller --noconfirm --clean --onedir --name RabbitGhost `
  --icon "$repo\assets\ghost_rabbit.ico" `
  --paths "$repo\src" --paths "$RabbitHome" `
  --collect-submodules rabbitghost --collect-data rabbitghost `
  --collect-submodules rabbit.security.ghost `
  --hidden-import rabbit.research.sovereign_browser_engine `
  --hidden-import rabbit.network.sovereign_wireguard `
  --hidden-import rabbit.core.crypto `
  --hidden-import rabbit.core.sovereign_downloader `
  --hidden-import rabbit.council.dominance `
  --hidden-import rabbit.core.sovereign_semantic `
  --hidden-import rabbit.perception.sovereign_ocr `
  --collect-all curl_cffi `
  --exclude-module numpy --exclude-module pandas --exclude-module scipy --exclude-module matplotlib `
  --exclude-module xarray --exclude-module h5py --exclude-module pyarrow --exclude-module dask `
  --exclude-module distributed --exclude-module patsy --exclude-module sympy --exclude-module statsmodels `
  --exclude-module numba --exclude-module bokeh --exclude-module tables --exclude-module numexpr `
  --exclude-module sklearn --exclude-module Cython --exclude-module sqlalchemy `
  --exclude-module torch --exclude-module playwright --exclude-module selenium `
  --exclude-module PyQt5 --exclude-module PyQt6 --exclude-module PySide2 --exclude-module PySide6 `
  --exclude-module IPython --exclude-module jupyter --exclude-module notebook --exclude-module tkinter `
  --distpath "$repo\dist" --workpath "$repo\build" --specpath "$repo" `
  "$repo\src\rabbitghost\console.py"

Write-Host "Build complete -> $repo\dist\RabbitGhost\RabbitGhost.exe"
