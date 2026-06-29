<#
.SYNOPSIS
  Autonomous, self-adapting installer for Ghosted -- installs BOTH the FULL and
  LEAN variants (or one), with no external tooling (no Inno Setup) and no prompts.

  It TESTS the host and ADAPTS:
    * OS / architecture   -> verifies a Windows x64 host for the bundled .exe
    * privileges          -> per-user install by default (no admin needed)
    * bundle discovery    -> finds each variant's onedir bundle next to THIS
                             script first (Ghosted-FULL / Ghosted-LEAN), then in
                             dist\ (Ghosted-full / Ghosted-lean); can build if asked
    * Smart App Control   -> detects + warns (unsigned bundles may be blocked)

  Then it copies each found bundle to a per-user location and creates Desktop +
  Start-Menu shortcuts ("Ghosted (Full)" / "Ghosted (Lean)").

.EXAMPLE
  .\Install-Ghosted.ps1                 # autonomous: install every variant found
  .\Install-Ghosted.ps1 -Variant Lean   # install only the lean variant
  .\Install-Ghosted.ps1 -DetectOnly     # print a JSON system report and exit
  .\Install-Ghosted.ps1 -WhatIf         # show the plan without changing anything
  .\Install-Ghosted.ps1 -Build          # (re)build missing bundles, then install
  .\Install-Ghosted.ps1 -Uninstall      # remove all installed variants + shortcuts
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet("Both", "Full", "Lean")]
    [string]$Variant = "Both",
    [string]$InstallRoot,
    [switch]$Build,
    [switch]$DetectOnly,
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$Exe = "Ghosted.exe"
$here = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

# Variant model: bundle-folder candidates (by name), install dir name, shortcut label.
$VARIANTS = [ordered]@{
    Full = @{ names = @("Ghosted-FULL", "Ghosted-Full", "dist\Ghosted-full"); dest = "Ghosted-Full"; label = "Ghosted (Full)"; leanFlag = $false }
    Lean = @{ names = @("Ghosted-LEAN", "Ghosted-Lean", "dist\Ghosted-lean"); dest = "Ghosted-Lean"; label = "Ghosted (Lean)"; leanFlag = $true }
}
$wanted = if ($Variant -eq "Both") { @("Full", "Lean") } else { @($Variant) }

function Get-SystemReport {
    $isWin = $true
    if ($null -ne $IsWindows) { $isWin = $IsWindows }
    $admin = $false
    if ($isWin) {
        try {
            $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
        } catch { $admin = $false }
    }
    $py = (Get-Command python -ErrorAction SilentlyContinue)
    $hasPyInstaller = $false
    if ($py) { try { python -c "import PyInstaller" 2>$null; $hasPyInstaller = ($LASTEXITCODE -eq 0) } catch {} }
    $appControl = "unknown"
    if ($isWin) {
        try {
            $v = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy" -Name VerifiedAndReputablePolicyState -ErrorAction Stop).VerifiedAndReputablePolicyState
            $appControl = @{0 = "off"; 1 = "enforced"; 2 = "evaluation" }[[int]$v]
            if (-not $appControl) { $appControl = "state=$v" }
        } catch { $appControl = "off-or-unset" }
    }
    $localApp = $env:LOCALAPPDATA
    if (-not $localApp) { $localApp = Join-Path $HOME "AppData\Local" }
    $perUserRoot = Join-Path $localApp "Programs"
    $freeGB = $null
    try { $q = (Split-Path -Qualifier $here).TrimEnd(':'); if (-not $q) { $q = 'C' }; $freeGB = [math]::Round((Get-PSDrive $q).Free / 1GB, 1) } catch {}
    # Precompute these (PowerShell 5.1 cannot use an if/else statement directly
    # as a hashtable value -- only PS7 can -- and most Windows hosts default to 5.1).
    $osCap = if ($isWin) { (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption } else { [Environment]::OSVersion.Platform.ToString() }
    $pySrc = if ($py) { $py.Source } else { $null }
    [ordered]@{
        os = $osCap
        isWindows = $isWin; arch = $env:PROCESSOR_ARCHITECTURE; admin = $admin
        appControl = $appControl; here = $here; freeGB = $freeGB
        python = $pySrc; hasPyInstaller = $hasPyInstaller
        perUserRoot = $perUserRoot; icon = (Join-Path $here "assets\ghost_rabbit.ico")
        wantedVariants = $wanted
    }
}

# Locate a variant's bundle dir (containing Ghosted.exe). $null if not found.
function Find-Bundle([string]$key) {
    foreach ($n in $VARIANTS[$key].names) {
        $p = if ([IO.Path]::IsPathRooted($n)) { $n } else { Join-Path $here $n }
        if (Test-Path (Join-Path $p $Exe)) { return $p }
    }
    return $null
}

function New-Shortcut([string]$lnkPath, [string]$target, [string]$icon, [string]$workdir, [string]$desc) {
    $dir = Split-Path -Parent $lnkPath
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force $dir | Out-Null }
    $sh = New-Object -ComObject WScript.Shell
    $sc = $sh.CreateShortcut($lnkPath)
    $sc.TargetPath = $target; $sc.WorkingDirectory = $workdir
    if ($icon -and (Test-Path $icon)) { $sc.IconLocation = $icon }
    $sc.Description = $desc; $sc.Save()
}

function Install-Variant([string]$key, [hashtable]$sys) {
    $v = $VARIANTS[$key]
    $dest = if ($InstallRoot) { Join-Path $InstallRoot $v.dest } else { Join-Path $sys.perUserRoot $v.dest }
    $bundle = Find-Bundle $key
    if (-not $bundle) {
        if ($Build -and $sys.python -and $sys.hasPyInstaller -and (Test-Path (Join-Path $here "build.ps1"))) {
            Write-Host "[$key] no bundle found -- building ..."
            $ba = @{}; if ($v.leanFlag) { $ba['Lean'] = $true }
            if ($PSCmdlet.ShouldProcess("build.ps1", "build $key")) { & (Join-Path $here "build.ps1") @ba; $bundle = Join-Path $here "dist\Ghosted" }
        }
        if (-not $bundle -or -not (Test-Path (Join-Path $bundle $Exe))) {
            Write-Warning "[$key] no bundle found (looked for: $($v.names -join ', ')) -- skipping."
            return $false
        }
    }
    $exe = Join-Path $dest $Exe
    $deskLnk = Join-Path ([Environment]::GetFolderPath('Desktop')) ($v.label + ".lnk")
    $menuLnk = Join-Path ([Environment]::GetFolderPath('Programs')) ($v.label + ".lnk")
    Write-Host "[$key] install: $bundle  ->  $dest"
    if ($PSCmdlet.ShouldProcess($dest, "copy $key bundle + shortcuts")) {
        if (Test-Path $dest) { Remove-Item $dest -Recurse -Force }
        New-Item -ItemType Directory -Force $dest | Out-Null
        Copy-Item (Join-Path $bundle '*') $dest -Recurse -Force
        # Icon: prefer the .ico PyInstaller shipped in the bundle (_internal), then a
        # local assets copy, else fall back to the exe's embedded icon (--icon).
        $icon = Join-Path $dest "_internal\ghost_rabbit.ico"
        if (-not (Test-Path $icon)) {
            if (Test-Path $sys.icon) { Copy-Item $sys.icon (Join-Path $dest 'ghost_rabbit.ico') -Force; $icon = Join-Path $dest 'ghost_rabbit.ico' }
            else { $icon = $exe }
        }
        New-Shortcut $deskLnk $exe $icon $dest "Ghosted -- sovereign stealth console ($key)"
        New-Shortcut $menuLnk $exe $icon $dest "Ghosted -- sovereign stealth console ($key)"
        Write-Host "[$key] installed. Shortcut: $deskLnk"
    }
    return $true
}

# -- Main ---------------------------------------------------------------------
$sys = Get-SystemReport
if ($DetectOnly) { $sys | ConvertTo-Json -Depth 4; exit 0 }

if ($Uninstall) {
    foreach ($key in @("Full", "Lean")) {
        $v = $VARIANTS[$key]
        $dest = if ($InstallRoot) { Join-Path $InstallRoot $v.dest } else { Join-Path $sys.perUserRoot $v.dest }
        foreach ($lnk in @((Join-Path ([Environment]::GetFolderPath('Desktop')) ($v.label + ".lnk")), (Join-Path ([Environment]::GetFolderPath('Programs')) ($v.label + ".lnk")))) {
            if (Test-Path $lnk) { if ($PSCmdlet.ShouldProcess($lnk, "remove shortcut")) { Remove-Item $lnk -Force } }
        }
        if (Test-Path $dest) { if ($PSCmdlet.ShouldProcess($dest, "remove install")) { Remove-Item $dest -Recurse -Force } }
    }
    Write-Host "Uninstalled all Ghosted variants + shortcuts."; exit 0
}

if (-not $sys.isWindows) {
    Write-Error "The bundled $Exe is a Windows executable; this host is not Windows. Run from source: PYTHONPATH=src python -m ghosted.console"
    exit 2
}

Write-Host "Ghosted installer -- host: $($sys.os) [$($sys.arch)]  admin=$($sys.admin)  freeGB=$($sys.freeGB)"
Write-Host "Installing variants: $($wanted -join ', ')  (per-user: $($sys.perUserRoot))"
$installed = 0
foreach ($key in $wanted) { if (Install-Variant $key $sys) { $installed++ } }

if ($installed -eq 0) {
    Write-Error "No variants installed -- no bundles found next to this script or in dist\. Place Ghosted-FULL / Ghosted-LEAN beside this installer, or run with -Build."
    exit 4
}
Write-Host "Done -- $installed variant(s) installed."
if ($sys.appControl -in @("enforced", "evaluation")) {
    Write-Warning "Smart App Control / WDAC is '$($sys.appControl)' -- it may block the unsigned Ghosted.exe on first launch. Choose 'More info -> Run anyway', sign the bundle, or run from source."
}
