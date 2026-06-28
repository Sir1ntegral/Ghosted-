<#
.SYNOPSIS
  Self-adapting installer for RabbitGhost — no external installer tooling required
  (no Inno Setup). It TESTS the system it is stored on and ADAPTS:

    * OS / architecture            -> verifies a Windows x64 host for the bundled .exe
    * the drive the repo lives on  -> picks an install root with enough free space
    * privileges                   -> per-user install by default (no admin needed);
                                      uses Program Files only when admin + requested
    * existing build               -> installs dist\RabbitGhost if present; otherwise
                                      builds it (when Python + PyInstaller are available)

  Then it copies the onedir bundle to the chosen location and creates a Desktop
  shortcut + Start-Menu shortcut with the ghost-rabbit icon.

.EXAMPLE
  .\Install-RabbitGhost.ps1                 # detect, adapt, install, make desktop icon
  .\Install-RabbitGhost.ps1 -DetectOnly     # print a JSON system report and exit (smoke)
  .\Install-RabbitGhost.ps1 -WhatIf         # show the plan without changing anything
  .\Install-RabbitGhost.ps1 -Build -Lean    # force a fresh lean build, then install
  .\Install-RabbitGhost.ps1 -Uninstall      # remove the install + shortcuts
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$InstallRoot,
    [string]$RabbitHome,
    [switch]$Lean,
    [switch]$Build,
    [switch]$DetectOnly,
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$AppName = "RabbitGhost"
$Exe = "$AppName.exe"
$repo = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

# ── System detection — "test what system it is stored on" ────────────────────
function Get-SystemReport {
    $isWin = $true
    if ($null -ne $IsWindows) { $isWin = $IsWindows }  # $IsWindows exists on PS7+
    $admin = $false
    if ($isWin) {
        try {
            $admin = ([Security.Principal.WindowsPrincipal]`
                [Security.Principal.WindowsIdentity]::GetCurrent()`
                ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
        } catch { $admin = $false }
    }
    $py = (Get-Command python -ErrorAction SilentlyContinue)
    $hasPyInstaller = $false
    if ($py) {
        try { python -c "import PyInstaller" 2>$null; $hasPyInstaller = ($LASTEXITCODE -eq 0) } catch {}
    }
    $repoDrive = (Split-Path -Qualifier $repo)
    $localApp = $env:LOCALAPPDATA
    if (-not $localApp) { $localApp = Join-Path $HOME "AppData\Local" }
    $perUserRoot = Join-Path $localApp "Programs"
    $freeGB = $null
    try {
        $q = if ($repoDrive) { $repoDrive.TrimEnd(':') } else { 'C' }
        $freeGB = [math]::Round((Get-PSDrive $q).Free / 1GB, 1)
    } catch {}
    [ordered]@{
        appName        = $AppName
        os             = if ($isWin) { (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption } else { [Environment]::OSVersion.Platform.ToString() }
        osVersion      = [Environment]::OSVersion.Version.ToString()
        isWindows      = $isWin
        arch           = $env:PROCESSOR_ARCHITECTURE
        admin          = $admin
        repo           = $repo
        repoDrive      = $repoDrive
        freeGB         = $freeGB
        python         = if ($py) { $py.Source } else { $null }
        hasPyInstaller = $hasPyInstaller
        builtBundle    = (Join-Path $repo "dist\$AppName\$Exe")
        builtExists    = (Test-Path (Join-Path $repo "dist\$AppName\$Exe"))
        icon           = (Join-Path $repo "assets\ghost_rabbit.ico")
        iconExists     = (Test-Path (Join-Path $repo "assets\ghost_rabbit.ico"))
        perUserRoot    = $perUserRoot
        systemRoot     = (Join-Path $env:ProgramFiles $AppName)
    }
}

# ── Adapt: choose where to install based on the detected system ──────────────
function Resolve-InstallRoot([hashtable]$sys) {
    if ($InstallRoot) { return $InstallRoot }
    # Admin + at least 1 GB free -> system-wide Program Files; else per-user (no admin).
    if ($sys.admin -and ($null -eq $sys.freeGB -or $sys.freeGB -ge 1)) {
        return $sys.systemRoot
    }
    return (Join-Path $sys.perUserRoot $AppName)
}

function New-Shortcut([string]$lnkPath, [string]$target, [string]$icon, [string]$workdir) {
    $dir = Split-Path -Parent $lnkPath
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force $dir | Out-Null }
    $sh = New-Object -ComObject WScript.Shell
    $sc = $sh.CreateShortcut($lnkPath)
    $sc.TargetPath = $target
    $sc.WorkingDirectory = $workdir
    if ($icon -and (Test-Path $icon)) { $sc.IconLocation = $icon }
    $sc.Description = "RabbitGhost — sovereign stealth console"
    $sc.Save()
}

# ── Main ─────────────────────────────────────────────────────────────────────
$sys = Get-SystemReport

if ($DetectOnly) {
    $sys | ConvertTo-Json -Depth 4
    exit 0
}

$dest = Resolve-InstallRoot $sys
$desktopLnk = Join-Path ([Environment]::GetFolderPath('Desktop')) "Rabbit Ghost.lnk"
$startMenu = Join-Path ([Environment]::GetFolderPath('Programs')) "Rabbit Ghost.lnk"
$installedExe = Join-Path $dest $Exe
$installedIcon = Join-Path $dest "ghost_rabbit.ico"

if ($Uninstall) {
    Write-Host "Uninstalling $AppName from $dest ..."
    if ($PSCmdlet.ShouldProcess($dest, "Remove install + shortcuts")) {
        foreach ($p in @($desktopLnk, $startMenu)) { if (Test-Path $p) { Remove-Item $p -Force } }
        if (Test-Path $dest) { Remove-Item $dest -Recurse -Force }
        Write-Host "Removed."
    }
    exit 0
}

if (-not $sys.isWindows) {
    Write-Error "The bundled $Exe is a Windows executable; this host is not Windows. " +
    "Run from source instead: PYTHONPATH=src python -m rabbitghost.console"
    exit 2
}

# Ensure a built bundle exists; build if asked or missing (and tooling is present).
if ($Build -or -not $sys.builtExists) {
    if (-not $sys.python -or -not $sys.hasPyInstaller) {
        Write-Error "No built bundle at $($sys.builtBundle) and cannot build " +
        "(python=$($sys.python), pyinstaller=$($sys.hasPyInstaller)). " +
        "Install Python + 'pip install pyinstaller', or run build.ps1 on a build box."
        exit 3
    }
    $buildArgs = @{}
    if ($Lean) { $buildArgs['Lean'] = $true }
    if ($RabbitHome) { $buildArgs['RabbitHome'] = $RabbitHome }
    Write-Host "Building $AppName ($(if ($Lean) { 'lean' } else { 'full' })) ..."
    if ($PSCmdlet.ShouldProcess("$repo\build.ps1", "Run PyInstaller build")) {
        & (Join-Path $repo "build.ps1") @buildArgs
    }
}

$srcBundle = Join-Path $repo "dist\$AppName"
if (-not (Test-Path (Join-Path $srcBundle $Exe))) {
    Write-Error "Build bundle not found at $srcBundle\$Exe — nothing to install."
    exit 4
}

Write-Host "Installing $AppName -> $dest"
Write-Host "  host: $($sys.os) [$($sys.arch)]  admin=$($sys.admin)  freeGB=$($sys.freeGB)"
if ($PSCmdlet.ShouldProcess($dest, "Copy bundle + create shortcuts")) {
    if (Test-Path $dest) { Remove-Item $dest -Recurse -Force }
    New-Item -ItemType Directory -Force $dest | Out-Null
    Copy-Item (Join-Path $srcBundle '*') $dest -Recurse -Force
    if ($sys.iconExists) { Copy-Item $sys.icon $installedIcon -Force }
    New-Shortcut $desktopLnk $installedExe $installedIcon $dest
    New-Shortcut $startMenu $installedExe $installedIcon $dest
    Write-Host "Installed. Desktop icon: $desktopLnk"
    Write-Host "Launch: `"$installedExe`""
}
