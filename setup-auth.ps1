# RabbitGhost — GitHub Auth + Push Wizard
# ---------------------------------------------------------------------------
# Run it yourself (interactive):
#   ! powershell -ExecutionPolicy Bypass -File "C:\Users\Admin\Desktop\RabbitGhost\setup-auth.ps1"
# Handles: login (browser OR token), account creation, repo create + push.
# ---------------------------------------------------------------------------
$ErrorActionPreference = "Stop"
$gh = "C:\Program Files\GitHub CLI\gh.exe"
if (-not (Test-Path $gh)) { $gh = (Get-Command gh -ErrorAction SilentlyContinue).Source }
if (-not $gh) { Write-Host "GitHub CLI not found. Install: winget install GitHub.cli" -ForegroundColor Red; exit 1 }
$repo = $PSScriptRoot
Set-Location $repo

function Test-Authed { & $gh auth status *> $null; return ($LASTEXITCODE -eq 0) }

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  RabbitGhost - GitHub Setup Wizard" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

if (Test-Authed) {
    $who = & $gh api user --jq .login 2>$null
    Write-Host "[*] Already authenticated as: $who" -ForegroundColor Green
}
else {
    Write-Host ""
    Write-Host "Not logged in. How would you like to authenticate?"
    Write-Host "  [1] Log in with a browser    (recommended)"
    Write-Host "  [2] Paste a Personal Access Token (repo scope)"
    Write-Host "  [3] I don't have a GitHub account yet  (open sign-up)"
    Write-Host ""
    $choice = Read-Host "Select 1 / 2 / 3"
    switch ($choice) {
        '1' {
            Write-Host "[*] Launching browser login..." -ForegroundColor Yellow
            & $gh auth login --hostname github.com --git-protocol https --web
        }
        '2' {
            $sec = Read-Host "Paste your PAT" -AsSecureString
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
            $tok = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
            $tok | & $gh auth login --hostname github.com --git-protocol https --with-token
        }
        '3' {
            Write-Host "[*] Opening GitHub sign-up in your browser..." -ForegroundColor Yellow
            Start-Process "https://github.com/signup"
            Write-Host "    Create your account (email + verify), then re-run this wizard." -ForegroundColor Yellow
            exit 0
        }
        default { Write-Host "Invalid choice." -ForegroundColor Red; exit 1 }
    }
}

if (-not (Test-Authed)) {
    Write-Host "[!] Authentication did not complete. Re-run the wizard." -ForegroundColor Red
    exit 1
}

$me = & $gh api user --jq .login 2>$null
Write-Host ""
Write-Host "[*] Authenticated as $me. Publishing repo (private)..." -ForegroundColor Green

# already pushed? (remote exists + reachable)
& $gh repo view "$me/RabbitGhost" *> $null
if ($LASTEXITCODE -eq 0) {
    Write-Host "[*] Repo exists - pushing main..." -ForegroundColor Yellow
    if (-not (git remote 2>$null | Select-String -Quiet origin)) {
        git remote add origin "https://github.com/$me/RabbitGhost.git"
    }
    git push -u origin main
}
else {
    & $gh repo create RabbitGhost --private --source=. --remote=origin --push
}

Write-Host ""
Write-Host "[OK] Done -> https://github.com/$me/RabbitGhost" -ForegroundColor Green
