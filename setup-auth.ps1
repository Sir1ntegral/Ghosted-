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
            Write-Host ""
            Write-Host "--- New account: basic info + settings ---" -ForegroundColor Cyan
            Write-Host "(GitHub requires you to finish sign-up in the browser: password," -ForegroundColor DarkGray
            Write-Host " email verification, and CAPTCHA can't be automated. I'll prep everything else.)" -ForegroundColor DarkGray
            Write-Host ""
            $fullname = Read-Host "  Your name (for git commit identity)"
            $email    = Read-Host "  Your email (for GitHub + git commits)"
            $username = Read-Host "  Desired GitHub username"
            Write-Host ""
            Write-Host "--- Settings ---" -ForegroundColor Cyan
            $vis = Read-Host "  Repo visibility for RabbitGhost [private/public] (default private)"
            if ($vis -ne 'public') { $vis = 'private' }
            Set-Content -Path (Join-Path $repo '.ghosted-setup') -Value "visibility=$vis`nusername=$username`nemail=$email" -Encoding ascii

            # Apply local git identity now (so the eventual push commits are attributed correctly)
            if ($fullname) { git config user.name  "$fullname" }
            if ($email)    { git config user.email "$email" }

            Write-Host ""
            Write-Host "[*] Opening GitHub sign-up (email pre-filled)..." -ForegroundColor Yellow
            if ($email) { Start-Process ("https://github.com/signup?user_email=" + [uri]::EscapeDataString($email)) }
            else        { Start-Process "https://github.com/signup" }
            Write-Host ""
            Write-Host "  Suggested username : $username" -ForegroundColor Green
            Write-Host "  Repo visibility    : $vis (saved)" -ForegroundColor Green
            Write-Host "  Git identity       : configured locally" -ForegroundColor Green
            Write-Host ""
            Write-Host "  1) Finish sign-up in the browser (set a password, verify email, CAPTCHA)."
            Write-Host "  2) Re-run this wizard and pick [1] browser login -> it will push automatically."
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
    $vis = "private"
    $cfgPath = Join-Path $repo '.ghosted-setup'
    if (Test-Path $cfgPath) {
        $m = Select-String -Path $cfgPath -Pattern '^visibility=(\w+)' | Select-Object -First 1
        if ($m) { $vis = $m.Matches[0].Groups[1].Value }
    }
    & $gh repo create RabbitGhost "--$vis" --source=. --remote=origin --push
}

Write-Host ""
Write-Host "[OK] Done -> https://github.com/$me/RabbitGhost" -ForegroundColor Green
