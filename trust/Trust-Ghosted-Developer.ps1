<#
  Trust-Ghosted-Developer.ps1  —  OPT-IN developer trust for Ghosted.

  Ghosted is signed by an independent developer's own certificate. Windows doesn't
  know that certificate yet, so it shows "unknown publisher". Running this once tells
  Windows — for YOUR user account only — to trust code signed by the Ghosted developer.
  Afterward the signature validates (Get-AuthenticodeSignature -> Valid) and the app
  runs without the unknown-publisher prompt.

  Only run this if you choose to trust the Ghosted developer. It is reversible.

  Usage:
    .\Trust-Ghosted-Developer.ps1            # prompts for confirmation
    .\Trust-Ghosted-Developer.ps1 -Yes       # trust without prompting
    .\Trust-Ghosted-Developer.ps1 -Remove    # undo (untrust)
#>
[CmdletBinding()]
param([switch]$Yes, [switch]$Remove)

$ErrorActionPreference = 'Stop'
$cer = Join-Path $PSScriptRoot 'Ghosted-Developer.cer'
$expected = 'B95499709AFC59167C0CC6172BA39C64CC0AE17A'   # Ghosted developer cert thumbprint

if (-not (Test-Path $cer)) { throw "Ghosted-Developer.cer not found next to this script." }
$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cer)
if ($cert.Thumbprint -ne $expected) {
    throw "Certificate thumbprint mismatch (got $($cert.Thumbprint)) — refusing to proceed."
}

function Set-Store([string]$name, [switch]$add) {
    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new($name, 'CurrentUser')
    $store.Open('ReadWrite')
    if ($add) { $store.Add($cert) } else { $store.Remove($cert) }
    $store.Close()
}

if ($Remove) {
    foreach ($s in 'TrustedPublisher', 'Root') { try { Set-Store $s } catch {} }
    Write-Host "Removed trust for the Ghosted developer certificate (your account)."
    return
}

Write-Host "You are about to TRUST the Ghosted developer certificate for your user account:"
Write-Host "  Subject:    $($cert.Subject)"
Write-Host "  Thumbprint: $($cert.Thumbprint)"
Write-Host "  Valid to:   $($cert.NotAfter)"
Write-Host ""
Write-Host "Windows will then accept code signed by this developer. Trust only if you want to."
if (-not $Yes) {
    $ans = Read-Host "Trust the Ghosted developer? [y/N]"
    if ($ans -notin @('y', 'Y', 'yes')) { Write-Host "Cancelled — nothing changed."; return }
}
foreach ($s in 'TrustedPublisher', 'Root') { Set-Store $s -add }
Write-Host "Done. Ghosted's signature now validates as trusted on this account."
Write-Host "Undo any time with:  .\Trust-Ghosted-Developer.ps1 -Remove"
