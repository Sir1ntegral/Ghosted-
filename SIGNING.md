# Code signing

Ghosted's build (`build.ps1`) signs the exe with Authenticode when a certificate is
configured. An unsigned binary triggers SmartScreen / App Control warnings, which for a
security tool reads as untrustworthy — so signed builds matter for reputation.

## Configure a certificate

Set **one** of the following before building (or in your CI secrets):

```powershell
# a .pfx file
$env:GHOSTED_SIGN_PFX  = 'C:\path\to\cert.pfx'
$env:GHOSTED_SIGN_PASS = 'pfx-password'

# -- or -- a certificate already in the local store, by thumbprint
$env:GHOSTED_SIGN_THUMBPRINT = '<thumbprint>'

# optional: override the RFC3161 timestamp URL
$env:GHOSTED_SIGN_TS = 'http://timestamp.digicert.com'
```

With neither set, the build prints a skip notice and produces an **unsigned** exe (same
as before). `build.ps1` locates `signtool.exe` (PATH or the Windows SDK) and signs with
SHA-256 + a timestamp.

## Production (public downloads)

Use a certificate from a public CA — ideally an **EV code-signing** cert, which builds
SmartScreen reputation immediately. Point `GHOSTED_SIGN_PFX`/`_THUMBPRINT` at it and
rebuild; nothing else changes.

## Development / internal signing (self-signed)

For local/internal builds you can sign with a self-signed cert. It produces a *valid*
signature but an *untrusted publisher* on machines that don't trust the cert — fine for
your own machine or an org that deploys the cert. Create + trust one:

```powershell
$cert = New-SelfSignedCertificate -Type CodeSigningCert `
    -Subject 'CN=Ghosted (Sir1ntegral) DEV' -CertStoreLocation Cert:\CurrentUser\My `
    -KeyUsage DigitalSignature -KeyExportPolicy Exportable -NotAfter (Get-Date).AddYears(3)
foreach ($s in 'Root','TrustedPublisher') {
    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new($s,'CurrentUser')
    $store.Open('ReadWrite'); $store.Add($cert); $store.Close()
}
$env:GHOSTED_SIGN_THUMBPRINT = $cert.Thumbprint
```

Verify a build: `Get-AuthenticodeSignature .\dist\Ghosted\Ghosted.exe` → `Status: Valid`.

To remove a dev cert later: delete it from `Cert:\CurrentUser\My`, `\Root`, and
`\TrustedPublisher`.
