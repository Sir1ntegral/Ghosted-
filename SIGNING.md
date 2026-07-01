# Code signing

Ghosted signs with Authenticode when a certificate is configured. An unsigned binary
triggers SmartScreen / App Control warnings, which for a security tool reads as
untrustworthy — so signed builds matter for reputation.

## Build flow (both the app exe and the installer are signed)

```powershell
.\build.ps1            # builds dist\Ghosted and signs Ghosted.exe
.\build-installer.ps1  # compiles installer_out\Ghosted-Setup.exe and signs IT too
```

Both scripts share the signing logic in `sign.ps1` (dot-sourced), so the same certificate
config signs the app exe *and* the downloadable installer. If no certificate is
configured, both simply skip signing (unsigned output). CI (`.github/workflows/release.yml`)
signs both via the Azure Trusted Signing action.

## Configure a certificate

Set **one** of the following before building (checked in this order). `build.ps1`
locates `signtool.exe` (PATH or the Windows SDK) and signs with SHA-256 + a timestamp.

```powershell
# 1) Azure Artifact Signing (cloud EV — instant SmartScreen trust, no hardware token)
$env:GHOSTED_SIGN_AZURE_JSON = 'C:\path\to\metadata.json'
# optional: $env:GHOSTED_SIGN_AZURE_DLIB = '...\Azure.CodeSigning.Dlib.dll' (else auto-located)

# 2) a .pfx file
$env:GHOSTED_SIGN_PFX  = 'C:\path\to\cert.pfx'
$env:GHOSTED_SIGN_PASS = 'pfx-password'

# 3) a certificate already in the local store, by thumbprint
$env:GHOSTED_SIGN_THUMBPRINT = '<thumbprint>'

# optional: override the RFC3161 timestamp URL
$env:GHOSTED_SIGN_TS = 'http://timestamp.digicert.com'   # Azure default: timestamp.acs.microsoft.com
```

With none set, the build prints a skip notice and produces an **unsigned** exe.

## Azure Artifact Signing (recommended)

Azure Artifact Signing (formerly "Trusted Signing") is Microsoft's cloud code signing —
~$10/mo Basic, **no hardware token**. It establishes a **verified publisher identity**;
reputation attaches to that identity rather than a single cert.

> **SmartScreen note:** signing (Azure or an OV cert) does **not** clear the SmartScreen
> "unknown publisher" prompt instantly. For a new publisher the prompt persists until
> your identity builds download reputation — typically several weeks and hundreds of
> clean installs. This is expected; signing is what starts that reputation accruing.

One-time acquisition (Azure portal):
1. Register the `Microsoft.CodeSigning` resource provider.
2. Create a **Trusted Signing Account** (Basic SKU) in a supported region.
3. Assign yourself **Trusted Signing Identity Verifier** + **Certificate Profile Signer** roles.
4. **Identity validations → New Identity** → Individual (USA/Canada) or Organization →
   complete Verified ID / business validation until status **Completed**.
5. **Certificate profiles → Create → Public Trust** → select your identity validation.

On the build machine:
```powershell
winget install -e --id Microsoft.Azure.ArtifactSigningClientTools   # signtool dlib + deps
az login                                                            # or a service principal (Signer role)
```
Create `metadata.json` (region endpoint + your account/profile names):
```json
{
  "Endpoint": "https://wus3.codesigning.azure.net/",
  "CodeSigningAccountName": "ghostedsigning",
  "CertificateProfileName": "ghosted"
}
```
Then `$env:GHOSTED_SIGN_AZURE_JSON = '<path>\metadata.json'` and run `build.ps1` — it
signs via `signtool /dlib /dmdf` against the ACS timestamp. Verify with
`Get-AuthenticodeSignature .\dist\Ghosted\Ghosted.exe` → `Status: Valid`.

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
