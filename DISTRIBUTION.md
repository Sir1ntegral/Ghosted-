# Distributing Ghosted

Ghosted ships as one signed installer on GitHub Releases; these are the download channels.

## 1) Landing page (live)

A download front door on GitHub Pages: **https://sir1ntegral.github.io/Ghosted-/**
(served from `docs/`). The Download button points at
`releases/latest/download/Ghosted-Setup.exe`, so it always tracks the newest release.

## 2) Scoop

Manifest: [`scoop/ghosted.json`](scoop/ghosted.json). Users can install it directly:

```powershell
scoop install https://raw.githubusercontent.com/Sir1ntegral/Ghosted-/main/scoop/ghosted.json
```

Or, for `scoop update` support, host a bucket (a repo named e.g. `scoop-ghosted` with the
manifest in `bucket/ghosted.json`) and `scoop bucket add ghosted <url>`. The manifest uses
`innosetup: true` (silent per-user install), `shortcuts`, and `checkver`/`autoupdate` so
Scoop detects new GitHub releases automatically.

## 3) winget (Windows Package Manager)

Manifest (v1.6, 3 files) in [`winget/`](winget/), package id **`Sir1ntegral.Ghosted`**.
To publish so users can `winget install Sir1ntegral.Ghosted`:

1. Fork **microsoft/winget-pkgs**.
2. Copy the three YAMLs to `manifests/s/Sir1ntegral/Ghosted/0.1.0/`.
3. Validate: `winget validate --manifest <folder>` and (optional) `winget install --manifest <folder>`.
4. Open a PR — the winget bot runs automated validation (installs the package in a sandbox,
   scans it). **Note:** a new-publisher / dev-cert installer can draw a SmartScreen or
   reputation flag during validation; this is cleaner once Azure Trusted Signing lands
   (see SIGNING.md). Bump `PackageVersion` + `InstallerSha256` for each new release.

## 4) Microsoft Store (deferred)

Best reach + trust, biggest effort — and it needs money + review, so it's parked until the
same funding as the signing cert:

- A **Partner Center developer account** (~$19 one-time).
- Repackage the app as **MSIX** (the current build is a PyInstaller onedir + Inno Setup exe;
  Store requires MSIX). Options: wrap with the MSIX Packaging Tool, or build an MSIX target.
- Store **certification review** before it goes live.

When funded, the sequence is: dev account → MSIX package (signed by the Store or your cert)
→ submit → pass certification. I can prep the MSIX packaging when you're ready.

---

Every channel points at the same GitHub release asset, so there's one source of truth:
build → sign → release → (landing page / Scoop / winget / Store) all follow.
