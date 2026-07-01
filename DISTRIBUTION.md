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

## 3) Trust the developer (signature, no CA)

Ghosted is signed by the developer's own certificate rather than a commercial CA, so
Windows shows "unknown publisher" (**More info → Run anyway** works). Users who choose to
trust the developer can make the signature validate — no admin, reversible:

- [`trust/Ghosted-Developer.cer`](trust/Ghosted-Developer.cer) — the developer's **public**
  cert (no private key), thumbprint `B95499709AFC59167C0CC6172BA39C64CC0AE17A`.
- [`trust/Trust-Ghosted-Developer.ps1`](trust/Trust-Ghosted-Developer.ps1) — imports it to
  the current user's Trusted Publisher + Root stores after a confirmation prompt
  (`-Yes` to skip it, `-Remove` to undo).

Both are attached to each release so downloaders have them alongside the installer. This is
an opt-in trust model for an independent developer — the machine will then accept code
signed by the Ghosted developer, so only run it if you trust them.

> The Microsoft ecosystem paths (winget, Store, Azure Trusted Signing) are intentionally
> left out — Ghosted stays self-signed + opt-in-trust rather than depending on them.

---

Every channel points at the same GitHub release asset, so there's one source of truth:
build → sign → release → (landing page / Scoop / trust) all follow.
