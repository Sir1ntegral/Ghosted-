# Ghosted 🐰

[![Buy Me a Coffee](https://img.shields.io/badge/Buy_Me_a_Coffee-Sir1ntegral-FFDD00?logo=buymeacoffee&logoColor=black)](https://buymeacoffee.com/Sir1ntegral)

A **sovereign, standalone** privacy tool for Windows: a stealth console, a Google-like
search **homepage**, private **email**, a **WireGuard** device mesh, and meaning-aware
semantic search — all on Ghosted's **own** engines. No Google APIs, no third-party
browser engine, no cloud, and **no dependency on any other project**. It carries its
own crypto, its own masked HTTP + **bundled Tor**, its own EDR-lite, and its own
boundary (Gojo).

## Install (Windows)

**Download page → https://sir1ntegral.github.io/Ghosted-/** — or grab the installer
straight from the [**latest release**](../../releases/latest) and run it. It installs
per-user (no admin), creates a desktop icon, and launches — your **search homepage opens
in your browser** automatically.

| Method | Command / link |
|---|---|
| **Installer** | [Download `Ghosted-Setup.exe`](../../releases/latest/download/Ghosted-Setup.exe) |
| **Scoop** | `scoop install https://raw.githubusercontent.com/Sir1ntegral/Ghosted-/main/scoop/ghosted.json` |

- Everything the browser needs is in the package, including its **own Tor** — anonymized
  browsing works out of the box, with a clearnet fallback so it's never blocked.

### Trust the developer (optional)

Ghosted is signed by the developer's own certificate, so Windows shows "unknown
publisher" (**More info → Run anyway** works fine). If you'd rather have the signature
validate as trusted and skip that prompt, you can **opt in to trust the developer** — no
admin needed, and it's reversible:

```powershell
# from the release (Ghosted-Developer.cer + the script are attached), or the repo's trust/ folder
.\Trust-Ghosted-Developer.ps1        # prompts you to confirm; -Remove to undo
```

Only do this if you choose to trust the Ghosted developer. See
[trust/](trust/) and [DISTRIBUTION.md](DISTRIBUTION.md).

## Support

Ghosted is built in the open by one developer — no cloud, no ads, no Big Tech. If it's
useful to you, you can help keep it independent and shipping:

**☕ [Buy me a coffee](https://buymeacoffee.com/Sir1ntegral)** — or hit the **Sponsor**
button at the top of this repo. Backers are listed in [SUPPORTERS.md](SUPPORTERS.md).

## What it does

| Face | What it is |
|---|---|
| **Homepage** (`:7654`) | Google-like search + your account: private email, WireGuard, health, all Gojo-gated. Opens in your browser. |
| **Console** | `browse`, `recon`, `cloak`/`uncloak` (stego), `forge`, `encrypt`/`decrypt` (GHOSTED-CIPHER-1), `wg` (WireGuard), `tor`, `scan` (EDR), `update`, `defense`. |
| **Email** | Send/receive real email (SMTP/IMAP/POP), sealed at rest under your master password. |
| **WireGuard** | Enroll your devices into a sovereign mesh, connect real tunnels, all sealed in your vault. |

## Privacy model

Every fetch rides Ghosted's own masked HTTP: real-browser **TLS/JA3 masks** via
`curl_cffi`, **Tor by default** for sensitive egress (bundled tor.exe, auto-started),
clearnet fallback so it never hard-fails. Getting a link never costs anonymity. The
homepage/account are **Gojo-gated** (role + source-class policy + throttle + audit) and
fail closed — only the local operator drives sensitive actions. Ghosted's own EDR-lite
scans anything it downloads, protecting the app's own integrity.

## Security & scope

Ghosted is dual-use security tooling intended for the operator's **own** devices,
research, and defensive use. It protects **itself** (integrity, functionality,
reputation) — it is not a host antivirus.

## Run from source (developers)

Requires Python 3.11+.

```powershell
git clone https://github.com/Sir1ntegral/Ghosted-.git
cd Ghosted-
pip install -e .            # base: curl_cffi, beautifulsoup4, Pillow
ghosted                     # stealth console (auto-opens the homepage)
ghosted-home                # just the homepage -> http://127.0.0.1:7654
```

Optional extras: `.[semantic]` (numpy meaning-ranking), `.[ocr]`, `.[docs]`,
`.[build]` (PyInstaller).

## Build the installer

```powershell
./build.ps1                 # onedir bundle -> dist/Ghosted/ (bundles Tor if present)
# then compile installer.iss with Inno Setup -> installer_out/Ghosted-Setup.exe
```

Code signing and the auto-updater are documented in [SIGNING.md](SIGNING.md).
