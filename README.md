# Ghosted 🐰

A **sovereign** application built on the Rabbit mind: a stealth console, a Google-like
search homepage, and a meaning-aware semantic search — all running on Rabbit's own
organs (no Google APIs, no third-party browser engine, no Tailscale).

## Faces

| Module | What it is |
|---|---|
| `ghosted.console` | Ghost stealth console — `recon`, `cloak`/`uncloak` (stego), `forge`, `network` (WireGuard PackMesh), `encrypt`/`decrypt` (RABBIT-CIPHER-1), `browse`. |
| `ghosted.homepage` | Sovereign Google-like search homepage. Stdlib `http.server`, **Gojo-gated** (throttle + policy + audit), binds `0.0.0.0`, shows LAN / WireGuard / **egress** IPs. |
| `ghosted.semantic_search` | Re-ranks web results by **meaning, context, sentiment** and the reasoning **Dominance Engine's** read of query **intent**. |

## How it browses (no third-party browser)

Every fetch rides Rabbit's own sovereign HTTP (`rabbit.core.sovereign_downloader`):
**5+ engine TLS masks** (chrome142/136, firefox144/135, edge101, safari184, tor145)
via `curl_cffi` real-JA3 with **header↔TLS coherence**, **Tor by default** (clearnet
fallback so it's never blocked), ghost rotating headers, EDR-scanned + Madara-enrolled.

## Dependency: the Rabbit mind

This app imports the `rabbit` package (the mind). Make it importable:

```powershell
$env:PYTHONPATH = "C:\path\to\RabbitProject-clean"
```

Optional extras: `pip install .[ocr]` (RABBIT-OCR-1 / RapidOCR), `.[build]` (PyInstaller).

## Run

```powershell
$env:PYTHONPATH = "C:\path\to\RabbitProject-clean"
python -m ghosted.console        # stealth console
python -m ghosted.homepage       # http://127.0.0.1:7654
```

## Build the exe

```powershell
./build.ps1            # produces dist/RabbitGhost/ (onedir, ghost-rabbit icon)
```

## Security note

Ghost is **dual-use** security tooling intended for the operator's own devices,
research, and defensive use. Run standalone it is outside Rabbit's Madara/Watchtower
envelope; the homepage/API are Gojo-gated and fail-closed to localhost.
