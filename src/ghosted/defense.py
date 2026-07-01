"""
Ghosted — the defense facade. One boot() that brings up Ghosted's whole self-defense
so every Ghosted desktop application (the console, the homepage/browser, and any future
app that installs Ghosted) ships the SAME protection from a single call.

What it protects: GHOSTED ITSELF — the app's integrity, functionality, and reputation.
It is NOT a host antivirus and does not police the user's machine; where it touches the
machine at all, it does so only to keep the app and its data sound (e.g. the EDR-lite
scans files Ghosted itself fetches/opens, not the whole disk).

The pillars, unified here:
  • Gojo boundary + security workflow (ghosted.gate + ghosted.security) — gates and
    audits every sensitive action.
  • Encryption (ghosted.crypto, GHOSTED-CIPHER-1) — seals Ghosted's data at rest.
  • EDR-lite (ghosted.scan) — heuristic file-safety check + inert quarantine for
    anything Ghosted handles.
  • Security event bus (ghosted.event_bus) — one audited chain every pillar announces on.

Decoupled from rabbit. boot() is idempotent and fail-soft: a missing optional pillar
degrades the posture but never stops the app from starting.
"""

from __future__ import annotations

import threading

from ghosted import event_bus

__all__ = ["boot", "status", "guard", "scan_file", "encrypt", "decrypt", "announce", "is_booted"]

_BOOTED = False
_BOOT_LOCK = threading.Lock()


# ── facade re-exports (so an app imports ONE module for its defense) ────────────
def guard(**kwargs):
    """Gate a sensitive action through Gojo + announce it. See ghosted.security.guard."""
    from ghosted import security

    return security.guard(**kwargs)


def scan_file(path: str, quarantine: bool = False):
    """EDR-lite safety check on a file Ghosted handles (heuristics + inert quarantine)."""
    from ghosted import scan

    return scan.scan_file(path, quarantine=quarantine)


def encrypt(text: str, passphrase: str):
    """Seal text with GHOSTED-CIPHER-1. Returns an EncryptedBlob."""
    from ghosted.crypto import encrypt as _e

    return _e(text, passphrase)


def decrypt(blob, passphrase: str) -> str:
    from ghosted.crypto import decrypt as _d

    return _d(blob, passphrase)


def announce(event: dict) -> dict:
    """Announce a security event on the bus."""
    return event_bus.announce(event)


# ── posture + boot ──────────────────────────────────────────────────────────────
def _pillars() -> dict:
    """Presence check for each defense pillar (protects Ghosted's own integrity)."""
    out: dict[str, str] = {}
    for name, mod, attr in (
        ("gojo", "ghosted.gate", "GojoBoundaryGate"),
        ("workflow", "ghosted.security", "guard"),
        ("encryption", "ghosted.crypto", "encrypt"),
        ("edr", "ghosted.scan", "scan_file"),
        ("event_bus", "ghosted.event_bus", "announce"),
    ):
        try:
            m = __import__(mod, fromlist=[attr])
            out[name] = "available" if hasattr(m, attr) else "degraded"
        except Exception:
            out[name] = "absent"
    return out


def status() -> dict:
    """Defense posture for the console / health / doctor. Never raises."""
    pillars = _pillars()
    try:
        from ghosted import wg_tunnel

        tunnels = wg_tunnel.active_tunnels()
    except Exception:
        tunnels = []
    ok = all(v == "available" for v in pillars.values())
    return {
        "booted": _BOOTED,
        "pillars": pillars,
        "protects": "ghosted app integrity/functionality/reputation (not the host)",
        "active_tunnels": tunnels,
        "recent_events": len(event_bus.recent(0)),
        "state": "ok" if ok else "warn",
    }


def is_booted() -> bool:
    return _BOOTED


def boot(app_name: str = "ghosted") -> dict:
    """Bring up Ghosted's self-defense for *app_name*. Idempotent + fail-soft.

    Any Ghosted desktop app calls this once at startup; afterwards it uses this module
    as its single defense entry point (guard / scan_file / encrypt / announce). Warming
    the Gojo gate + announcing a defense-online event means the protection and its audit
    trail are live before the app does anything sensitive.
    """
    global _BOOTED
    with _BOOT_LOCK:
        if _BOOTED:
            return status()
        # Warm the Gojo gate + security workflow so the first guarded action is fast.
        try:
            from ghosted import security

            security._gate()  # constructs the boundary gate + wires the audit sink
        except Exception:
            pass
        _BOOTED = True
    post = status()
    event_bus.announce({
        "component": "defense",
        "event_type": "defense_online",
        "app": app_name,
        "pillars": post["pillars"],
        "severity": "info" if post["state"] == "ok" else "warning",
    })
    return post
