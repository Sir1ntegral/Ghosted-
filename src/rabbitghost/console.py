#!/usr/bin/env python
"""
Rabbit Ghost — standalone stealth console.

Separated from the live Rabbit runtime per Lucy's authorization, this bundles
the FULL ghost stack (recon / cloak-stego / forge / traffic / dissect) together
with the SovereignBrowserEngine (Google/Bing/YouTube/Tor) into one app.

Governance note: run standalone, Ghost is OUTSIDE Rabbit's Madara/Watchtower
envelope. This console keeps the voice-auth-as-Lucy intent by being launched
only from Lucy's own desktop icon. Defensive/research use on Lucy's own device.
"""
from __future__ import annotations

import sys
import textwrap

# Frozen-console fix: force UTF-8 on stdout/stderr so the banner em-dashes and any
# Rabbit Unicode render correctly instead of as cp1252 replacement chars (the glitch).
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

BANNER = r"""
   ____ _               _      ____  _   _  ___  ____ _____
  |  _ \ |__   ___  ___| |_   / ___|| | | |/ _ \/ ___|_   _|
  | |_) | '_ \ / _ \/ __| __| | |  _| |_| | | | \___ \ | |
  |  _ <| |_) |  __/ (__| |_  | |_| |  _  | |_| |___) || |
  |_| \_\_.__/ \___|\___|\__|  \____|_| |_|\___/|____/ |_|
        sovereign stealth console — ghost + browser
"""


def _ghost():
    from rabbit.security.ghost.ghost_mode import GhostMode
    return GhostMode()


def _browser():
    from rabbit.research.sovereign_browser_engine import SovereignBrowserEngine
    return SovereignBrowserEngine()


def menu() -> None:
    print(BANNER)
    g = _ghost()
    print(g.enter())
    actions = textwrap.dedent(
        """
        commands:
          recon <topic>     stealth-investigate (uses browser engine)
          cloak <img> <msg> hide encrypted message inside an image (stego)
          uncloak <img>     extract hidden message from an image
          forge <path>      produce a unique, equivalent artifact
          browse <query>    sovereign web search (Google/Bing/YT/Tor)
          network           build a sovereign WireGuard pack-mesh (interactive)
          encrypt <text>    seal text with RABBIT-CIPHER-1 (passphrase)
          decrypt           open a sealed blob (paste token + passphrase)
          status            posture
          quit              stand down (drops all ghost components for GC)
        """
    ).strip()
    print(actions)
    while True:
        try:
            raw = input("ghost> ").strip()
        except (EOFError, KeyboardInterrupt):
            raw = "quit"
        if not raw:
            continue
        cmd, _, rest = raw.partition(" ")
        cmd = cmd.lower()
        try:
            if cmd == "quit":
                print(g.exit())
                break
            elif cmd == "status":
                print({"active": g.is_active})
            elif cmd == "recon":
                print(g.recon(rest))
            elif cmd == "forge":
                out = rest + ".forged"
                print(g.forge(rest, out))
            elif cmd == "browse":
                b = _browser()
                print(b.web_search(rest))
            elif cmd == "network":
                from rabbit.network.sovereign_wireguard import PackMesh
                hub = input("hub device name (blank = full mesh): ").strip()
                mesh = PackMesh(hub=hub or "")
                print("add devices (blank name to finish).")
                while True:
                    nm = input("  device name: ").strip()
                    if not nm:
                        break
                    ep = input(f"  {nm} public endpoint host:port (blank if NAT): ").strip()
                    mesh.add_device(nm, endpoint=ep)
                paths = mesh.write()
                print({"mesh_built": {k: str(v) for k, v in paths.items()}})
            elif cmd == "encrypt":
                import base64
                from rabbit.core.crypto import encrypt
                pw = input("passphrase: ").strip()
                blob = encrypt(rest, pw)
                tok = base64.b64encode(blob.to_bytes()).decode()
                print({"sealed": tok})
            elif cmd == "decrypt":
                import base64
                from rabbit.core.crypto import decrypt, EncryptedBlob
                tok = input("sealed token: ").strip()
                pw = input("passphrase: ").strip()
                blob = EncryptedBlob.from_bytes(base64.b64decode(tok))
                print({"opened": decrypt(blob, pw)})
            elif cmd in ("cloak", "uncloak"):
                from rabbit.security.ghost.ghost_cloak import GhostCloak
                if cmd == "cloak":
                    img, _, msg = rest.partition(" ")
                    pw = input("passphrase: ").strip() or None
                    out = img + ".cloaked.png"
                    GhostCloak(passphrase=pw).cloak_payload(img, msg.encode(), out)
                    print({"cloaked": out})
                else:
                    pw = input("passphrase: ").strip() or None
                    raw_out = GhostCloak(passphrase=pw).extract_payload(rest)
                    print({"hidden": raw_out})
            else:
                print(f"unknown: {cmd}")
        except Exception as e:  # console must never die on one bad op
            print(f"[error] {type(e).__name__}: {e}")


if __name__ == "__main__":
    menu()
    sys.exit(0)
