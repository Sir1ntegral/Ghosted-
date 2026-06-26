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

import getpass
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
          login             unlock / set the master password (vault + mesh)
          network           build a WireGuard mesh, sealed in the vault (login first)
          encrypt <text>    seal text with RABBIT-CIPHER-1 (passphrase)
          decrypt           open a sealed blob (paste token + passphrase)
          parse <path|text> extract text/structure (pdf/docx/html/csv/json/img via OCR)
          contacts          list saved contacts
          filters           list mail filter rules
          mailsearch <q>    search your black-box mail (needs passphrase)
          spool             store-and-forward outbox: pending count + online status
          identity [add|rm <email>]  use your own email (any kind, no IMAP/POP); @sovereign.dmn first
          status            posture
          quit              stand down (drops all ghost components for GC)
        """
    ).strip()
    print(actions)
    session = {"pw": None}  # app-login state: holds the unlocked master password
    while True:
        try:
            raw = input("ghost> ").strip()
        except (EOFError, KeyboardInterrupt):
            raw = "quit"
        if not raw:
            continue
        cmd, _, rest = raw.partition(" ")
        try:
            if not handle_command(cmd.lower(), rest, g, session):
                break
        except Exception as e:  # console must never die on one bad op
            print(f"[error] {type(e).__name__}: {e}")


def handle_command(cmd, rest, g, session, *, ask=input, getpw=getpass.getpass, out=print) -> bool:
    """Execute one console command. Returns False to quit, True to continue.

    I/O is injectable (ask / getpw / out) so every command is unit-testable
    without a real terminal — this is the seam that makes the console SoC-clean."""
    if cmd == "quit":
        out(g.exit())
        return False
    elif cmd == "status":
        out({"active": g.is_active})
    elif cmd == "recon":
        out(g.recon(rest))
    elif cmd == "forge":
        out(g.forge(rest, rest + ".forged"))
    elif cmd == "browse":
        out(_browser().web_search(rest))
    elif cmd == "login":
        from rabbitghost import vault
        pw = getpw("master password: ")
        if not vault.is_initialized():
            confirm = getpw("set new master password (confirm): ")
            if pw != confirm:
                out({"vault": "passwords do not match"})
                return True
            vault.initialize(pw)
            session["pw"] = pw
            out({"vault": "initialized + unlocked"})
        elif vault.login(pw):
            session["pw"] = pw
            out({"vault": "unlocked"})
        else:
            out({"vault": "wrong password"})
    elif cmd == "network":
        from rabbitghost import vault
        if not session.get("pw"):
            out("locked — run 'login' first")
            return True
        hub = ask("hub device name (blank = full mesh): ").strip()
        devices = []
        out("add devices (blank name to finish).")
        while True:
            nm = ask("  device name: ").strip()
            if not nm:
                break
            ep = ask(f"  {nm} public endpoint host:port (blank if NAT): ").strip()
            devices.append((nm, ep))
        out({"mesh_sealed_in_vault": vault.build_and_seal_mesh(devices, session["pw"], hub=hub or "")})
    elif cmd == "encrypt":
        import base64
        from rabbit.core.crypto import encrypt
        blob = encrypt(rest, getpw("passphrase: ").strip())
        out({"sealed": base64.b64encode(blob.to_bytes()).decode()})
    elif cmd == "decrypt":
        import base64
        from rabbit.core.crypto import EncryptedBlob, decrypt
        tok = ask("sealed token: ").strip()
        pw = getpw("passphrase: ").strip()
        out({"opened": decrypt(EncryptedBlob.from_bytes(base64.b64decode(tok)), pw)})
    elif cmd in ("cloak", "uncloak"):
        from rabbit.security.ghost.ghost_cloak import GhostCloak
        if cmd == "cloak":
            img, _, msg = rest.partition(" ")
            pw = getpw("passphrase: ").strip() or None
            out_path = img + ".cloaked.png"
            GhostCloak(passphrase=pw).cloak_payload(img, msg.encode(), out_path)
            out({"cloaked": out_path})
        else:
            pw = getpw("passphrase: ").strip() or None
            out({"hidden": GhostCloak(passphrase=pw).extract_payload(rest)})
    elif cmd == "spool":
        from rabbitghost import transport
        sp = transport.Spool()
        out({"pending": len(sp), "online": transport.online()})
    elif cmd == "identity":
        from rabbitghost import mail
        sub, _, arg = rest.partition(" ")
        if sub == "add":
            out({"added": mail.add_identity(arg)})
        elif sub == "rm":
            out({"removed": mail.remove_identity(arg)})
        else:
            out({"suggested": mail.address("me"), "identities": mail.identities(),
                 "note": "no IMAP / no POP — identities only; @sovereign.dmn suggested first"})
    elif cmd == "contacts":
        from rabbitghost import contacts
        out({"contacts": contacts.contacts()})
    elif cmd == "filters":
        from rabbitghost import mail_filters
        out({"filters": mail_filters.filters()})
    elif cmd == "mailsearch":
        from rabbitghost import mail
        hits = mail.search(rest, getpw("passphrase: "))
        out({"hits": len(hits), "subjects": [h.get("subject") for h in hits[:10]]})
    elif cmd == "parse":
        from rabbitghost import parser
        res = parser.parse(rest, max_chars=2000)
        info = {"type": res.get("type"), "chars": len(res.get("text") or ""),
                "preview": (res.get("text") or "")[:160]}
        if "error" in res:
            info["error"] = res["error"]
        out(info)
    else:
        out(f"unknown: {cmd}")
    return True


if __name__ == "__main__":
    menu()
    sys.exit(0)
