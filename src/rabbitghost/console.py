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
import os
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
    g = None
    try:
        g = _ghost()
        print(g.enter())
    except (
        Exception
    ) as e:  # boot must reach the prompt even if the stealth stack can't load
        print(
            f"[ghost] stealth stack unavailable ({type(e).__name__}: {e}).\n"
            "        Running with reduced commands — the rabbit mind isn't importable.\n"
            "        Stdlib commands (connect/spool/contacts/filters/identity/parse) still work."
        )
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
          connect           check internet across wifi/LAN/WAN (multi-interface)
          hotspot           start a WiFi hotspot for the mesh (Windows, needs admin)
          contacts          list saved contacts
          filters           list mail filter rules
          mail [sub]        black-box mail: inbox|read|compose|send <peer>|ext|pull <imap|pop>
          mailsearch <q>    search your black-box mail (needs passphrase)
          spool             store-and-forward outbox: pending count + online status
          identity [add|rm <email>]  use your own email (any kind, no IMAP/POP); @sovereign.dmn first
          status            posture
          help [command]    full help — everything the app does (or detail for one command)
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


def handle_command(
    cmd, rest, g, session, *, ask=input, getpw=getpass.getpass, out=print
) -> bool:
    """Execute one console command. Returns False to quit, True to continue.

    I/O is injectable (ask / getpw / out) so every command is unit-testable
    without a real terminal — this is the seam that makes the console SoC-clean."""
    if cmd == "quit":
        out(g.exit() if g is not None else {"bye": True})
        return False
    elif cmd == "status":
        out({"active": bool(g is not None and getattr(g, "is_active", False))})
    elif cmd == "help":
        from rabbitghost import help_text

        out(help_text.detail(rest) if rest.strip() else help_text.overview())
    elif cmd in ("recon", "forge") and g is None:
        out("ghost stealth stack unavailable (the rabbit mind isn't importable)")
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
        out(
            {
                "mesh_sealed_in_vault": vault.build_and_seal_mesh(
                    devices, session["pw"], hub=hub or ""
                )
            }
        )
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
            out(
                {
                    "suggested": mail.address("me"),
                    "identities": mail.identities(),
                    "note": "no IMAP / no POP — identities only; @sovereign.dmn suggested first",
                }
            )
    elif cmd == "connect":
        from rabbitghost import connectivity

        out(connectivity.ensure_online())
    elif cmd == "hotspot":
        from rabbitghost import connectivity

        out(connectivity.start_hotspot())
    elif cmd == "contacts":
        from rabbitghost import contacts

        out({"contacts": contacts.contacts()})
    elif cmd == "filters":
        from rabbitghost import mail_filters

        out({"filters": mail_filters.filters()})
    elif cmd == "mail":
        from rabbitghost import bridge, imap_pull, mail, mesh_mail

        sub, _, arg = rest.partition(" ")
        sub = sub.strip().lower()
        if sub in ("", "inbox", "list"):
            boxes = mail.inbox()
            out(
                {
                    "count": len(boxes),
                    "recent": [
                        f"{i}: {os.path.basename(p)}" for i, p in enumerate(boxes[-10:])
                    ],
                    "note": "mail read <index|path> (needs passphrase)",
                }
            )
        elif sub == "read":
            boxes = mail.inbox()
            a = arg.strip()
            target = boxes[int(a)] if a.isdigit() and int(a) < len(boxes) else a
            if not target:
                out("usage: mail read <index|path>")
                return True
            out(mail.read(target, getpw("passphrase: ")))
        elif sub == "compose":  # seal into the local black-box mailbox
            to = ask("to: ").strip()
            subject = ask("subject: ").strip()
            body = ask("body: ")
            out(
                {
                    "sealed_to_mailbox": mail.send(
                        to, subject, body, getpw("passphrase: ")
                    )
                }
            )
        elif (
            sub == "send"
        ):  # deliver over the WireGuard mesh to a peer (spool if offline)
            peer = arg.strip()
            if not peer:
                out("usage: mail send <peer-host>")
                return True
            to = ask("to: ").strip()
            subject = ask("subject: ").strip()
            body = ask("body: ")
            out(mesh_mail.send_to(peer, to, subject, body, getpw("passphrase: ")))
        elif sub == "ext":  # external SMTP submission — leaves the sovereign envelope
            to = ask("to: ").strip()
            subject = ask("subject: ").strip()
            body = ask("body: ")
            from_addr = ask("from (your address): ").strip()
            host = ask("smtp host: ").strip()
            port = ask("smtp port [587]: ").strip() or "587"
            user = ask("username (blank if none): ").strip() or None
            pw = getpw("smtp password (blank if none): ") or None
            out(
                bridge.send_external(
                    to,
                    subject,
                    body,
                    from_addr=from_addr,
                    smtp_host=host,
                    smtp_port=int(port),
                    username=user,
                    password=pw,
                )
            )
        elif sub == "pull":  # opt-in IMAP/POP receive → black-boxed at rest
            proto = arg.strip().lower()
            if proto not in ("imap", "pop"):
                out("usage: mail pull <imap|pop>")
                return True
            host = ask("host: ").strip()
            default_port = "993" if proto == "imap" else "995"
            port = ask(f"port [{default_port}]: ").strip() or default_port
            user = ask("username: ").strip()
            pw = getpw("account password: ")
            key = getpw("black-box passphrase (seals fetched mail at rest): ")
            fn = imap_pull.pull_imap if proto == "imap" else imap_pull.pull_pop
            out(fn(host, user, pw, key, port=int(port)))
        else:
            out(f"unknown mail subcommand: {sub} (inbox|read|compose|send|ext|pull)")
    elif cmd == "mailsearch":
        from rabbitghost import mail

        hits = mail.search(rest, getpw("passphrase: "))
        out({"hits": len(hits), "subjects": [h.get("subject") for h in hits[:10]]})
    elif cmd == "parse":
        from rabbitghost import parser

        res = parser.parse(rest, max_chars=2000)
        info = {
            "type": res.get("type"),
            "chars": len(res.get("text") or ""),
            "preview": (res.get("text") or "")[:160],
        }
        if "error" in res:
            info["error"] = res["error"]
        out(info)
    else:
        out(f"unknown: {cmd}")
    return True


if __name__ == "__main__":
    menu()
    sys.exit(0)
