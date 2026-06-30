#!/usr/bin/env python
"""
Ghosted — standalone stealth console.

Separated from the live Rabbit runtime per Lucy's authorization, this bundles
the FULL ghost stack (recon / cloak-stego / forge / traffic / dissect) together
with the SovereignBrowserEngine (Google/Bing/YouTube/Tor) into one app.

Governance note: run standalone, Ghosted is OUTSIDE Rabbit's Madara/Watchtower
envelope. This console keeps the voice-auth-as-Lucy intent by being launched
only from Lucy's own desktop icon. Defensive/research use on Lucy's own device.
"""
from __future__ import annotations

import getpass
import os
import sys
import textwrap

# Frozen-console fix: force UTF-8 on stdout/stderr so the banner em-dashes and any
# Unicode render correctly instead of as cp1252 replacement chars (the glitch).
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

BANNER = r"""
   ____ _   _  ___  ____ _____ _____ ____
  / ___| | | |/ _ \/ ___|_   _| ____|  _ \
 | |  _| |_| | | | \___ \ | | |  _| | | | |
 | |_| |  _  | |_| |___) || | | |___| |_| |
  \____|_| |_|\___/|____/ |_| |_____|____/
        sovereign stealth console — ghost + browser
"""


def _ghost():
    from ghosted.ghost import GhostMode

    return GhostMode()


def _browser():
    from ghosted.web import SovereignBrowserEngine

    return SovereignBrowserEngine()


def _setup_wizard(*, ask=input, getpw=None, out=print, session=None) -> None:
    """Guided account setup — captures everything here: account, display name, your
    emails (with fallbacks), phone+carrier for text codes, an authenticator (QR),
    a trusted-location factor, and one-time recovery codes. I/O is injectable so the
    same flow is unit-testable. Multi-factor enrollment so 'two must be used' at login."""
    import getpass as _gp
    import os

    getpw = getpw or _gp.getpass
    session = session if session is not None else {}
    from ghosted import mail, mfa, preferences, qrcode, vault

    out("— Ghosted account setup —  account · profile · email · text · 2FA · location")
    # 1) account (master password)
    if vault.is_initialized():
        pw = session.get("pw") or getpw("enter master password to configure your account: ")
        if not vault.login(pw):
            out({"setup": "wrong password — aborted"})
            return
        session["pw"] = pw
        out("account: unlocked.")
    else:
        pw = getpw("create a master password: ")
        if not pw or pw != getpw("confirm master password: "):
            out({"setup": "passwords empty or did not match — aborted"})
            return
        vault.initialize(pw)
        session["pw"] = pw
        out("account: created + unlocked.")
    # 2) display name (shown whenever signed in)
    name = ask("your display name (shown when signed in): ").strip()
    if name:
        preferences.set("display_name", name)
    # 3) email(s): primary + fallbacks (sovereign mail will try 2nd/3rd if needed)
    out(f"sovereign address: {mail.address('me')}  (always available)")
    elist = [e.strip() for e in ask("your email(s), comma-separated (1st, 2nd, 3rd): ")
             .replace(";", ",").split(",") if e.strip()]
    for e in elist:
        try:
            mail.add_identity(e)
        except Exception:
            pass
    if elist:
        mfa.enroll("email", pw, addrs=elist)
        out({"email factor": elist})
        # External email access (IMAP/POP/SMTP) so you can send/receive here, with the
        # OPTION to save the email password (encrypted) so you don't retype it.
        if ask("set up external email access (IMAP/SMTP) to send/receive here? [y/N]: ").strip().lower() == "y":
            addr = elist[0]
            proto = ask("  protocol [imap/pop/smtp] (imap): ").strip().lower() or "imap"
            # Auto-fill the server from the email's provider so the user needn't look it up.
            sug = mail.provider_config(addr).get(proto, {})
            host = ask(f"  server host [{sug.get('host', '')}]: ").strip() or sug.get("host", "")
            port_s = ask(f"  port [{sug.get('port', '')}]: ").strip()
            user = ask(f"  username ({addr}): ").strip() or addr
            save = ask("  save the email password (encrypted)? [y/N]: ").strip().lower() == "y"
            epw = getpw("  email password: ") if save else ""
            mail.set_account(addr, proto, host, int(port_s) if port_s.isdigit() else 0,
                             user, password=epw, master_pw=pw)
            out({"email access": "configured" + (" + password saved (encrypted)" if save else " (password entered per fetch)")})
    # 4) phone + carrier → text-message (SMS) codes
    number = ask("mobile number for text codes (blank to skip): ").strip()
    if number:
        out("  carriers: " + ", ".join(sorted(mfa.CARRIER_GATEWAYS)))
        carrier = ask("  carrier: ").strip().lower()
        mfa.enroll("phone", pw, number=number, carrier=carrier)
        out({"text factor": {"number": number, "carrier": carrier}})
    # 5) authenticator (QR)
    if ask("set up an authenticator app via QR? [Y/n]: ").strip().lower() != "n":
        en = mfa.enroll("authenticator", pw)
        qr_path = os.path.join(mail._data_root(), "authenticator_qr.svg")
        try:
            with open(qr_path, "w", encoding="utf-8") as fh:
                fh.write(qrcode.svg(en["uri"]))
        except Exception:
            qr_path = "(could not save)"
        out({"authenticator": "enrolled", "secret": en["secret"],
             "otpauth_uri": en["uri"], "qr_saved": qr_path,
             "tip": "open the saved .svg to scan, or type the secret into your app"})
    # 6) trusted-location factor (this network)
    if ask("trust this network as a location factor? [Y/n]: ").strip().lower() != "n":
        ip = ""
        try:
            from ghosted.homepage import _primary_lan_ip

            ip = _primary_lan_ip()
        except Exception:
            pass
        r = mfa.enroll("location", pw, ip=ip)
        out({"location factor": r.get("trusted")})
    # 7) one-time recovery codes
    rc = mfa.enroll("recovery", pw)["recovery_codes"]
    out({"recovery_codes": rc, "note": "store safely — each works once (lost-factor escape)"})
    # 8) WireGuard mesh enrollment (optional) — seal each device's config in the vault
    if ask("enroll devices into a sovereign WireGuard mesh now? [y/N]: ").strip().lower() == "y":
        from ghosted import vault as _v

        hub = ask("  hub device name (blank = full mesh): ").strip()
        devices = []
        out("  add devices (blank name to finish).")
        while True:
            nm = ask("    device name: ").strip()
            if not nm:
                break
            ep = ask(f"    {nm} public endpoint host:port (blank if NAT): ").strip()
            devices.append((nm, ep))
        if devices:
            names = _v.build_and_seal_mesh(devices, pw, hub=hub)
            out({"wireguard": "mesh sealed in your vault", "devices": names,
                 "export": "type 'mesh export' to write each importable .conf, or use the Account page"})
    out({"setup": "done", "display_name": preferences.get("display_name"),
         "identities": mail.identities(), "mfa": mfa.status()})


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
            "        Running with reduced commands — the stealth stack failed to load.\n"
            "        Stdlib commands (connect/spool/contacts/filters/identity/parse) still work."
        )
    try:  # auto-complete spooled mesh-mail / fetch the instant connectivity returns
        from ghosted import flusher

        flusher.start_autoflush()
    except Exception:
        pass
    actions = textwrap.dedent(
        """
        commands:
          recon <topic>     stealth-investigate (uses browser engine)
          cloak <img> <msg> hide encrypted message inside an image (stego)
          uncloak <img>     extract hidden message from an image
          forge <path>      produce a unique, equivalent artifact
          browse <query>    sovereign web search (Google/Bing/YT/Tor)
          home [port]       open the search website (GUI: logo + search bar + layout)
          login             unlock / set the master password (vault + mesh)
          network           build a WireGuard mesh, sealed in the vault (login first)
          encrypt <text>    seal text with GHOSTED-CIPHER-1 (passphrase)
          decrypt           open a sealed blob (paste token + passphrase)
          parse <path|text> extract text/structure (pdf/docx/html/csv/json/img via OCR)
          scan <path> [q]   EDR-lite file safety check (q = quarantine if malicious)
          doctor            report which capabilities are wired (+ optional deps)
          setup             guided account setup: name·email·text·2FA(QR)·location
          account           your info: personal data + history + usage stats
          mfa               multi-factor status (password + 2 factors required)
          prefs [set k v]   customize your experience (accent/notifications/…)
          notify            your optional notifications
          health            device health: CPU/RAM/disk/battery/net/security
          feedback [sub]    learning loop: summary | good <q> | bad <q> | rate <s> <q>
          connect           check internet across wifi/LAN/WAN (multi-interface)
          hotspot           start a WiFi hotspot for the mesh (Windows, needs admin)
          contacts          list saved contacts
          filters           list mail filter rules
          mail [sub]        black-box mail: inbox|read|compose|send <peer>|ext|pull <imap|pop>
          mailsearch <q>    search your black-box mail (needs passphrase)
          spool             store-and-forward outbox: pending count + online status
          flush             flush spooled mesh-mail + fetch now (store-and-forward)
          mesh [export]     mesh status, or export sealed configs to .conf (login)
          passwd            rotate the master password (re-seals the mesh)
          identity [add|rm <email>]  use your own email (any kind, no IMAP/POP); @sovereign.dmn first
          status            posture
          help [command]    full help — everything the app does (or detail for one command)
          quit              stand down (drops all ghost components for GC)
        """
    ).strip()
    print(actions)
    session = {"pw": None}  # app-login state: holds the unlocked master password
    # GUI-first: launching the app (e.g. the desktop icon) auto-opens the search
    # website in the browser so it "just works", while this console stays available
    # for setup/advanced commands. Disable with env GHOSTED_NO_AUTOHOME=1.
    if os.environ.get("GHOSTED_NO_AUTOHOME", "") not in ("1", "true", "yes"):
        try:
            import threading
            import time as _time
            import webbrowser

            from ghosted import homepage

            port = homepage._PORT
            t = threading.Thread(target=homepage.serve, args=(port,), daemon=True)
            t.start()
            session["home_thread"] = t
            session["home_port"] = port
            _time.sleep(0.7)  # let it bind before opening the browser
            url = f"http://127.0.0.1:{port}"
            try:
                webbrowser.open(url)
            except Exception:
                pass
            print(f"\n[ghosted] your search website is open in the browser: {url}")
            print("          create your account there (👤 Account), or type 'setup' here.\n")
        except Exception:
            pass  # headless / port busy → the console still works
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
        from ghosted import help_text

        out(help_text.detail(rest) if rest.strip() else help_text.overview())
    elif cmd in ("recon", "forge") and g is None:
        out("ghost stealth stack unavailable (failed to load)")
    elif cmd == "recon":
        out(g.recon(rest))
    elif cmd == "forge":
        out(g.forge(rest, rest + ".forged"))
    elif cmd == "browse":
        from ghosted import feedback, spellcheck

        sp = spellcheck.correct(rest)
        q = sp["corrected"]
        results = _browser().web_search(q)
        try:
            feedback.record_search(q, len(results) if hasattr(results, "__len__") else 0)
        except Exception:
            pass
        if sp["changed"]:
            out({"showing_results_for": q, "you_typed": sp["original"], "results": results})
        else:
            out(results)
    elif cmd in ("home", "gui", "web"):
        # Launch Ghosted's own search website (logo + search bar + layout) and open
        # it in the default browser. The server runs in a daemon thread so this
        # console stays interactive; homepage.serve() blocks only that thread.
        import threading
        import time
        import webbrowser

        from ghosted import homepage

        port = int(rest.strip()) if rest.strip().isdigit() else homepage._PORT
        if not session.get("home_thread"):
            t = threading.Thread(target=homepage.serve, args=(port,), daemon=True)
            t.start()
            session["home_thread"] = t
            session["home_port"] = port
            time.sleep(0.6)  # let it bind + print its reachable IPs
        url = f"http://127.0.0.1:{session.get('home_port', port)}"
        try:
            webbrowser.open(url)
        except Exception:  # headless / no browser — the URL is still served
            pass
        out({"homepage": "live", "open": url,
             "note": "search website running; this console stays active"})
    elif cmd == "health":
        from ghosted import health

        out(health.snapshot())
    elif cmd == "feedback":
        from ghosted import feedback

        sub, _, arg = rest.partition(" ")
        sub = sub.strip().lower()
        if sub in ("", "summary", "status"):
            out(feedback.summary())
        elif sub in ("good", "up", "+1", "👍"):
            feedback.record_rating(arg, 1.0)
            out({"feedback": "recorded 👍", "query": arg})
        elif sub in ("bad", "down", "-1", "👎"):
            feedback.record_rating(arg, -1.0)
            out({"feedback": "recorded 👎", "query": arg})
        elif sub == "rate":
            score_s, _, q = arg.partition(" ")
            try:
                feedback.record_rating(q, float(score_s))
                out({"feedback": "recorded", "score": score_s, "query": q})
            except ValueError:
                out({"usage": "feedback rate <1-5 or -1..1> <query>"})
        else:
            out({"usage": "feedback [summary | good <q> | bad <q> | rate <score> <q>]"})
    elif cmd == "setup":
        _setup_wizard(ask=ask, getpw=getpw, out=out, session=session)
    elif cmd == "mfa":
        from ghosted import mfa

        out(mfa.status())
    elif cmd in ("prefs", "preferences"):
        from ghosted import preferences

        sub, _, arg = rest.partition(" ")
        sub = sub.strip().lower()
        if sub in ("", "show", "list"):
            out(preferences.all())
        elif sub == "set":
            k, _, v = arg.partition(" ")
            out(preferences.set(k.strip(), v.strip()))
        elif sub == "reset":
            out(preferences.reset())
        else:
            out({"usage": "prefs [show | set <key> <value> | reset]"})
    elif cmd in ("notify", "notifications"):
        from ghosted import notifications

        out({"notifications": notifications.collect()})
    elif cmd == "account":
        # Account information: all personal data + history + statistical use.
        from ghosted import feedback, mail, mfa, preferences

        fb = feedback.summary()
        out({
            "display_name": preferences.get("display_name") or "(unset)",
            "identities": mail.identities(),
            "email_accounts": list(mail.accounts().keys()),
            "mfa": mfa.status(),
            "preferences": preferences.all(),
            "history": feedback.recent_queries(limit=15),
            "usage_stats": {k: fb[k] for k in ("searches", "clicks", "ratings", "adaptivity", "learned_pairs")},
        })
    elif cmd == "login":
        from ghosted import mfa, vault

        pw = getpw("master password: ")
        if not vault.is_initialized():
            confirm = getpw("set new master password (confirm): ")
            if pw != confirm:
                out({"vault": "passwords do not match"})
                return True
            vault.initialize(pw)
            session["pw"] = pw
            out({"vault": "initialized + unlocked", "tip": "run 'setup' to add 2FA factors"})
            return True
        if not vault.login(pw):
            out({"vault": "wrong password"})
            return True
        # Multi-factor: password verified — now require the enrolled second factors.
        enrolled = mfa.enrolled()
        if not enrolled:
            session["pw"] = pw
            out({"vault": "unlocked", "note": "no 2FA factors enrolled — run 'setup' to add them"})
            return True
        proofs = {}
        # auto location factor (the machine itself counts as a trusted location here)
        for factor in enrolled:
            if factor == "location":
                continue  # verified from network context, not a typed code
            if factor in ("email", "phone"):
                ch = mfa.challenge(factor, pw)
                if ch.get("shown"):
                    out({factor: f"code (offline fallback): {ch['shown']}"})
                else:
                    out({factor: f"one-time code sent via {ch.get('via', factor)}"})
            proofs[factor] = ask(f"  {factor} code: ").strip()
        result = mfa.validate(pw, proofs, client_ip="127.0.0.1")
        if result["ok"]:
            session["pw"] = pw
            out({"vault": "unlocked", "factors_used": result["passed"], "policy": result["required"]})
        else:
            out({"vault": "2FA failed", "passed": result["passed"],
                 "required": result["required"], "enrolled": result.get("enrolled")})
    elif cmd == "network":
        from ghosted import vault

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

        from ghosted.crypto import encrypt

        blob = encrypt(rest, getpw("passphrase: ").strip())
        out({"sealed": base64.b64encode(blob.to_bytes()).decode()})
    elif cmd == "decrypt":
        import base64

        from ghosted.crypto import EncryptedBlob, decrypt

        tok = ask("sealed token: ").strip()
        pw = getpw("passphrase: ").strip()
        out({"opened": decrypt(EncryptedBlob.from_bytes(base64.b64decode(tok)), pw)})
    elif cmd in ("cloak", "uncloak"):
        from ghosted.ghost import GhostCloak

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
        from ghosted import transport

        sp = transport.Spool()
        out({"pending": len(sp), "online": transport.online()})
    elif cmd == "flush":
        from ghosted import flusher

        out(flusher.flush_all())
    elif cmd == "mesh":
        from ghosted import vault

        sub, _, arg = rest.partition(" ")
        sub = sub.strip().lower()
        if sub in ("", "status"):
            out({"has_mesh": vault.has_mesh()})
        elif sub == "export":
            if not vault.has_mesh():
                out("no mesh sealed yet — run 'network' first")
                return True
            try:
                configs = vault.unseal_mesh(getpw("master password: "))
            except Exception:
                out({"mesh": "wrong password or vault locked"})
                return True
            target = arg.strip() or os.path.join(
                os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"),
                "Ghosted",
                "mesh-export",
            )
            os.makedirs(target, exist_ok=True)
            written = []
            for name, conf in configs.items():
                import json as _json

                p = os.path.join(target, f"{name}.conf")
                with open(p, "w", encoding="utf-8") as fh:
                    fh.write(
                        conf if isinstance(conf, str) else _json.dumps(conf, indent=2)
                    )
                written.append(p)
            out(
                {"exported": written, "import_into": "WireGuard — Add Tunnel from file"}
            )
        else:
            out(f"unknown mesh subcommand: {sub} (status|export [dir])")
    elif cmd == "passwd":
        from ghosted import vault

        if not vault.is_initialized():
            out("no master password set yet — run 'login' first")
            return True
        old = getpw("current master password: ")
        new = getpw("new master password: ")
        if new != getpw("confirm new master password: "):
            out({"vault": "new passwords do not match"})
            return True
        try:
            ok = vault.change_password(old, new)
        except ValueError as e:
            out({"vault": str(e)})
            return True
        if ok:
            if session.get("pw"):
                session["pw"] = new
            out({"vault": "password rotated (mesh re-sealed)"})
        else:
            out({"vault": "current password incorrect"})
    elif cmd == "identity":
        from ghosted import mail

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
        from ghosted import connectivity

        out(connectivity.ensure_online())
    elif cmd == "hotspot":
        from ghosted import connectivity

        out(connectivity.start_hotspot())
    elif cmd == "contacts":
        from ghosted import contacts

        out({"contacts": contacts.contacts()})
    elif cmd == "filters":
        from ghosted import mail_filters

        out({"filters": mail_filters.filters()})
    elif cmd == "mail":
        from ghosted import bridge, imap_pull, mail, mesh_mail

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
        from ghosted import mail

        hits = mail.search(rest, getpw("passphrase: "))
        out({"hits": len(hits), "subjects": [h.get("subject") for h in hits[:10]]})
    elif cmd == "parse":
        from ghosted import parser

        res = parser.parse(rest, max_chars=2000)
        info = {
            "type": res.get("type"),
            "chars": len(res.get("text") or ""),
            "preview": (res.get("text") or "")[:160],
        }
        if "error" in res:
            info["error"] = res["error"]
        out(info)
    elif cmd == "scan":
        from ghosted import scan as _scan

        target, _, opt = rest.partition(" ")
        quarantine = opt.strip().lower() in ("q", "-q", "quarantine")
        out(_scan.scan_file(target.strip(), quarantine=quarantine))
    elif cmd == "doctor":
        from ghosted import contracts

        out(contracts.verify_contracts())
    else:
        out(f"unknown: {cmd}")
    return True


if __name__ == "__main__":
    menu()
    sys.exit(0)
