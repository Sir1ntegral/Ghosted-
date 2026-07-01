"""
Sovereign black-box mail (Layer A: Rabbit ↔ Rabbit).

Every message is a GHOSTED-CIPHER-1 ciphertext at rest and on the wire. To anyone
without the key — disk, network, a server, a thief — each message is an
indistinguishable **black box**: no subject, no sender, no body, just opaque bytes.
Only a holder of the passphrase/key opens it. End-to-end private, zero external
infrastructure (delivery rides the WireGuard mesh).

Layer B (a valid/functional external address that receives e.g. GitHub
verification mail) requires a domain + MX + reachable SMTP receiver — see README /
task #16. Inbound external mail is plaintext in transit (sender-controlled) but is
black-boxed AT REST the instant it lands via `seal_inbound()`.
"""

from __future__ import annotations

import base64
import glob
import json
import os
import re
import secrets
import time
from typing import Any

# Rabbit's sovereign email domain — used for mesh (Layer A) addressing. This is an
# internal/sovereign domain (no public DNS, no registration): every sovereign.dmn
# message is a GHOSTED-CIPHER-1 black box delivered peer-to-peer over WireGuard.
# Functional EXTERNAL mail (e.g. GitHub verifications) would need a registered
# public-TLD domain + MX records — .dmn cannot receive internet email (see #16).
DOMAIN = "sovereign.dmn"


def address(user: str) -> str:
    """Qualify a bare username into a sovereign address: 'lucy' -> 'lucy@sovereign.dmn'."""
    user = (user or "").strip()
    return user if "@" in user else f"{user}@{DOMAIN}"


# ── identities (bring-your-own-email) ────────────────────────────────────────
# Users may register their OWN address of any kind (gmail / proton / outlook /
# custom). It is stored as an IDENTITY ONLY — no password, NO IMAP, NO POP. Rabbit
# never logs into a third-party inbox; the address is just a from/identity label.
# The sovereign @sovereign.dmn address is always suggested FIRST.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _data_root() -> str:
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    d = os.path.join(base, "Ghosted")
    os.makedirs(d, exist_ok=True)
    return d


def _identities_path() -> str:
    return os.path.join(_data_root(), "identities.json")


def _load_ids() -> list:
    try:
        with open(_identities_path(), encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return []


def atomic_write_json(path: str, obj) -> None:
    """Crash-safe JSON write: temp file + fsync + atomic os.replace. Shared by the
    local stores (identities/contacts/filters) so a crash mid-write can't truncate
    and silently empty a security-relevant store (e.g. block-rules)."""
    import tempfile

    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=d, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(obj, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except Exception:
        try:
            os.remove(tmp)
        except Exception:
            pass
        raise


def _save_ids(ids: list) -> None:
    atomic_write_json(_identities_path(), ids)


def add_identity(addr: str) -> str:
    """Register an email identity the user owns — ANY provider. No password/IMAP/POP
    is ever requested or stored; it's an identity label only. Returns the address."""
    addr = (addr or "").strip()
    if not _EMAIL_RE.match(addr):
        raise ValueError("not a valid email address")
    ids = _load_ids()
    if addr.lower() not in (x.lower() for x in ids):
        ids.append(addr)
        _save_ids(ids)
    return addr


def remove_identity(addr: str) -> bool:
    addr = (addr or "").strip().lower()
    ids = _load_ids()
    kept = [x for x in ids if x.lower() != addr]
    if len(kept) != len(ids):
        _save_ids(kept)
        return True
    return False


def identities() -> list:
    """All usable from-identities. The sovereign @sovereign.dmn address is suggested
    FIRST, then the user's own registered addresses (identities only — no IMAP/POP)."""
    own = _load_ids()
    sovereign = address("me")
    return [sovereign] + [a for a in own if a.lower() != sovereign.lower()]


def is_enrolled() -> bool:
    """True once the user has set up their OWN email — a personal identity they own
    (beyond the default @sovereign.dmn mesh address) or an external IMAP/POP/SMTP
    account. Drives the /mail route: not enrolled → guided setup; enrolled → mailbox."""
    try:
        return len(identities()) > 1 or bool(accounts())
    except Exception:
        return False


# ── external email account settings (server config only — NEVER a password) ────────
# The setup wizard's "email options". We persist the IMAP/POP/SMTP server settings so
# the user doesn't retype them, but the PASSWORD is still supplied per pull/send call
# and is never written to disk (consistent with imap_pull's per-call credential rule).
def _accounts_path() -> str:
    return os.path.join(_data_root(), "email_accounts.json")


# Known provider server settings → auto-fill IMAP/POP/SMTP when a user enters their own
# email, so they don't have to look it up. Generic fallback derives from the domain.
_PROVIDERS = {
    "gmail.com": ("imap.gmail.com", "pop.gmail.com", "smtp.gmail.com"),
    "googlemail.com": ("imap.gmail.com", "pop.gmail.com", "smtp.gmail.com"),
    "outlook.com": ("outlook.office365.com", "outlook.office365.com", "smtp-mail.outlook.com"),
    "hotmail.com": ("outlook.office365.com", "outlook.office365.com", "smtp-mail.outlook.com"),
    "live.com": ("outlook.office365.com", "outlook.office365.com", "smtp-mail.outlook.com"),
    "msn.com": ("outlook.office365.com", "outlook.office365.com", "smtp-mail.outlook.com"),
    "yahoo.com": ("imap.mail.yahoo.com", "pop.mail.yahoo.com", "smtp.mail.yahoo.com"),
    "ymail.com": ("imap.mail.yahoo.com", "pop.mail.yahoo.com", "smtp.mail.yahoo.com"),
    "aol.com": ("imap.aol.com", "pop.aol.com", "smtp.aol.com"),
    "icloud.com": ("imap.mail.me.com", "imap.mail.me.com", "smtp.mail.me.com"),
    "me.com": ("imap.mail.me.com", "imap.mail.me.com", "smtp.mail.me.com"),
    "zoho.com": ("imap.zoho.com", "pop.zoho.com", "smtp.zoho.com"),
    "gmx.com": ("imap.gmx.com", "pop.gmx.com", "mail.gmx.com"),
    "fastmail.com": ("imap.fastmail.com", "pop.fastmail.com", "smtp.fastmail.com"),
    "protonmail.com": ("127.0.0.1", "127.0.0.1", "127.0.0.1"),  # needs Proton Bridge
    "proton.me": ("127.0.0.1", "127.0.0.1", "127.0.0.1"),
}
_PORTS = {"imap": 993, "pop": 995, "smtp": 587}


def provider_config(addr: str) -> dict:
    """Suggested server settings for an email address, from its domain. Always returns
    a usable dict (generic imap./pop./smtp.<domain> fallback for unknown providers)."""
    addr = (addr or "").strip().lower()
    domain = addr.split("@")[-1] if "@" in addr else ""
    imap, pop, smtp = _PROVIDERS.get(
        domain, (f"imap.{domain}", f"pop.{domain}", f"smtp.{domain}") if domain else ("", "", "")
    )
    return {
        "domain": domain,
        "imap": {"host": imap, "port": _PORTS["imap"]},
        "pop": {"host": pop, "port": _PORTS["pop"]},
        "smtp": {"host": smtp, "port": _PORTS["smtp"]},
        "known": domain in _PROVIDERS,
    }


def accounts() -> dict:
    try:
        with open(_accounts_path(), encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def set_account(
    addr: str,
    protocol: str = "imap",
    host: str = "",
    port: int = 0,
    username: str = "",
    use_ssl: bool = True,
    password: str = "",
    master_pw: str = "",
) -> dict:
    """Save server settings for an external email address and register it as an identity.
    The email-access password is OPTIONAL: if you provide it (with your master password),
    it is sealed with GHOSTED-CIPHER-1 and stored encrypted so you don't retype it; leave
    it blank to keep the old per-fetch behaviour (entered each time, never stored)."""
    addr = (addr or "").strip()
    if not _EMAIL_RE.match(addr):
        raise ValueError("not a valid email address")
    protocol = (protocol or "imap").strip().lower()
    if protocol not in ("imap", "pop", "smtp"):
        raise ValueError("protocol must be imap, pop, or smtp")
    host = (host or "").strip()
    if not host:  # auto-fill the server from the email's provider/domain
        host = provider_config(addr)[protocol]["host"]
    if not port:
        port = _PORTS[protocol]
    data = accounts()
    existing = data.get(addr.lower(), {})
    cfg = {
        "protocol": protocol,
        "host": host,
        "port": int(port),
        "username": (username or addr).strip(),
        "use_ssl": bool(use_ssl),
        # preserve a previously-saved sealed password unless we're setting a new one
        "pw_blob": existing.get("pw_blob", ""),
    }
    if password and master_pw:
        cfg["pw_blob"] = _seal({"pw": password}, master_pw)
    data[addr.lower()] = cfg
    atomic_write_json(_accounts_path(), data)
    try:
        add_identity(addr)
    except Exception:
        pass
    safe = {k: v for k, v in cfg.items() if k != "pw_blob"}
    safe["password_saved"] = bool(cfg["pw_blob"])
    return {addr: safe}


def set_account_password(addr: str, password: str, master_pw: str) -> bool:
    """Save or change the (encrypted) email-access password for an account."""
    data = accounts()
    cfg = data.get((addr or "").strip().lower())
    if not cfg:
        return False
    cfg["pw_blob"] = _seal({"pw": password}, master_pw) if password else ""
    data[addr.strip().lower()] = cfg
    atomic_write_json(_accounts_path(), data)
    return True


def account_password(addr: str, master_pw: str) -> str:
    """Recover a saved email-access password (empty string if none / wrong key)."""
    cfg = accounts().get((addr or "").strip().lower(), {})
    blob = cfg.get("pw_blob")
    if not blob:
        return ""
    try:
        return _open(blob, master_pw).get("pw", "")
    except Exception:
        return ""


def remove_account(addr: str) -> bool:
    addr = (addr or "").strip().lower()
    data = accounts()
    if addr in data:
        data.pop(addr, None)
        atomic_write_json(_accounts_path(), data)
        return True
    return False


def _mailbox_dir() -> str:
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    d = os.path.join(base, "Ghosted", "mail")
    os.makedirs(d, exist_ok=True)
    return d


def _seal(obj: dict, passphrase: str) -> str:
    """Serialise + GHOSTED-CIPHER-1 encrypt → opaque base64 token (the black box)."""
    from ghosted.crypto import encrypt

    blob = encrypt(json.dumps(obj, ensure_ascii=False), passphrase)
    return base64.b64encode(blob.to_bytes()).decode()


def _open(token: str, passphrase: str) -> dict:
    from ghosted.crypto import EncryptedBlob, decrypt

    blob = EncryptedBlob.from_bytes(base64.b64decode(token))
    return json.loads(decrypt(blob, passphrase))


def compose(
    to: str, subject: str, body: str, passphrase: str, sender: str = "me"
) -> str:
    """Return a sealed black-box token for one message (nothing is stored)."""
    msg = {
        "to": address(to),
        "from": address(sender),
        "subject": subject,
        "body": body,
        "t": int(time.time()),
    }
    return _seal(msg, passphrase)


def send(to: str, subject: str, body: str, passphrase: str, sender: str = "me") -> str:
    """Seal + drop the message into the local mailbox as a `.box` file. Returns its path.
    (Mesh delivery to a peer's mailbox is the same token over WireGuard — same black box.)
    """
    token = compose(to, subject, body, passphrase, sender)
    path = os.path.join(
        _mailbox_dir(), f"{int(time.time() * 1000)}-{secrets.token_hex(4)}.box"
    )
    with open(path, "w", encoding="ascii") as fh:
        fh.write(token)
    return path


def seal_inbound(raw_rfc822: str, passphrase: str) -> str:
    """Layer-B hook: black-box an externally-received (plaintext) email AT REST the
    moment it lands, so it never sits on disk readable."""
    msg = {
        "to": "me",
        "from": "external",
        "subject": "(external)",
        "body": raw_rfc822,
        "t": int(time.time()),
    }
    path = os.path.join(
        _mailbox_dir(), f"{int(time.time() * 1000)}-{secrets.token_hex(4)}.box"
    )
    with open(path, "w", encoding="ascii") as fh:
        fh.write(_seal(msg, passphrase))
    return path


def inbox() -> list[str]:
    """Paths of all black-box messages (opaque until opened)."""
    return sorted(glob.glob(os.path.join(_mailbox_dir(), "*.box")))


def read(path: str, passphrase: str) -> dict[str, Any]:
    """Open one black box with the key."""
    with open(path, "r", encoding="ascii") as fh:
        return _open(fh.read(), passphrase)


def search(query: str, passphrase: str, *, limit: int = 500) -> list[dict]:
    """Search the mailbox for query across from/to/subject/body.

    Requires the key: black boxes are opaque on disk, so search must open each with
    the passphrase, then match. Boxes the key can't open are skipped. Each hit is the
    decrypted message dict plus its _path. Newest first.
    """
    q = (query or "").lower()
    hits: list[dict] = []
    for path in reversed(inbox()[-limit:]):
        try:
            m = read(path, passphrase)
        except Exception:
            continue  # wrong key / corrupt — can't search what we can't open
        hay = " ".join(
            str(m.get(k, "")) for k in ("from", "to", "subject", "body")
        ).lower()
        if not q or q in hay:
            hits.append({**m, "_path": path})
    return hits
