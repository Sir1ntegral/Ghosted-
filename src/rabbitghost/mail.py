"""
Sovereign black-box mail (Layer A: Rabbit ↔ Rabbit).

Every message is a RABBIT-CIPHER-1 ciphertext at rest and on the wire. To anyone
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
# message is a RABBIT-CIPHER-1 black box delivered peer-to-peer over WireGuard.
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
    d = os.path.join(base, "RabbitGhost")
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


def _save_ids(ids: list) -> None:
    with open(_identities_path(), "w", encoding="utf-8") as fh:
        json.dump(ids, fh)


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


def _mailbox_dir() -> str:
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    d = os.path.join(base, "RabbitGhost", "mail")
    os.makedirs(d, exist_ok=True)
    return d


def _seal(obj: dict, passphrase: str) -> str:
    """Serialise + RABBIT-CIPHER-1 encrypt → opaque base64 token (the black box)."""
    from rabbit.core.crypto import encrypt

    blob = encrypt(json.dumps(obj, ensure_ascii=False), passphrase)
    return base64.b64encode(blob.to_bytes()).decode()


def _open(token: str, passphrase: str) -> dict:
    from rabbit.core.crypto import EncryptedBlob, decrypt

    blob = EncryptedBlob.from_bytes(base64.b64decode(token))
    return json.loads(decrypt(blob, passphrase))


def compose(to: str, subject: str, body: str, passphrase: str, sender: str = "me") -> str:
    """Return a sealed black-box token for one message (nothing is stored)."""
    msg = {"to": address(to), "from": address(sender), "subject": subject,
           "body": body, "t": int(time.time())}
    return _seal(msg, passphrase)


def send(to: str, subject: str, body: str, passphrase: str, sender: str = "me") -> str:
    """Seal + drop the message into the local mailbox as a `.box` file. Returns its path.
    (Mesh delivery to a peer's mailbox is the same token over WireGuard — same black box.)"""
    token = compose(to, subject, body, passphrase, sender)
    path = os.path.join(_mailbox_dir(), f"{int(time.time() * 1000)}-{secrets.token_hex(4)}.box")
    with open(path, "w", encoding="ascii") as fh:
        fh.write(token)
    return path


def seal_inbound(raw_rfc822: str, passphrase: str) -> str:
    """Layer-B hook: black-box an externally-received (plaintext) email AT REST the
    moment it lands, so it never sits on disk readable."""
    msg = {"to": "me", "from": "external", "subject": "(external)", "body": raw_rfc822, "t": int(time.time())}
    path = os.path.join(_mailbox_dir(), f"{int(time.time() * 1000)}-{secrets.token_hex(4)}.box")
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
        hay = " ".join(str(m.get(k, "")) for k in ("from", "to", "subject", "body")).lower()
        if not q or q in hay:
            hits.append({**m, "_path": path})
    return hits
