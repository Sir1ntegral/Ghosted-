"""
IMAP / POP pull — OPT-IN external inbox receiving (option 2, user-enabled).

Logs into a provider's IMAP/POP server with credentials supplied PER CALL (never
stored), fetches messages, and BLACK-BOXES each at rest (mail.seal_inbound). This is
the explicitly-chosen escape hatch for receiving external mail WITHOUT a domain.

Honest: this is NOT sovereign — Rabbit logs into a third-party inbox to read it. It's
opt-in; the sovereign default remains @sovereign.dmn mesh mail. Once pulled, messages
are sealed immediately so they never sit on disk readable.
"""
from __future__ import annotations

import imaplib
import poplib

from rabbitghost import mail


def pull_imap(host: str, username: str, password: str, key: str, *,
              port: int = 993, folder: str = "INBOX", limit: int = 50, use_ssl: bool = True) -> dict:
    """Fetch up to `limit` newest messages from an IMAP inbox; black-box each at rest.
    Returns the count sealed. Credentials are used for this call only."""
    M = imaplib.IMAP4_SSL(host, port) if use_ssl else imaplib.IMAP4(host, port)
    sealed = 0
    try:
        M.login(username, password)
        M.select(folder)
        _typ, data = M.search(None, "ALL")
        ids = data[0].split()[-limit:] if data and data[0] else []
        for i in ids:
            _typ, msgdata = M.fetch(i, "(RFC822)")
            if msgdata and msgdata[0]:
                raw = msgdata[0][1]
                raw = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else str(raw)
                mail.seal_inbound(raw, key)
                sealed += 1
    finally:
        try:
            M.logout()
        except Exception:
            pass
    return {"sealed": sealed, "via": f"imap:{host}"}


def pull_pop(host: str, username: str, password: str, key: str, *,
             port: int = 995, limit: int = 50, use_ssl: bool = True) -> dict:
    """Fetch up to `limit` newest messages from a POP3 inbox; black-box each at rest."""
    P = poplib.POP3_SSL(host, port) if use_ssl else poplib.POP3(host, port)
    sealed = 0
    try:
        P.user(username)
        P.pass_(password)
        count = len(P.list()[1])
        for idx in range(max(1, count - limit + 1), count + 1):
            _resp, lines, _octets = P.retr(idx)
            raw = b"\n".join(lines).decode("utf-8", "replace")
            mail.seal_inbound(raw, key)
            sealed += 1
    finally:
        try:
            P.quit()
        except Exception:
            pass
    return {"sealed": sealed, "via": f"pop:{host}"}
