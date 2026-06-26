"""
External email bridge — SEND to any address via SMTP submission.

This is the explicit, opt-in NON-sovereign escape hatch: it relays one outbound
message through a submission server (e.g. ``smtp.gmail.com:587``) using credentials
supplied for THAT CALL ONLY — nothing is stored. It is still **NO IMAP / NO POP**:
no inbox is ever pulled or logged into for reading.

Receiving external mail is a fundamentally different problem. Without IMAP/POP it
requires your OWN MX mail server — a registered public-TLD domain + a publicly
reachable host listening on SMTP. That can't be done in pure software on a NAT'd
machine, so RabbitGhost does not pretend to: see ``receive_external_status()``.

Sovereign alternative that needs none of this: @sovereign.dmn mesh mail (mail.py /
mesh_mail.py) — end-to-end black box, peer-to-peer over WireGuard.
"""
from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage


def send_external(
    to: str,
    subject: str,
    body: str,
    *,
    from_addr: str,
    smtp_host: str,
    smtp_port: int = 587,
    username: str | None = None,
    password: str | None = None,
    use_tls: bool = True,
    timeout: float = 20.0,
) -> dict:
    """Send a normal email to an external address via SMTP submission.

    Credentials are used for this single call and never persisted. Caveats the
    caller must accept: this leaves the sovereign envelope (the relay sees the
    plaintext), and a residential IP often has port 25/587 blocked or its mail
    spam-filtered (DKIM/SPF live with the sending domain, not here).
    """
    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)

    if (username or password) and not use_tls:
        raise ValueError("refusing to send SMTP credentials without TLS (set use_tls=True)")
    with smtplib.SMTP(smtp_host, smtp_port, timeout=timeout) as server:
        if use_tls:
            server.starttls(context=ssl.create_default_context())  # verified TLS
        if username and password:
            server.login(username, password)
        server.send_message(msg)
    return {"sent": True, "to": to, "via": f"{smtp_host}:{smtp_port}"}


def receive_external_status() -> dict:
    """Honest statement of what receiving external mail requires (not a capability)."""
    return {
        "supported": False,
        "reason": "Receiving external mail needs IMAP/POP (excluded) OR your own MX "
                  "server (registered domain + publicly-reachable SMTP host).",
        "sovereign_alternative": "@sovereign.dmn mesh mail (mail.py / mesh_mail.py)",
    }
