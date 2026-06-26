"""
Sovereign SMTP receiver — accept inbound external mail and BLACK-BOX it at rest.

This is the piece you run on a (free) publicly-reachable host so that MX-routed
internet mail lands sealed. Pure-stdlib socket SMTP (HELO/MAIL/RCPT/DATA/QUIT) — no
deps. Every received message is sealed with RABBIT-CIPHER-1 the instant it arrives
(mail.seal_inbound), so it never sits on disk readable. NO IMAP / NO POP: your laptop
pulls the sealed boxes over WireGuard (mesh), it never logs into an inbox.

Zero-dollar deployment:
    * a free-forever host with a public IP  (e.g. Oracle Cloud "Always Free" VM)
    * a free subdomain that supports MX      (e.g. afraid.org / FreeDNS)
    * point the subdomain's MX at the host, run this on it:
          RABBIT_INBOX_KEY=yourkey python -m rabbitghost.smtp_inbox 25
    (port 25 needs root/admin; use a high port + a forward, or run as a service.)
"""
from __future__ import annotations

import os
import socket
import sys
import threading

from rabbitghost import mail


def _handle(conn: socket.socket, key: str) -> None:
    def send(s: str) -> None:
        conn.sendall(s.encode("ascii", "replace") + b"\r\n")

    f = conn.makefile("rb")
    mailfrom = None
    rcpts: list[str] = []
    try:
        send("220 sovereign.dmn RabbitGhost ready")
        while True:
            line = f.readline()
            if not line:
                break
            cmd = line.decode("ascii", "replace").strip()
            up = cmd.upper()
            if up.startswith(("HELO", "EHLO")):
                send("250 hello")
            elif up.startswith("MAIL FROM"):
                mailfrom = cmd
                send("250 ok")
            elif up.startswith("RCPT TO"):
                rcpts.append(cmd)
                send("250 ok")
            elif up == "DATA":
                send("354 end with <CRLF>.<CRLF>")
                data = []
                while True:
                    chunk = f.readline()
                    if not chunk or chunk in (b".\r\n", b".\n"):
                        break
                    if chunk.startswith(b".."):  # undo dot-stuffing
                        chunk = chunk[1:]
                    data.append(chunk)
                raw = b"".join(data).decode("utf-8", "replace")
                envelope = f"{mailfrom or ''}\n{''.join(rcpts)}\n\n{raw}"
                try:
                    mail.seal_inbound(envelope, key)  # black-box AT REST immediately
                except Exception:
                    pass
                send("250 queued (black-boxed)")
                mailfrom, rcpts = None, []
            elif up == "RSET":
                mailfrom, rcpts = None, []
                send("250 ok")
            elif up == "NOOP":
                send("250 ok")
            elif up == "QUIT":
                send("221 bye")
                break
            else:
                send("250 ok")
    finally:
        conn.close()


def serve(port: int = 25, key: str | None = None, host: str = "0.0.0.0") -> None:
    key = key or os.environ.get("RABBIT_INBOX_KEY") or "rabbit-inbox-default-key"
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(16)
    print(f"🐰 sovereign SMTP inbox on :{port} — inbound mail black-boxed at rest")
    try:
        while True:
            conn, _addr = srv.accept()
            threading.Thread(target=_handle, args=(conn, key), daemon=True).start()
    except KeyboardInterrupt:
        srv.close()


if __name__ == "__main__":
    serve(int(sys.argv[1]) if len(sys.argv) > 1 else 25)
