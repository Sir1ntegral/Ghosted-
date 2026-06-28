"""
Sovereign SMTP receiver — accept inbound external mail and BLACK-BOX it at rest.

Run on a (free) publicly-reachable host so MX-routed internet mail lands sealed.
Pure-stdlib socket SMTP — no deps. Every message is sealed with RABBIT-CIPHER-1 the
instant it arrives (mail.seal_inbound), so it never sits readable. NO IMAP/POP: the
laptop pulls the sealed boxes over WireGuard.

Hardened: bounded DATA buffering, per-line caps, socket timeout, bounded concurrency,
fail-CLOSED on seal failure (451 retry, never a false ACK), and it refuses to start
without an explicit key (no inbound mail sealed under a shared default).

    RABBIT_INBOX_KEY=yourkey python -m ghosted.smtp_inbox 25
"""

from __future__ import annotations

import os
import socket
import sys
import threading

from ghosted import mail

_MAX_BYTES = int(
    os.environ.get("RABBIT_INBOX_MAX_BYTES", str(25 * 1024 * 1024))
)  # 25MB/msg
_MAX_LINE = 8192
_TIMEOUT = 30  # slowloris / idle-peer guard
_MAX_CONN = 64  # bound thread fan-out
_sem = threading.BoundedSemaphore(_MAX_CONN)


def _accept_ip(ip: str) -> bool:
    return ip.startswith("127.") or ip.startswith("10.44.")


def _handle(conn: socket.socket, key: str) -> None:
    def send(s: str) -> None:
        conn.sendall(s.encode("ascii", "replace") + b"\r\n")

    conn.settimeout(_TIMEOUT)
    f = conn.makefile("rb")
    mailfrom, rcpts = None, []
    try:
        send("220 sovereign.dmn Ghosted ready")
        while True:
            line = f.readline(_MAX_LINE + 1)
            if not line:
                break
            if len(line) > _MAX_LINE:
                send("500 line too long")
                break
            cmd = line.decode("ascii", "replace").strip()
            up = cmd.upper()
            if up.startswith(("HELO", "EHLO")):
                send("250 hello")
            elif up.startswith("MAIL FROM"):
                mailfrom = cmd
                send("250 ok")
            elif up.startswith("RCPT TO"):
                if len(rcpts) >= 100:
                    send("452 too many recipients")
                else:
                    rcpts.append(cmd)
                    send("250 ok")
            elif up == "DATA":
                send("354 end with <CRLF>.<CRLF>")
                data, total, overflow = [], 0, False
                while True:
                    chunk = f.readline(_MAX_LINE + 1)
                    if not chunk or chunk in (b".\r\n", b".\n"):
                        break
                    if chunk.startswith(b".."):
                        chunk = chunk[1:]
                    total += len(chunk)
                    if total > _MAX_BYTES:
                        overflow = True  # keep draining to the terminator, but drop
                        continue
                    data.append(chunk)
                if overflow:
                    send("552 message too large")
                    mailfrom, rcpts = None, []
                    continue
                raw = b"".join(data).decode("utf-8", "replace")
                envelope = f"{mailfrom or ''}\n{''.join(rcpts)}\n\n{raw}"
                try:
                    mail.seal_inbound(envelope, key)  # black-box AT REST immediately
                    send("250 queued (black-boxed)")
                except Exception as e:  # noqa: BLE001 — fail CLOSED, never false-ACK
                    print(
                        f"[smtp_inbox] seal failed, asking sender to retry: {type(e).__name__}",
                        file=sys.stderr,
                    )
                    send("451 4.3.0 temporary failure, retry later")
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
    except (socket.timeout, OSError):
        pass
    finally:
        conn.close()


def _wrap(conn: socket.socket, key: str) -> None:
    try:
        _handle(conn, key)
    finally:
        _sem.release()


def serve(port: int = 25, key: str | None = None, host: str = "0.0.0.0") -> None:
    key = key or os.environ.get("RABBIT_INBOX_KEY")
    if not key:
        raise SystemExit(
            "refusing to start: set RABBIT_INBOX_KEY "
            "(inbound mail must not be sealed under a shared default key)"
        )
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if os.name == "nt":  # Windows: exclusive bind, no hijack
        try:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        except Exception:
            pass
    else:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(64)
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    print(f"sovereign SMTP inbox on :{port} - inbound mail black-boxed at rest")
    try:
        while True:
            conn, _addr = srv.accept()
            if not _sem.acquire(blocking=False):
                try:
                    conn.sendall(b"421 too busy\r\n")
                    conn.close()
                except Exception:
                    pass
                continue
            threading.Thread(target=_wrap, args=(conn, key), daemon=True).start()
    except KeyboardInterrupt:
        srv.close()


if __name__ == "__main__":
    serve(int(sys.argv[1]) if len(sys.argv) > 1 else 25)
