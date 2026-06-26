"""
Mesh delivery — move @sovereign.dmn black-box mail between peers over WireGuard.

The message is already a RABBIT-CIPHER-1 black box, so transport is opaque end-to-end
AND it rides the authenticated WireGuard tunnel. A peer runs ``receiver()``; ``send_to``
delivers it (multi-port — a dead port isn't fatal), spooling for store-and-forward if
the peer is offline so it completes the instant the peer returns.

Run a receiver:   python -m rabbitghost.mesh_mail [port]
"""
from __future__ import annotations

import http.client
import os
import secrets
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from rabbitghost import mail, transport

INBOX_PORT = 8765
_MAX_TOKEN = 256 * 1024  # one sealed message; cap to stop abuse


def _accept_ip(ip: str) -> bool:
    # Accept only loopback + the WireGuard mesh subnet. The token is encrypted
    # regardless, but this keeps the inbox off the open internet.
    return ip.startswith("127.") or ip.startswith("10.44.")


def _store(token: str) -> str:
    path = os.path.join(mail._mailbox_dir(), f"{int(time.time() * 1000)}-{secrets.token_hex(4)}.box")
    with open(path, "w", encoding="ascii") as fh:
        fh.write(token)
    return path


class _Inbox(BaseHTTPRequestHandler):
    timeout = 30  # slowloris guard — socketserver applies this to the request socket

    def do_POST(self) -> None:  # noqa: N802
        ip = self.client_address[0] if self.client_address else ""
        if not _accept_ip(ip):
            self.send_response(403)
            self.end_headers()
            return
        if urlparse(self.path).path != "/inbox":
            self.send_response(404)
            self.end_headers()
            return
        try:
            length = int(self.headers.get("Content-Length", "0") or 0)
        except ValueError:
            self.send_response(400)
            self.end_headers()
            return
        if length > _MAX_TOKEN:
            self.send_response(413)
            self.end_headers()
            return
        raw = self.rfile.read(length) if length else b""
        try:
            token = raw.decode("ascii")  # valid black-box tokens are base64 ASCII
        except UnicodeDecodeError:
            self.send_response(400)       # non-ASCII junk → reject (was a write crash)
            self.end_headers()
            return
        _store(token)  # store the opaque black box; only the key-holder can open it
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):  # quiet
        pass


def receiver(port: int = INBOX_PORT) -> None:
    """Run the mesh inbox — accepts black-box mail from WireGuard peers, stores it."""
    httpd = ThreadingHTTPServer(("0.0.0.0", port), _Inbox)
    print(f"🐰 mesh inbox on :{port} — accepting black-box mail from loopback + 10.44.* peers")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


def _post_token(host: str, port: int, token: str, timeout: float = 8.0) -> bool:
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("POST", "/inbox", body=token.encode("ascii"),
                     headers={"Content-Type": "application/octet-stream",
                              "Content-Length": str(len(token))})
        resp = conn.getresponse()
        ok = resp.status == 200
        resp.read()
        return ok
    finally:
        conn.close()


def deliver(peer_host: str, token: str, *, port: int = INBOX_PORT, ports=None) -> dict:
    """Deliver a sealed token to a peer. Multi-port (a dead port isn't fatal); on any
    failure the token is spooled for store-and-forward retry."""
    candidates = ports or (port, 443, 80, 8443)
    open_port = next((p for p in candidates if transport.port_reachable(peer_host, p, 2.0)), None)
    if open_port is not None:
        try:
            if _post_token(peer_host, open_port, token):
                return {"delivered": True, "port": open_port}
        except Exception:
            pass
    jid = transport.Spool("mesh_mail").enqueue({"peer": peer_host, "port": port, "token": token})
    return {"delivered": False, "spooled": jid}


def send_to(peer_host: str, to: str, subject: str, body: str, passphrase: str,
            *, sender: str = "me", port: int = INBOX_PORT) -> dict:
    """Compose a black box and deliver it to a peer over the mesh (spool if offline)."""
    token = mail.compose(to, subject, body, passphrase, sender=sender)
    return deliver(peer_host, token, port=port)


def flush_outbound() -> dict:
    """Retry spooled mesh mail to peers — completes deliveries when peers return."""
    sp = transport.Spool("mesh_mail")

    def _send(payload: dict) -> bool:
        try:
            return _post_token(payload["peer"], payload.get("port", INBOX_PORT), payload["token"])
        except Exception:
            return False

    # check_online=False: mesh peers may be reachable on a LAN with NO public internet
    # (the whole point of the mesh) — gate per-peer in _send, not on public probes.
    return sp.flush(_send, check_online=False)


if __name__ == "__main__":
    receiver(int(sys.argv[1]) if len(sys.argv) > 1 else INBOX_PORT)
