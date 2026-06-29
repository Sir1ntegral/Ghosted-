"""
Transport resilience — multi-port egress + store-and-forward spool.

Pure-Python (socket / json / os): the parts of "works no matter what" that need
NO external pluggable-transport binaries.

  * multi-port egress — a dead/blocked port isn't fatal. Probe a candidate list and
    use the first that connects (for reaching a Rabbit peer or proxy on
    443 / 80 / 853 / 8443 / 9001 / ...).
  * store-and-forward — when there is no path NOW, an operation is spooled to disk
    and auto-flushed the instant connectivity returns; it completes later, not never.

True obfs4 / snowflake / meek bridges need external PT binaries + bridge infra and
are out of scope for this pure-software module (see task #12 notes).
"""

from __future__ import annotations

import json
import os
import secrets
import socket
import time
from typing import Callable

COMMON_PORTS = (443, 80, 8443, 8080, 853, 9001, 9050)


def port_reachable(host: str, port: int, timeout: float = 3.0) -> bool:
    """True if a TCP connection to host:port succeeds within timeout."""
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except Exception:
        return False


def first_open_port(host: str, ports=COMMON_PORTS, timeout: float = 3.0):
    """First reachable port from the candidate list — so a dead port isn't fatal."""
    for p in ports:
        if port_reachable(host, p, timeout):
            return p
    return None


def online(
    probes=(("1.1.1.1", 443), ("8.8.8.8", 53), ("9.9.9.9", 443)), timeout: float = 3.0
) -> bool:
    """Any sliver of connectivity? True if ANY probe host:port connects."""
    return any(port_reachable(h, p, timeout) for h, p in probes)


def _spool_dir(name: str) -> str:
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    d = os.path.join(base, "Ghosted", "spool", name)
    os.makedirs(d, exist_ok=True)
    return d


class Spool:
    """A persistent store-and-forward outbox. Items survive restarts. flush() sends
    each via a caller-supplied dispatch and removes ONLY those that succeed — so a
    half-online flush loses nothing."""

    def __init__(self, name: str = "outbox") -> None:
        self._dir = _spool_dir(name)

    def _path(self, jid: str) -> str:
        return os.path.join(self._dir, jid + ".job")

    def enqueue(self, payload: dict) -> str:
        jid = f"{int(time.time() * 1000)}-{secrets.token_hex(4)}"
        with open(self._path(jid), "w", encoding="utf-8") as fh:
            json.dump({"id": jid, "ts": int(time.time()), "payload": payload}, fh)
        return jid

    def pending(self) -> list:
        out = []
        for fn in sorted(os.listdir(self._dir)):
            if fn.endswith(".job"):
                try:
                    with open(os.path.join(self._dir, fn), encoding="utf-8") as fh:
                        out.append(json.load(fh))
                except Exception:
                    pass
        return out

    def __len__(self) -> int:
        return sum(1 for f in os.listdir(self._dir) if f.endswith(".job"))

    def flush(self, send: Callable[[dict], bool], *, check_online: bool = True) -> dict:
        """Attempt delivery. `send(payload) -> bool`. If offline, keep everything and
        report; otherwise remove only the items `send` confirms (True)."""
        if check_online and not online():
            return {"sent": 0, "kept": len(self), "offline": True}
        sent = kept = 0
        for job in self.pending():
            try:
                ok = bool(send(job["payload"]))
            except Exception:
                ok = False
            if ok:
                try:
                    os.remove(self._path(job["id"]))
                    sent += 1
                except Exception:
                    kept += 1
            else:
                kept += 1
        return {"sent": sent, "kept": kept, "offline": False}
