"""
Ghosted — sovereign security event bus. Pure-Python pub/sub + JSONL audit, zero deps.

One verb: ``announce(event)``. Every security-relevant thing that happens (a Gojo
boundary decision, a WireGuard tunnel coming up, a deny-streak) is announced here;
subscribers react, and every event is also appended to a JSONL audit log and kept in
a bounded in-memory ring buffer for the console/health view.

Decoupled from rabbit — Ghosted is a standalone tool, so it carries its own bus rather
than summoning Rabbit's event chain. Thread-safe; announce() never raises, so the bus
can never break the action that emitted the event.
"""

from __future__ import annotations

import json
import os
import threading
import time
from collections import deque
from typing import Any, Callable

__all__ = ["announce", "subscribe", "unsubscribe", "recent", "audit_path"]

_LOCK = threading.RLock()
_SUBSCRIBERS: list[Callable[[dict], None]] = []
_RECENT: deque = deque(maxlen=512)  # ring buffer of recent events for quick inspection
_MAX_LOG_BYTES = 5 * 1024 * 1024  # rotate the JSONL audit log once it passes 5 MB


def _rotate_if_needed(path: str) -> None:
    """Keep the audit log bounded: past the size cap, roll it to <path>.1 (one previous
    generation kept) so it never grows without limit. Best-effort, never raises."""
    try:
        if os.path.getsize(path) < _MAX_LOG_BYTES:
            return
    except OSError:
        return
    try:
        bak = path + ".1"
        if os.path.exists(bak):
            os.remove(bak)
        os.replace(path, bak)
    except OSError:
        pass


def audit_path() -> str:
    """Path to the JSONL security audit log (created on first write)."""
    try:
        from ghosted.mail import _data_root

        d = os.path.join(_data_root(), "logs")
    except Exception:
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        d = os.path.join(base, "Ghosted", "logs")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, "security_events.jsonl")


def subscribe(fn: Callable[[dict], None]) -> Callable[[dict], None]:
    """Register a subscriber called with each announced event. Idempotent."""
    with _LOCK:
        if fn not in _SUBSCRIBERS:
            _SUBSCRIBERS.append(fn)
    return fn


def unsubscribe(fn: Callable[[dict], None]) -> None:
    with _LOCK:
        if fn in _SUBSCRIBERS:
            _SUBSCRIBERS.remove(fn)


def recent(limit: int = 50) -> list[dict]:
    """The most recent announced events (newest last), up to *limit*."""
    with _LOCK:
        items = list(_RECENT)
    return items[-limit:] if limit and limit > 0 else items


def announce(event: dict) -> dict:
    """Publish one security event.

    Stamps ts/severity if absent, ring-buffers it, appends it to the JSONL audit log,
    then fans out to every subscriber. Never raises — a broken subscriber or unwritable
    log must not break the action that announced the event.
    """
    ev: dict[str, Any] = dict(event)
    ev.setdefault("ts", time.time())
    ev.setdefault("severity", "info")
    with _LOCK:
        _RECENT.append(ev)
        subs = list(_SUBSCRIBERS)
    try:
        p = audit_path()
        _rotate_if_needed(p)
        with open(p, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(ev, ensure_ascii=False) + "\n")
    except Exception:  # noqa: BLE001 — audit is best-effort, never blocks
        pass
    for fn in subs:
        try:
            fn(ev)
        except Exception:  # noqa: BLE001 — one bad subscriber can't sink the bus
            pass
    return ev
