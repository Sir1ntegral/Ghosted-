"""
Store-and-forward flusher — completes spooled work the instant connectivity returns.

The spools (sovereign fetch + mesh mail) persist intents while offline; this wires
them to actual dispatch and runs an opt-in background loop so queued operations
auto-complete later, not never. Both the console and the homepage start it at boot.
"""

from __future__ import annotations

import threading

from ghosted import connectivity, mesh_mail, transport


def flush_all() -> dict:
    """Flush every outbound spool once. No-ops (reports offline) when there is no link."""
    if not transport.online():
        return {"online": False}
    return {
        "online": True,
        "mesh_mail": mesh_mail.flush_outbound(),
        "fetch": connectivity.flush_fetch(),
    }


_AUTO_THREAD: threading.Thread | None = None
_AUTO_STOP = threading.Event()
_AUTO_LOCK = threading.Lock()


def start_autoflush(interval: float = 30.0) -> bool:
    """Start a daemon that flushes the spools whenever connectivity is up. Idempotent —
    returns True if it started a thread, False if one was already running."""
    global _AUTO_THREAD
    with _AUTO_LOCK:
        if _AUTO_THREAD is not None and _AUTO_THREAD.is_alive():
            return False
        _AUTO_STOP.clear()

        def _loop() -> None:
            while not _AUTO_STOP.wait(interval):
                try:
                    if transport.online():
                        flush_all()
                except Exception:
                    pass  # a flush must never kill the daemon

        _AUTO_THREAD = threading.Thread(
            target=_loop, name="ghosted-autoflush", daemon=True
        )
        _AUTO_THREAD.start()
        return True


def stop_autoflush() -> None:
    """Signal the background flusher to stop (best-effort; it is a daemon)."""
    _AUTO_STOP.set()
