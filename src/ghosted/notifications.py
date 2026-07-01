"""
Ghosted — optional notifications.

Notifications are OPT-IN: nothing is shown unless the account holder has turned them on
in preferences, and they choose which kinds (health / mail / suggestions). They are
PERSONAL — only surfaced to the signed-in account holder (website) or at the machine
(console). Built live from current state, so there's no background daemon; a small
dismiss list keeps acknowledged items from reappearing.

Pure-Python, zero deps, never raises.
"""

from __future__ import annotations

import os
from typing import Any


def _dismiss_path() -> str:
    try:
        from ghosted.mail import _data_root

        return os.path.join(_data_root(), "notifications_dismissed.json")
    except Exception:
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        d = os.path.join(base, "Ghosted")
        os.makedirs(d, exist_ok=True)
        return os.path.join(d, "notifications_dismissed.json")


def _dismissed() -> set[str]:
    try:
        import json

        with open(_dismiss_path(), encoding="utf-8") as fh:
            return set(json.load(fh))
    except Exception:
        return set()


def dismiss(note_id: str) -> None:
    if not note_id:
        return
    try:
        from ghosted.mail import atomic_write_json

        ids = _dismissed()
        ids.add(note_id)
        atomic_write_json(_dismiss_path(), sorted(ids))
        _invalidate()  # next collect() recomputes without the dismissed item
    except Exception:
        pass


def clear_dismissed() -> None:
    try:
        from ghosted.mail import atomic_write_json

        atomic_write_json(_dismiss_path(), [])
    except Exception:
        pass


def _health_notes(prefs) -> list[dict]:
    if not prefs.get("notify_health"):
        return []
    out = []
    try:
        from ghosted import health

        snap = health.snapshot()
        for key, label in (("cpu", "CPU"), ("memory", "Memory"), ("disk", "Disk"), ("battery", "Battery")):
            m = snap.get(key, {})
            st = m.get("state")
            if st in ("warn", "critical"):
                val = m.get("percent")
                out.append({
                    "id": f"health:{key}:{st}",
                    "kind": "health",
                    "level": st,
                    "text": f"{label} {st}" + (f" at {val}%" if val is not None else ""),
                })
    except Exception:
        pass
    return out


def _mail_notes(prefs) -> list[dict]:
    if not prefs.get("notify_mail"):
        return []
    try:
        from ghosted import mail

        n = len(mail.inbox())
        if n:
            return [{
                "id": f"mail:count:{n}",
                "kind": "mail",
                "level": "info",
                "text": f"{n} message{'s' if n != 1 else ''} in your black-box inbox",
            }]
    except Exception:
        pass
    return []


def _suggestion_notes(prefs) -> list[dict]:
    if not prefs.get("notify_suggestions"):
        return []
    try:
        from ghosted import feedback

        s = feedback.summary()
        out = []
        # surface the single most-engaged learned result as a gentle suggestion
        top = (s.get("top_results") or [])
        if top:
            t = top[0]
            out.append({
                "id": f"suggest:top:{t.get('url','')}",
                "kind": "suggestion",
                "level": "info",
                "text": f"You return to “{t.get('query','')}” — Ghosted is ranking its best result higher.",
            })
        return out
    except Exception:
        return []


# Cache the computed notifications briefly. Building them touches health (a CPU sample
# + egress lookup) and the mailbox, so without this the notification BELL would pay that
# cost on every single page render for a signed-in user. 25s is fresh enough for a badge.
_CACHE: dict[str, Any] = {"at": 0.0, "notes": []}
_CACHE_TTL = 25.0


def _invalidate() -> None:
    _CACHE["at"] = 0.0


def collect() -> list[dict[str, Any]]:
    """The account holder's current notifications, honouring their opt-in choices."""
    import time

    now = time.time()
    if now - _CACHE["at"] < _CACHE_TTL:
        return _CACHE["notes"]
    try:
        from ghosted import preferences

        prefs = preferences.all()
    except Exception:
        return []
    if not prefs.get("notifications"):
        _CACHE.update(at=now, notes=[])
        return []  # master switch is off — notifications are optional
    notes = _health_notes(prefs) + _mail_notes(prefs) + _suggestion_notes(prefs)
    dis = _dismissed()
    result = [n for n in notes if n["id"] not in dis]
    _CACHE.update(at=now, notes=result)
    return result


def count() -> int:
    return len(collect())
