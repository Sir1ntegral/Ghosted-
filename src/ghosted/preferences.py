"""
Ghosted — per-account-holder preferences.

Lets the account holder customize their personal experience: accent theme, whether
notifications are on (they are OPT-IN / optional), which notification kinds to receive,
voice auto-read, and whether to show the relevance badges. Pure-Python, zero deps.

Preferences are personal data — they live in %LOCALAPPDATA%/Ghosted/preferences.json
and the website only reads/writes them for the signed-in account holder. Unknown keys
are rejected and every value is validated, so a bad write can never corrupt the store.
"""

from __future__ import annotations

import os
from typing import Any

# Accent palette → CSS color. Personalises the homepage for the account holder.
ACCENTS = {
    "violet": "#9aa9ff",
    "blue": "#6db3ff",
    "green": "#7bd88f",
    "amber": "#ffcf6b",
    "rose": "#ff8aa0",
    "slate": "#aab3c5",
}

DEFAULTS: dict[str, Any] = {
    "display_name": "",
    "accent": "violet",
    "notifications": False,        # OPT-IN — off until the account holder enables it
    "notify_health": True,         # which kinds (only active when notifications is on)
    "notify_mail": True,
    "notify_suggestions": True,
    "voice_autoread": False,
    "show_badges": True,
}

_BOOL_KEYS = {
    "notifications",
    "notify_health",
    "notify_mail",
    "notify_suggestions",
    "voice_autoread",
    "show_badges",
}


def _path() -> str:
    try:
        from ghosted.mail import _data_root

        return os.path.join(_data_root(), "preferences.json")
    except Exception:
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        d = os.path.join(base, "Ghosted")
        os.makedirs(d, exist_ok=True)
        return os.path.join(d, "preferences.json")


def all() -> dict[str, Any]:
    """Every preference, defaults filled in for anything not yet set."""
    prefs = dict(DEFAULTS)
    try:
        import json

        with open(_path(), encoding="utf-8") as fh:
            disk = json.load(fh)
        if isinstance(disk, dict):
            for k, v in disk.items():
                if k in DEFAULTS:
                    prefs[k] = v
    except Exception:
        pass
    return prefs


def get(key: str, default: Any = None) -> Any:
    return all().get(key, DEFAULTS.get(key, default))


def _coerce(key: str, value: Any) -> Any:
    if key in _BOOL_KEYS:
        if isinstance(value, str):
            return value.strip().lower() in ("1", "true", "on", "yes", "y")
        return bool(value)
    if key == "accent":
        v = str(value).strip().lower()
        return v if v in ACCENTS else DEFAULTS["accent"]
    if key == "display_name":
        return str(value).strip()[:60]
    return value


def set(key: str, value: Any) -> dict[str, Any]:
    """Set one preference (validated). Unknown keys are ignored, never stored."""
    if key not in DEFAULTS:
        return all()
    prefs = all()
    prefs[key] = _coerce(key, value)
    _save(prefs)
    return prefs


def update(values: dict[str, Any]) -> dict[str, Any]:
    """Set many at once (e.g. from the website preferences form)."""
    prefs = all()
    for k, v in (values or {}).items():
        if k in DEFAULTS:
            prefs[k] = _coerce(k, v)
    _save(prefs)
    return prefs


def reset() -> dict[str, Any]:
    _save(dict(DEFAULTS))
    return dict(DEFAULTS)


def accent_color() -> str:
    """The account holder's chosen accent as a CSS color (personalisation)."""
    return ACCENTS.get(get("accent"), ACCENTS["violet"])


def _save(prefs: dict[str, Any]) -> None:
    try:
        from ghosted.mail import atomic_write_json

        atomic_write_json(_path(), {k: prefs.get(k, DEFAULTS[k]) for k in DEFAULTS})
    except Exception:
        try:
            import json

            with open(_path(), "w", encoding="utf-8") as fh:
                json.dump(prefs, fh)
        except Exception:
            pass
