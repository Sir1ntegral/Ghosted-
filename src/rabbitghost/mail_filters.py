"""
Mail filters — local rules that tag / star / block / route mail.

A rule matches a message field (from/to/subject/body) by contains/equals/regex and
applies an action (tag/star/block/folder). apply_filters() evaluates all rules over a
decrypted message dict and returns the combined verdict. Sovereign + local; the caller
decides when to run them (on receive, or when listing).
"""
from __future__ import annotations

import json
import os
import re

from rabbitghost import mail

_FIELDS = ("from", "to", "subject", "body")
_OPS = ("contains", "equals", "regex")
_ACTIONS = ("tag", "star", "block", "folder")


def _path() -> str:
    return os.path.join(mail._data_root(), "filters.json")


def _load() -> list:
    try:
        with open(_path(), encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return []


def _save(fs: list) -> None:
    mail.atomic_write_json(_path(), fs)  # crash-safe — block-rules never silently vanish


def add_filter(field: str, op: str, value: str, action: str, *, arg: str = "", name: str = "") -> dict:
    field, op, action = field.lower(), op.lower(), action.lower()
    if field not in _FIELDS:
        raise ValueError(f"field must be one of {_FIELDS}")
    if op not in _OPS:
        raise ValueError(f"op must be one of {_OPS}")
    if action not in _ACTIONS:
        raise ValueError(f"action must be one of {_ACTIONS}")
    rule = {"name": name or f"{field}-{op}-{value}", "field": field, "op": op,
            "value": value, "action": action, "arg": arg}
    fs = _load()
    fs.append(rule)
    _save(fs)
    return rule


def remove_filter(name: str) -> bool:
    fs = _load()
    kept = [f for f in fs if f["name"] != name]
    if len(kept) != len(fs):
        _save(kept)
        return True
    return False


def filters() -> list:
    return _load()


def _match(rule: dict, msg: dict) -> bool:
    # Bound the regex input — a user's filter regex on attacker-controlled mail body
    # could otherwise backtrack catastrophically (ReDoS). Capped input = bounded time.
    hay = str(msg.get(rule["field"], "") or "")[:100_000]
    val = rule["value"]
    op = rule["op"]
    if op == "contains":
        return val.lower() in hay.lower()
    if op == "equals":
        return hay.lower() == val.lower()
    if op == "regex":
        try:
            return re.search(val, hay, re.IGNORECASE) is not None
        except Exception:
            return False
    return False


def apply_filters(msg: dict) -> dict:
    """Evaluate every rule over a decrypted message. Returns combined actions."""
    result = {"tags": [], "starred": False, "blocked": False, "folder": None}
    for rule in _load():
        if _match(rule, msg):
            a = rule["action"]
            if a == "tag":
                result["tags"].append(rule.get("arg") or rule["value"])
            elif a == "star":
                result["starred"] = True
            elif a == "block":
                result["blocked"] = True
            elif a == "folder":
                result["folder"] = rule.get("arg") or "filtered"
    return result
