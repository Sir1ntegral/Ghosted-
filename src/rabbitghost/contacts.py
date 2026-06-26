"""
Contact list — names <-> addresses (sovereign or external), persisted locally.

Bare names qualify to @sovereign.dmn (mail.address); addresses with an @ are kept
as-is (any provider). resolve() turns a known name into its address for composing.
"""
from __future__ import annotations

import json
import os

from rabbitghost import mail


def _path() -> str:
    return os.path.join(mail._data_root(), "contacts.json")


def _load() -> list:
    try:
        with open(_path(), encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return []


def _save(cs: list) -> None:
    mail.atomic_write_json(_path(), cs)  # crash-safe (temp + fsync + os.replace)


def add_contact(name: str, address: str, *, tags=None, note: str = "") -> dict:
    name = (name or "").strip()
    if not name:
        raise ValueError("name required")
    address = mail.address((address or "").strip())  # qualify bare -> @sovereign.dmn
    cs = [c for c in _load() if c["address"].lower() != address.lower()]  # replace dup
    contact = {"name": name, "address": address, "tags": list(tags or []), "note": note}
    cs.append(contact)
    _save(cs)
    return contact


def remove_contact(address: str) -> bool:
    addr = mail.address((address or "").strip()).lower()
    cs = _load()
    kept = [c for c in cs if c["address"].lower() != addr]
    if len(kept) != len(cs):
        _save(kept)
        return True
    return False


def contacts() -> list:
    return _load()


def find(query: str) -> list:
    q = (query or "").lower()
    return [c for c in _load() if q in c["name"].lower() or q in c["address"].lower()]


def resolve(name_or_addr: str) -> str:
    """A known contact name -> its address; otherwise qualify the input as an address."""
    s = (name_or_addr or "").strip()
    for c in _load():
        if c["name"].lower() == s.lower():
            return c["address"]
    return mail.address(s)
