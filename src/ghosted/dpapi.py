"""
Ghosted — Windows DPAPI wrapper (user-bound encryption, zero deps).

Wraps CryptProtectData / CryptUnprotectData via ctypes so a small secret (the mailbox
passphrase, only for a "stay logged in" session) can be sealed at rest bound to the
CURRENT Windows user on THIS machine — decryptable only by the same user, with no key
to store anywhere. Domain-separated with app entropy so only Ghosted's own blobs open.

Fail-soft: on non-Windows, or if the API is unavailable, protect()/unprotect() return
None and the caller falls back to re-entering the passphrase (the secure default). This
is opt-in via "stay logged in"; the passphrase is never written in the clear.
"""

from __future__ import annotations

import ctypes
import os
from ctypes import wintypes

__all__ = ["available", "protect", "unprotect"]

_ENTROPY = b"ghosted:dpapi:mailkey:v1"  # app domain separation


class _Blob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def available() -> bool:
    """True only where DPAPI can be used (Windows with crypt32)."""
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.crypt32)
    except Exception:
        return False


def _mk_blob(data: bytes) -> _Blob:
    buf = ctypes.create_string_buffer(bytes(data), len(data))
    return _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))


def _run(fn, data: bytes) -> bytes | None:
    in_blob = _mk_blob(data)
    ent_blob = _mk_blob(_ENTROPY)
    out_blob = _Blob()
    try:
        ok = fn(
            ctypes.byref(in_blob), None, ctypes.byref(ent_blob),
            None, None, 0, ctypes.byref(out_blob),
        )
    except Exception:
        return None
    if not ok:
        return None
    try:
        out = ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        try:
            ctypes.windll.kernel32.LocalFree(out_blob.pbData)
        except Exception:
            pass
    return out


def protect(data: bytes) -> bytes | None:
    """Seal *data* bound to the current Windows user, or None if DPAPI is unavailable."""
    if not available():
        return None
    return _run(ctypes.windll.crypt32.CryptProtectData, data)


def unprotect(blob: bytes) -> bytes | None:
    """Open a blob produced by protect(), or None if it can't be decrypted here."""
    if not available():
        return None
    return _run(ctypes.windll.crypt32.CryptUnprotectData, blob)
