"""
Ghosted — sovereign two-factor authentication (required for account login).

Two means of identification:
  1. the master password  — something you KNOW (verified by the vault),
  2. a 6-digit time code   — something you HAVE (RFC 6238 TOTP from an authenticator).

Pure-Python (HMAC-SHA1 + base32), zero deps. The TOTP secret + recovery codes are
sealed under the master password (GHOSTED-CIPHER-1), so they're useless at rest.

Fail-soft parameters (so a small problem never hard-locks the account holder out):
  • code verification tolerates clock drift — ±1 time-step (30s) by default;
  • enrollment also issues one-time RECOVERY codes for a lost/!-syncing authenticator.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import time

_STEP = 30          # seconds per TOTP step
_DIGITS = 6
_WINDOW = 1         # ± steps tolerated — the fail-soft clock-drift allowance
_N_RECOVERY = 8


def _path() -> str:
    try:
        from ghosted.mail import _data_root

        return os.path.join(_data_root(), "twofactor.json")
    except Exception:
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        d = os.path.join(base, "Ghosted")
        os.makedirs(d, exist_ok=True)
        return os.path.join(d, "twofactor.json")


def _store() -> dict:
    try:
        with open(_path(), encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def _save(d: dict) -> None:
    try:
        from ghosted.mail import atomic_write_json

        atomic_write_json(_path(), d)
    except Exception:
        with open(_path(), "w", encoding="utf-8") as fh:
            json.dump(d, fh)


def is_enabled() -> bool:
    """True once the account holder has enrolled a second factor."""
    return bool(_store().get("blob"))


def _seal(obj, passphrase: str) -> str:
    from ghosted.crypto import encrypt

    return base64.b64encode(encrypt(json.dumps(obj), passphrase).to_bytes()).decode()


def _unseal(token: str, passphrase: str):
    from ghosted.crypto import EncryptedBlob, decrypt

    return json.loads(decrypt(EncryptedBlob.from_bytes(base64.b64decode(token)), passphrase))


def _b32_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def provisioning_uri(secret: str, account: str = "me", issuer: str = "Ghosted") -> str:
    """otpauth:// URI an authenticator app imports (Google Authenticator, Aegis, …)."""
    return (
        f"otpauth://totp/{issuer}:{account}?secret={secret}"
        f"&issuer={issuer}&algorithm=SHA1&digits={_DIGITS}&period={_STEP}"
    )


def enroll(passphrase: str, account: str = "me") -> dict:
    """Generate + seal a new TOTP secret and recovery codes. Returns the secret, the
    provisioning URI, and the one-time recovery codes to show the user ONCE."""
    secret = _b32_secret()
    recovery = [secrets.token_hex(5) for _ in range(_N_RECOVERY)]  # 10-char codes
    _save({"blob": _seal({"secret": secret, "recovery": recovery}, passphrase),
           "account": account})
    return {
        "secret": secret,
        "uri": provisioning_uri(secret, account),
        "recovery_codes": list(recovery),
    }


def disable(passphrase: str) -> bool:
    """Turn off 2FA. Requires the password (must be able to unseal) so a guest can't."""
    if not is_enabled():
        return True
    try:
        _unseal(_store()["blob"], passphrase)
    except Exception:
        return False
    try:
        os.remove(_path())
    except Exception:
        _save({})
    return True


def _totp(secret: str, t: float | None = None) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    counter = int((t if t is not None else time.time()) // _STEP)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** _DIGITS)
    return str(code).zfill(_DIGITS)


def verify(passphrase: str, code: str, window: int = _WINDOW) -> bool:
    """Verify a TOTP code OR a one-time recovery code. Not enrolled → True (no second
    factor required yet). Fail-soft: ±`window` steps tolerated; recovery codes accepted
    once each."""
    if not is_enabled():
        return True
    try:
        payload = _unseal(_store()["blob"], passphrase)
    except Exception:
        return False
    code = (code or "").strip().replace(" ", "").replace("-", "")
    if not code:
        return False
    # recovery-code path — one-time use, consumed on success (lost-authenticator escape)
    rec = payload.get("recovery", [])
    low = [r.lower() for r in rec]
    if code.lower() in low:
        payload["recovery"] = [r for r in rec if r.lower() != code.lower()]
        _save({"blob": _seal(payload, passphrase), "account": _store().get("account", "me")})
        return True
    if not code.isdigit():
        return False
    now = time.time()
    secret = payload.get("secret", "")
    return any(_totp(secret, now + w * _STEP) == code for w in range(-window, window + 1))


def current_code(passphrase: str) -> str | None:
    """The code right now (account holder only) — for console display / self-test."""
    if not is_enabled():
        return None
    try:
        return _totp(_unseal(_store()["blob"], passphrase)["secret"])
    except Exception:
        return None


def status() -> dict:
    s = _store()
    return {"enabled": bool(s.get("blob")), "account": s.get("account", "me")}
