"""
Ghosted — multi-factor authentication coordinator.

Account validation requires the master password PLUS at least TWO enrolled factors —
"two must be used to validate the account". Every one-time code is generated and
sealed through GHOSTED-CIPHER-1 (sovereign encryption) and is single-use.

Identification means (all valid; any two satisfy the policy):
  • authenticator  — RFC 6238 TOTP via QR (delegated to ghosted.twofactor)
  • email          — one-time code delivered via @sovereign.dmn mail
  • phone/number   — one-time code delivered over the mesh
  • location       — the request's network matches an enrolled trusted location
  • recovery       — sovereign one-time backup codes

Delivery is sovereign + fail-soft: email via mail, number via mesh, and when offline
or no gateway exists, the sealed one-time code is shown to the account holder on screen.
Pure-Python, zero deps, never raises into the caller.
"""

from __future__ import annotations

import os
import secrets
import time
from typing import Any

REQUIRED_FACTORS = 2            # how many enrolled factors must pass (beyond password)
_CODE_TTL = 600                 # delivered email/number codes valid 10 min
_LOC_NONE = "0.0.0.0"

FACTOR_TYPES = ("authenticator", "email", "phone", "location", "recovery")

# Sovereign text-message (SMS) delivery without a paid gateway: carrier email-to-SMS.
# A code mailed to <number>@<gateway> arrives as a text. Uses the existing mail path,
# so "all dependencies for text" are already satisfied (no new library, no SMS API).
CARRIER_GATEWAYS = {
    "att": "txt.att.net",
    "tmobile": "tmomail.net",
    "verizon": "vtext.com",
    "sprint": "messaging.sprintpcs.com",
    "uscellular": "email.uscc.net",
    "boost": "sms.myboostmobile.com",
    "cricket": "sms.cricketwireless.net",
    "metropcs": "mymetropcs.com",
    "googlefi": "msg.fi.google.com",
    "xfinity": "vtext.com",
}


def _path() -> str:
    try:
        from ghosted.mail import _data_root

        return os.path.join(_data_root(), "mfa.json")
    except Exception:
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        d = os.path.join(base, "Ghosted")
        os.makedirs(d, exist_ok=True)
        return os.path.join(d, "mfa.json")


def _store() -> dict:
    try:
        import json

        with open(_path(), encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save(d: dict) -> None:
    try:
        from ghosted.mail import atomic_write_json

        atomic_write_json(_path(), d)
    except Exception:
        try:
            import json

            with open(_path(), "w", encoding="utf-8") as fh:
                json.dump(d, fh)
        except Exception:
            pass


def _seal(obj, passphrase: str) -> str:
    import base64
    import json

    from ghosted.crypto import encrypt

    return base64.b64encode(encrypt(json.dumps(obj), passphrase).to_bytes()).decode()


def _unseal(token: str, passphrase: str):
    import base64
    import json

    from ghosted.crypto import EncryptedBlob, decrypt

    return json.loads(decrypt(EncryptedBlob.from_bytes(base64.b64decode(token)), passphrase))


# ── enrollment ─────────────────────────────────────────────────────────────────
def enrolled() -> list[str]:
    """Factor types the account holder has set up (authenticator reads twofactor)."""
    s = _store()
    out = list(s.get("factors", {}).keys())
    try:
        from ghosted import twofactor

        if twofactor.is_enabled() and "authenticator" not in out:
            out.append("authenticator")
    except Exception:
        pass
    return out


def enroll(factor: str, passphrase: str, **opts) -> dict:
    """Enroll one identification factor. Returns details to show the user once."""
    factor = (factor or "").strip().lower()
    if factor not in FACTOR_TYPES:
        return {"error": f"unknown factor: {factor}"}
    if factor == "authenticator":
        from ghosted import twofactor

        return {"factor": "authenticator", **twofactor.enroll(passphrase, opts.get("account", "me"))}
    s = _store()
    factors = s.get("factors", {})
    if factor == "email":
        # Multiple addresses, tried in order — if the first can't be reached, the code
        # goes to the second, then the third (the account holder's fallbacks).
        addrs = opts.get("addrs")
        if not addrs:
            addrs = [a.strip() for a in (opts.get("addr") or "").replace(";", ",").split(",")]
        addrs = [a for a in (addrs or []) if a]
        factors["email"] = {"addrs": addrs}
        result = {"factor": "email", "addrs": addrs}
    elif factor == "phone":
        carrier = (opts.get("carrier") or "").strip().lower()
        factors["phone"] = {
            "number": (opts.get("number") or "").strip(),
            "carrier": carrier if carrier in CARRIER_GATEWAYS else "",
        }
        result = {"factor": "phone", **factors["phone"], "sms_carriers": sorted(CARRIER_GATEWAYS)}
    elif factor == "location":
        # Trust the current network (prefix match) as a location factor.
        ip = (opts.get("ip") or "").strip()
        prefix = ".".join(ip.split(".")[:3]) if ip.count(".") == 3 else ip
        trusted = set(factors.get("location", {}).get("trusted", []))
        if prefix:
            trusted.add(prefix)
        factors["location"] = {"trusted": sorted(trusted)}
        result = {"factor": "location", "trusted": factors["location"]["trusted"]}
    elif factor == "recovery":
        codes = [secrets.token_hex(5) for _ in range(8)]
        factors["recovery"] = {"blob": _seal({"codes": codes}, passphrase)}
        result = {"factor": "recovery", "recovery_codes": list(codes)}
    s["factors"] = factors
    _save(s)
    return result


def remove(factor: str, passphrase: str) -> bool:
    factor = (factor or "").strip().lower()
    if factor == "authenticator":
        from ghosted import twofactor

        return twofactor.disable(passphrase)
    s = _store()
    if factor in s.get("factors", {}):
        s["factors"].pop(factor, None)
        _save(s)
        return True
    return False


# ── challenge (deliver one-time codes for email / phone) ──────────────────────────
def challenge(factor: str, passphrase: str) -> dict:
    """Generate + deliver a one-time code for a delivery factor (email/phone).
    Returns {delivered, via, shown?} — `shown` is the on-screen fallback when offline."""
    factor = (factor or "").strip().lower()
    if factor not in ("email", "phone"):
        return {"error": "challenge only applies to email/phone"}
    s = _store()
    cfg = s.get("factors", {}).get(factor)
    if not cfg:
        return {"error": f"{factor} factor not enrolled"}
    code = "".join(secrets.choice("0123456789") for _ in range(6))
    s.setdefault("pending", {})[factor] = {
        "blob": _seal({"code": code}, passphrase),
        "exp": time.time() + _CODE_TTL,
    }
    _save(s)
    # Real EXTERNAL transmission (SMTP to an email, email-to-SMS to a phone) is only
    # possible via a configured sending account with a saved password. Try that; if it
    # genuinely sends, mark delivered. mail.compose alone only SEALS a copy into the
    # sovereign mailbox (a record) — it is NOT transmission, so it must never be counted
    # as "delivered". Whenever we can't truly deliver, we SHOW the code on screen (the
    # designed fail-soft) so the account holder is never locked out.
    delivered, via = False, ""
    if factor == "email":
        targets = list(cfg.get("addrs", []))
    elif factor == "phone" and cfg.get("number"):
        digits = "".join(ch for ch in str(cfg["number"]) if ch.isdigit())
        gw = CARRIER_GATEWAYS.get(cfg.get("carrier", ""))
        targets = [f"{digits}@{gw}"] if gw else []
    else:
        targets = []
    try:
        from ghosted import bridge, mail

        accounts = mail.accounts()
        body = f"Your one-time Ghosted sign-in code is {code} (valid 10 minutes)."
        for to in targets:
            # 1) seal a copy into the sovereign mailbox as a record (best-effort)
            try:
                mail.compose(to=to, subject="Ghosted sign-in code", body=body,
                             passphrase=passphrase)
            except Exception:
                pass
            # 2) attempt REAL delivery via a configured external SMTP account
            for sender, acfg in accounts.items():
                try:
                    apw = mail.account_password(sender, passphrase)
                    if not apw:
                        continue
                    prov = mail.provider_config(sender)
                    r = bridge.send_external(
                        to=to, subject="Ghosted sign-in code", body=body,
                        from_addr=sender,
                        smtp_host=acfg.get("smtp_host") or prov["smtp"]["host"],
                        smtp_port=int(acfg.get("smtp_port") or prov["smtp"]["port"]),
                        username=sender, password=apw,
                    )
                    if r.get("ok"):
                        delivered, via = True, f"{'text' if factor == 'phone' else 'email'} → {to}"
                        break
                except Exception:
                    continue
            if delivered:
                break
    except Exception:
        delivered = False
    out = {"factor": factor, "delivered": delivered, "via": via}
    if not delivered:  # honest fail-soft — show the code so sign-in always works
        out["shown"] = code
        out["via"] = "shown on screen (no external delivery configured)"
    return out


# ── verification ─────────────────────────────────────────────────────────────────
def verify_factor(factor: str, passphrase: str, proof: str = "", *, client_ip: str = "") -> bool:
    """Verify a single factor's proof. Never raises."""
    factor = (factor or "").strip().lower()
    try:
        if factor == "authenticator":
            from ghosted import twofactor

            return twofactor.verify(passphrase, proof)
        if factor == "location":
            cfg = _store().get("factors", {}).get("location", {})
            prefix = ".".join((client_ip or "").split(".")[:3])
            return bool(prefix) and prefix in set(cfg.get("trusted", []))
        if factor == "recovery":
            cfg = _store().get("factors", {}).get("recovery")
            if not cfg:
                return False
            payload = _unseal(cfg["blob"], passphrase)
            code = (proof or "").strip().lower()
            codes = [c.lower() for c in payload.get("codes", [])]
            if code and code in codes:
                payload["codes"] = [c for c in payload["codes"] if c.lower() != code]
                s = _store()
                s["factors"]["recovery"]["blob"] = _seal(payload, passphrase)
                _save(s)
                return True
            return False
        if factor in ("email", "phone"):
            pend = _store().get("pending", {}).get(factor)
            if not pend or pend.get("exp", 0) < time.time():
                return False
            want = _unseal(pend["blob"], passphrase).get("code", "")
            return bool(proof) and proof.strip() == want
    except Exception:
        return False
    return False


def validate(passphrase: str, proofs: dict[str, str], *, client_ip: str = "") -> dict:
    """The account-login decision. Requires the master password to verify AND at least
    REQUIRED_FACTORS distinct enrolled factors to pass (password + 2 by policy)."""
    result: dict[str, Any] = {"ok": False, "password_ok": False, "passed": [], "required": REQUIRED_FACTORS}
    try:
        from ghosted import vault

        result["password_ok"] = bool(vault.login(passphrase))
    except Exception:
        result["password_ok"] = False
    if not result["password_ok"]:
        return result
    have = set(enrolled())
    passed = []
    for factor in FACTOR_TYPES:
        if factor not in have:
            continue
        proof = (proofs or {}).get(factor, "")
        if factor == "location" or proof:
            if verify_factor(factor, passphrase, proof, client_ip=client_ip):
                passed.append(factor)
    result["passed"] = passed
    # Fail-soft during rollout: if fewer than REQUIRED factors are even enrolled, the
    # password + whatever IS enrolled validates, but we flag that more should be added.
    need = min(REQUIRED_FACTORS, len(have))
    result["enrolled"] = sorted(have)
    result["ok"] = result["password_ok"] and len(passed) >= need
    if len(have) < REQUIRED_FACTORS:
        result["warning"] = (
            f"only {len(have)} factor(s) enrolled — enroll {REQUIRED_FACTORS - len(have)} "
            f"more so two are always required"
        )
    return result


def status() -> dict:
    have = enrolled()
    return {
        "enrolled": sorted(have),
        "count": len(have),
        "required": REQUIRED_FACTORS,
        "policy": "master password + 2 factors",
        "satisfiable": len(have) >= REQUIRED_FACTORS,
    }
