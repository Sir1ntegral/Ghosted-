"""Tests for the auth + personalization features: TOTP/2FA, MFA 2-of-N, QR, prefs.

Offline / no network. Stores are isolated to a temp dir per test.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest  # noqa: E402

from ghosted import mfa, preferences, qrcode, twofactor  # noqa: E402


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    """Point every personal store at a temp dir and init the vault there."""
    from ghosted import mail, vault

    d = str(tmp_path)
    monkeypatch.setattr(mail, "_data_root", lambda: d)
    monkeypatch.setattr(vault, "_vault_dir", lambda: d)
    monkeypatch.setattr(twofactor, "_path", lambda: os.path.join(d, "twofactor.json"))
    monkeypatch.setattr(mfa, "_path", lambda: os.path.join(d, "mfa.json"))
    monkeypatch.setattr(preferences, "_path", lambda: os.path.join(d, "preferences.json"))
    vault.initialize("master-pw-123")
    return d


# ── TOTP / 2FA ──────────────────────────────────────────────────────────────────
def test_totp_rfc6238_vectors():
    s = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # base32('12345678901234567890')
    assert twofactor._totp(s, 59) == "287082"
    assert twofactor._totp(s, 1111111109) == "081804"
    assert twofactor._totp(s, 1234567890) == "005924"


def test_totp_enroll_verify_and_recovery(isolated):
    e = twofactor.enroll("master-pw-123")
    assert twofactor.is_enabled()
    assert twofactor.verify("master-pw-123", twofactor.current_code("master-pw-123"))
    assert not twofactor.verify("master-pw-123", "000000")
    assert not twofactor.verify("wrong-pw", twofactor.current_code("master-pw-123"))
    rc = e["recovery_codes"][0]
    assert twofactor.verify("master-pw-123", rc)        # one-time recovery works
    assert not twofactor.verify("master-pw-123", rc)    # and is consumed


# ── MFA 2-of-N ───────────────────────────────────────────────────────────────────
def test_mfa_requires_password_plus_two_factors(isolated):
    mfa.enroll("authenticator", "master-pw-123")
    mfa.enroll("location", "master-pw-123", ip="192.168.1.10")
    code = twofactor.current_code("master-pw-123")
    ok = mfa.validate("master-pw-123", {"authenticator": code}, client_ip="192.168.1.55")
    assert ok["ok"] and set(ok["passed"]) == {"authenticator", "location"}
    # wrong password → never ok
    assert not mfa.validate("nope", {"authenticator": code}, client_ip="192.168.1.55")["ok"]
    # only one factor (bad location) → fails the 2-of-N policy
    assert not mfa.validate("master-pw-123", {"authenticator": code}, client_ip="10.0.0.9")["ok"]


def test_mfa_email_fallback_addresses(isolated):
    r = mfa.enroll("email", "master-pw-123", addr="a@x.com, b@y.com, c@z.com")
    assert r["addrs"] == ["a@x.com", "b@y.com", "c@z.com"]


def test_mfa_phone_carrier_sms(isolated):
    mfa.enroll("phone", "master-pw-123", number="5551234567", carrier="verizon")
    ch = mfa.challenge("phone", "master-pw-123")
    # delivered via carrier email-to-SMS, or shown on-screen as fallback
    assert ch.get("delivered") or ch.get("shown")


# ── QR ───────────────────────────────────────────────────────────────────────────
def test_qr_encode_and_svg():
    uri = "otpauth://totp/Ghosted:me?secret=JBSWY3DPEHPK3PXP&issuer=Ghosted"
    m = qrcode.encode(uri)
    assert len(m) == len(m[0]) and len(m) >= 21          # square, >= version 1
    assert m[0][0] == 1 and m[0][6] == 1                  # finder pattern present
    svg = qrcode.svg(uri)
    assert svg.startswith("<svg") and "rect" in svg


# ── preferences ──────────────────────────────────────────────────────────────────
def test_email_provider_autoconfig(isolated):
    from ghosted import mail

    g = mail.provider_config("002moore@gmail.com")
    assert g["imap"]["host"] == "imap.gmail.com" and g["imap"]["port"] == 993
    assert g["smtp"]["host"] == "smtp.gmail.com" and g["known"]
    # unknown domain → generic fallback
    u = mail.provider_config("x@mycompany.org")
    assert u["imap"]["host"] == "imap.mycompany.org" and not u["known"]
    # set_account with blank host auto-fills from the email
    r = mail.set_account("002moore@gmail.com", "imap", "", 0, "")
    assert r["002moore@gmail.com"]["host"] == "imap.gmail.com"


def test_wireguard_mesh_enrollment(isolated):
    from ghosted import vault

    names = vault.build_and_seal_mesh(
        [("phone", ""), ("laptop", "203.0.113.5:51820"), ("nuc", "")],
        "master-pw-123", hub="nuc",
    )
    assert set(names) == {"phone", "laptop", "nuc"}
    assert vault.has_mesh()
    cfgs = vault.unseal_mesh("master-pw-123")
    conf = cfgs["phone"]
    assert "[Interface]" in conf and "PrivateKey" in conf and "[Peer]" in conf


def test_preferences_validate_and_persist(isolated):
    preferences.update({"display_name": "Lucy", "accent": "green", "notifications": "on"})
    assert preferences.get("display_name") == "Lucy"
    assert preferences.get("accent") == "green"
    assert preferences.accent_color() == preferences.ACCENTS["green"]
    assert preferences.get("notifications") is True
    preferences.set("accent", "not-a-color")             # invalid → default
    assert preferences.get("accent") == "violet"
    preferences.set("bogus_key", "x")                    # unknown key ignored
    assert "bogus_key" not in preferences.all()
