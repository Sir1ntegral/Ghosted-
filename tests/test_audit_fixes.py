"""Regression tests for the meticulous-audit fixes — lock each defect closed."""

import pytest


PW = "correct-horse-battery-staple"


def test_mfa_challenge_is_honest_shows_code(tmp_path, monkeypatch):
    # A1: mail.compose only seals locally; with no external SMTP configured, challenge
    # must NOT claim delivery and MUST show the code so the user is never locked out.
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    from ghosted import mfa, vault

    vault.initialize(PW)
    mfa.enroll("email", PW, addrs=["me@example.com"])
    ch = mfa.challenge("email", PW)
    assert ch["delivered"] is False
    assert ch.get("shown") and len(ch["shown"]) == 6 and ch["shown"].isdigit()


def test_preferences_persists_mail_enroll_prompted(tmp_path, monkeypatch):
    # A3: the flag lives in the fixed schema now, so set/get actually persists.
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    from ghosted import preferences

    assert preferences.get("mail_enroll_prompted") is False
    preferences.set("mail_enroll_prompted", True)
    assert preferences.get("mail_enroll_prompted") is True


def test_enroll_peer_pubkey_source_class_denies_remote(tmp_path, monkeypatch):
    # N2: enroll_peer_pubkey now honors source_class so Gojo can source-deny it.
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    from ghosted import vault, wg_enroll
    from ghosted._sovereign_wireguard import (
        derive_public_key, encode_key, gen_private_key,
    )

    vault.initialize(PW)
    pub = encode_key(derive_public_key(gen_private_key()))
    r = wg_enroll.enroll_peer_pubkey("n", pub, PW, source_class="network_remote")
    assert r["ok"] is False and r.get("reason") == "source_not_permitted"
    assert wg_enroll.enroll_peer_pubkey("n", pub, PW, source_class="internal")["ok"]


def test_smtp_inbox_ip_filter_wired():
    # security: the receiver's loopback/mesh-only filter exists and is correct.
    from ghosted import smtp_inbox

    assert smtp_inbox._accept_ip("127.0.0.1") is True
    assert smtp_inbox._accept_ip("10.44.0.5") is True
    assert smtp_inbox._accept_ip("8.8.8.8") is False
    assert smtp_inbox._accept_ip("") is False


def test_scan_output_has_no_dead_rabbit_edr_key(tmp_path):
    from ghosted import scan

    p = tmp_path / "f.txt"
    p.write_text("hello world")
    r = scan.scan_file(str(p))
    assert r["verdict"] == "clean" and "rabbit_edr" not in r


def test_http_egress_masked_or_baseline(monkeypatch):
    # N1: default egress works (curl_cffi TLS mask when present, else urllib).
    from ghosted import http

    r = http.sovereign_http_get("https://api.ipify.org", connect_timeout=8, read_timeout=8)
    # network-dependent: accept success with a body, or a soft failure (never raises)
    assert isinstance(r.success, bool)
    if r.success:
        assert r.body and r.status == 200
