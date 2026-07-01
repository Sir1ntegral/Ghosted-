"""Functional email tests: parse received mail, seal/read round-trip, delete guard,
account-driven send/receive resolution. Guards the 'email actually works' contract."""
from __future__ import annotations

import os

import pytest

from ghosted import mail


@pytest.fixture(autouse=True)
def _tmp_mailbox(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    # isolate the accounts store + identities under the temp root too
    yield


MULTIPART = (
    "From: Alice Example <alice@example.com>\r\n"
    "To: me@ghosted.local\r\n"
    "Subject: Lunch tomorrow?\r\n"
    "Date: Wed, 01 Jul 2026 09:30:00 -0400\r\n"
    "MIME-Version: 1.0\r\n"
    'Content-Type: multipart/alternative; boundary="BND"\r\n\r\n'
    "--BND\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
    "Are we still on for lunch at noon?\r\n"
    "--BND\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
    "<p>Are we still on for <b>lunch</b>?</p>\r\n--BND--\r\n"
)


def test_parse_rfc822_extracts_real_fields():
    p = mail.parse_rfc822(MULTIPART)
    assert p["from"] == "Alice Example <alice@example.com>"
    assert p["subject"] == "Lunch tomorrow?"
    assert "lunch at noon" in p["body"]
    assert p["to"] == "me@ghosted.local"


def test_seal_inbound_is_readable_with_key():
    path = mail.seal_inbound(MULTIPART, "master-key")
    m = mail.read(path, "master-key")
    assert m["from"].startswith("Alice")
    assert m["subject"] == "Lunch tomorrow?"
    assert "lunch" in m["body"]
    # NOT the old broken behaviour (raw dump / from='external')
    assert m["from"] != "external"
    assert m["subject"] != "(external)"


def test_parse_html_only_strips_tags():
    raw = "From: b@x.com\r\nSubject: HTML\r\nContent-Type: text/html\r\n\r\n<h1>Hi</h1><p>x</p>"
    p = mail.parse_rfc822(raw)
    assert "Hi" in p["body"] and "<" not in p["body"]


def test_parse_never_raises_on_garbage():
    p = mail.parse_rfc822("this is not a valid email at all \x00\xff")
    assert isinstance(p, dict) and "body" in p


def test_delete_guards_path(tmp_path):
    path = mail.seal_inbound(MULTIPART, "k")
    assert mail.delete(path) is True          # a real .box in the mailbox
    assert mail.delete(path) is False         # already gone
    assert mail.delete("/etc/passwd") is False
    assert mail.delete(str(tmp_path / "x.txt")) is False  # not a .box


def test_send_via_account_needs_enrollment():
    with pytest.raises(ValueError, match="no enrolled email account"):
        mail.send_via_account("x@y.com", "s", "b", "pw")


def test_pull_via_account_needs_enrollment():
    with pytest.raises(ValueError, match="no enrolled email account"):
        mail.pull_via_account("pw")


def test_account_resolution_after_enrollment():
    # enroll a Gmail account with a saved (encrypted) app password
    mail.set_account("user@gmail.com", protocol="imap", password="app-pw", master_pw="master")
    assert mail.default_account() == "user@gmail.com"
    # send resolves SMTP from the provider even though enrolled as imap; fails only at
    # the network step (no real server) — proving config+password resolved.
    with pytest.raises(Exception) as ei:
        mail.send_via_account("dest@x.com", "hi", "body", "master")
    assert "no enrolled" not in str(ei.value)   # got past resolution
    assert "no saved email password" not in str(ei.value)
