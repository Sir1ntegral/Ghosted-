"""Email-identity tests — bring-your-own-email, no IMAP/POP, sovereign suggested first."""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from rabbitghost import mail


def test_sovereign_suggested_first(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    ids = mail.identities()
    assert ids[0].endswith("@sovereign.dmn")


def test_add_own_email_any_provider(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    mail.add_identity("lucy@gmail.com")
    mail.add_identity("lucy@proton.me")
    mail.add_identity("lucy@my-custom-host.io")
    ids = mail.identities()
    assert ids[0].endswith("@sovereign.dmn")  # sovereign still first
    for a in ("lucy@gmail.com", "lucy@proton.me", "lucy@my-custom-host.io"):
        assert a in ids


def test_invalid_email_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    with pytest.raises(ValueError):
        mail.add_identity("not-an-email")


def test_dedup_and_remove(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    mail.add_identity("x@y.com")
    mail.add_identity("x@y.com")  # dup ignored
    assert mail.identities().count("x@y.com") == 1
    assert mail.remove_identity("x@y.com") is True
    assert "x@y.com" not in mail.identities()


def test_no_imap_pop_surface():
    # The module must expose identity management but NO inbox-fetching protocols.
    assert hasattr(mail, "add_identity") and hasattr(mail, "identities")
    src = open(mail.__file__, encoding="utf-8").read().lower()
    assert "imaplib" not in src and "poplib" not in src
