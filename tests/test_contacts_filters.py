"""Contacts, mail filters, and black-box email search."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
pytest.importorskip("rabbit.core.crypto", reason="search/mail need the rabbit mind")


# ── contacts ─────────────────────────────────────────────────────────────────
def test_contacts_add_resolve_remove(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    from rabbitghost import contacts

    contacts.add_contact("Rabbit", "rabbit")  # bare -> @sovereign.dmn
    contacts.add_contact("Bob", "bob@gmail.com", tags=["work"])
    assert contacts.resolve("Rabbit") == "rabbit@sovereign.dmn"
    assert contacts.resolve("Bob") == "bob@gmail.com"
    assert len(contacts.find("bob")) == 1
    assert contacts.remove_contact("bob@gmail.com") is True
    assert len(contacts.contacts()) == 1


# ── filters ──────────────────────────────────────────────────────────────────
def test_filters_match_and_actions(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    from rabbitghost import mail_filters as mf

    mf.add_filter("from", "contains", "spam@", "block", name="block-spam")
    mf.add_filter(
        "subject", "contains", "invoice", "tag", arg="finance", name="tag-fin"
    )
    mf.add_filter("from", "contains", "lucy@", "star", name="star-lucy")

    spam = mf.apply_filters({"from": "spam@bad.com", "subject": "hi", "body": ""})
    assert spam["blocked"] is True

    inv = mf.apply_filters(
        {"from": "lucy@sovereign.dmn", "subject": "Your invoice", "body": ""}
    )
    assert "finance" in inv["tags"] and inv["starred"] is True

    assert mf.remove_filter("block-spam") is True


def test_filter_validation(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    from rabbitghost import mail_filters as mf

    with pytest.raises(ValueError):
        mf.add_filter("badfield", "contains", "x", "tag")
    with pytest.raises(ValueError):
        mf.add_filter("from", "badop", "x", "tag")


# ── email search ─────────────────────────────────────────────────────────────
def test_mail_search_requires_key_and_matches(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    from rabbitghost import mail

    mail.send(
        "rabbit", "Project Falcon", "the eagle lands at noon", "key123", sender="lucy"
    )
    mail.send("rabbit", "Lunch", "tacos on tuesday", "key123", sender="lucy")

    hits = mail.search("falcon", "key123")
    assert len(hits) == 1 and "Falcon" in hits[0]["subject"]

    # wrong key opens nothing — black boxes aren't searchable without it
    assert mail.search("falcon", "wrong-key") == []

    # empty query returns all openable
    assert len(mail.search("", "key123")) == 2
