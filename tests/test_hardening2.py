"""Regression tests for the second hardening pass (new-module fixes)."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
pytest.importorskip("rabbit.core.crypto", reason="requires the rabbit mind")


def test_bridge_refuses_credentials_without_tls():
    from ghosted import bridge

    with pytest.raises(ValueError):
        bridge.send_external(
            "a@b.com",
            "s",
            "b",
            from_addr="me@x.com",
            smtp_host="smtp.x.com",
            username="me",
            password="pw",
            use_tls=False,
        )


def test_imap_refuses_credentials_without_ssl():
    from ghosted import imap_pull

    with pytest.raises(ValueError):
        imap_pull.pull_imap("imap.x.com", "me", "pw", "key", use_ssl=False)
    with pytest.raises(ValueError):
        imap_pull.pull_pop("pop.x.com", "me", "pw", "key", use_ssl=False)


def test_smtp_inbox_refuses_to_start_without_key(monkeypatch):
    from ghosted import smtp_inbox

    monkeypatch.delenv("GHOSTED_INBOX_KEY", raising=False)
    with pytest.raises(SystemExit):
        smtp_inbox.serve(port=0, key=None)


def test_atomic_write_is_crash_safe(tmp_path):
    from ghosted import mail

    p = str(tmp_path / "store.json")
    mail.atomic_write_json(p, {"a": 1})
    import json

    assert json.load(open(p)) == {"a": 1}
    # no leftover temp files
    assert not [f for f in os.listdir(tmp_path) if f.endswith(".tmp")]


def test_filters_block_survives_via_atomic_write(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    from ghosted import mail_filters as mf

    mf.add_filter("from", "contains", "spam@", "block", name="b")
    assert any(r["name"] == "b" for r in mf.filters())
