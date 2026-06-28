"""Black-box mail tests — needs the rabbit mind (crypto). Skips if unavailable."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

pytest.importorskip(
    "rabbit.core.crypto", reason="requires the rabbit mind on PYTHONPATH"
)


def test_message_is_a_black_box_and_round_trips(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    from ghosted import mail

    pw = "LucyMasterKey!"
    path = mail.send(
        "rabbit@mesh", "secret subject", "classified body", pw, sender="lucy"
    )
    on_disk = open(path, encoding="ascii").read()

    # opaque: nothing readable leaks to disk
    assert "secret subject" not in on_disk
    assert "classified body" not in on_disk

    # opens only with the key
    opened = mail.read(path, pw)
    assert opened["subject"] == "secret subject"
    assert opened["body"] == "classified body"

    # wrong key is rejected (AEAD auth)
    with pytest.raises(Exception):
        mail.read(path, "wrongkey")
