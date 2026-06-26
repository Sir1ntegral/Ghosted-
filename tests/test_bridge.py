"""External SMTP-send bridge tests — mocked relay (no real server, no network)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from rabbitghost import bridge


def test_send_external_builds_and_relays(monkeypatch):
    captured = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout=None):
            captured["host"] = host
            captured["port"] = port

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def starttls(self, context=None):
            captured["tls"] = True

        def login(self, user, pw):
            captured["login"] = (user, pw)

        def send_message(self, msg):
            captured["msg"] = msg

    monkeypatch.setattr("smtplib.SMTP", FakeSMTP)

    res = bridge.send_external(
        "bob@gmail.com", "hi", "body text",
        from_addr="lucy@gmail.com", smtp_host="smtp.gmail.com",
        username="lucy@gmail.com", password="app-password",
    )
    assert res["sent"] is True and res["via"] == "smtp.gmail.com:587"
    assert captured["host"] == "smtp.gmail.com" and captured["tls"] is True
    assert captured["login"] == ("lucy@gmail.com", "app-password")
    assert captured["msg"]["To"] == "bob@gmail.com"
    assert captured["msg"]["From"] == "lucy@gmail.com"


def test_no_imap_pop_in_bridge():
    src = open(bridge.__file__, encoding="utf-8").read().lower()
    assert "imaplib" not in src and "poplib" not in src


def test_receive_status_is_honest():
    st = bridge.receive_external_status()
    assert st["supported"] is False
    assert "@sovereign.dmn" in st["sovereign_alternative"]
