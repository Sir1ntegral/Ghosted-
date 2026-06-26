"""External-receive tests — sovereign SMTP inbox (opt 3) + IMAP pull (opt 2)."""
import os
import smtplib
import socket
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
pytest.importorskip("rabbit.core.crypto", reason="requires the rabbit mind")


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_smtp_inbox_blackboxes_inbound(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    from rabbitghost import mail, smtp_inbox

    port = _free_port()
    threading.Thread(
        target=smtp_inbox.serve,
        kwargs={"port": port, "key": "inboxkey", "host": "127.0.0.1"}, daemon=True,
    ).start()
    time.sleep(1)

    sm = smtplib.SMTP("127.0.0.1", port, timeout=10)
    sm.sendmail("alice@external.com", ["lucy@sovereign.dmn"],
                "Subject: Hello\r\n\r\nthis is the external body")
    sm.quit()
    time.sleep(0.4)

    boxes = mail.inbox()
    assert boxes, "inbound mail should be black-boxed in the mailbox"
    opened = mail.read(boxes[-1], "inboxkey")
    assert "this is the external body" in opened["body"]


def test_imap_pull_blackboxes(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    from rabbitghost import imap_pull, mail

    class FakeIMAP:
        def __init__(self, host, port):
            pass

        def login(self, u, p):
            self.cred = (u, p)

        def select(self, folder):
            pass

        def search(self, charset, criteria):
            return "OK", [b"1 2"]

        def fetch(self, i, spec):
            return "OK", [(b"x", b"Subject: Hi\r\n\r\nexternal message " + i)]

        def logout(self):
            pass

    monkeypatch.setattr("imaplib.IMAP4_SSL", lambda host, port, **kw: FakeIMAP(host, port))
    res = imap_pull.pull_imap("imap.gmail.com", "lucy@gmail.com", "app-pass", "mykey")
    assert res["sealed"] == 2

    boxes = mail.inbox()
    assert len(boxes) == 2
    opened = mail.read(boxes[-1], "mykey")
    assert "external message" in opened["body"]
