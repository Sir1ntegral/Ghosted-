"""Mesh delivery tests — black-box mail moves peer-to-peer; offline → spool."""
import os
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


def test_mesh_delivery_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    from rabbitghost import mail, mesh_mail

    port = _free_port()
    threading.Thread(target=mesh_mail.receiver, kwargs={"port": port}, daemon=True).start()
    time.sleep(1)

    res = mesh_mail.send_to("127.0.0.1", "rabbit", "subject", "secret body", "passphrase123", port=port)
    assert res["delivered"] is True

    boxes = mail.inbox()
    assert boxes, "the delivered black box should be in the peer's mailbox"
    opened = mail.read(boxes[-1], "passphrase123")
    assert opened["body"] == "secret body"
    assert opened["to"].endswith("@sovereign.dmn")


def test_deliver_offline_spools(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    from rabbitghost import mesh_mail, transport

    res = mesh_mail.deliver("10.255.255.1", "opaque-token", port=9, ports=(9,))  # unreachable
    assert res["delivered"] is False and "spooled" in res
    assert len(transport.Spool("mesh_mail")) == 1
