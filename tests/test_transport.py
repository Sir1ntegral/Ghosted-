"""Transport tests — multi-port probing + store-and-forward spool (pure stdlib)."""

import os
import socket
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ghosted import transport as t  # noqa: E402


def _listener():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    return s, s.getsockname()[1]


def test_port_reachable_open_then_closed():
    s, port = _listener()
    assert t.port_reachable("127.0.0.1", port, timeout=2)
    s.close()
    assert not t.port_reachable("127.0.0.1", port, timeout=1)


def test_first_open_port_skips_dead_ports():
    s, port = _listener()
    try:
        assert t.first_open_port("127.0.0.1", ports=(1, 2, port), timeout=2) == port
    finally:
        s.close()


def test_online_any_probe(monkeypatch):
    monkeypatch.setattr(t, "port_reachable", lambda *a, **k: True)
    assert t.online() is True
    monkeypatch.setattr(t, "port_reachable", lambda *a, **k: False)
    assert t.online() is False


def test_spool_store_and_forward(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setattr(t, "online", lambda *a, **k: True)
    sp = t.Spool("test")
    sp.enqueue({"to": "rabbit", "msg": "hi"})
    sp.enqueue({"to": "lucy", "msg": "yo"})
    assert len(sp) == 2 and len(sp.pending()) == 2

    # deliver only "rabbit"; "lucy" fails and is kept
    res = sp.flush(lambda p: p["to"] == "rabbit")
    assert res["sent"] == 1 and res["kept"] == 1 and len(sp) == 1

    # retry succeeds for the rest
    res2 = sp.flush(lambda p: True)
    assert res2["sent"] == 1 and len(sp) == 0


def test_spool_offline_keeps_everything(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setattr(t, "online", lambda *a, **k: False)
    sp = t.Spool("test2")
    sp.enqueue({"x": 1})
    res = sp.flush(lambda p: True)
    assert res["offline"] is True and res["sent"] == 0 and len(sp) == 1
