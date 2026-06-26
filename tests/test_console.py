"""Console command tests — handle_command's I/O is injectable, so every branch
is testable without a terminal."""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
pytest.importorskip("rabbit.core.crypto", reason="requires the rabbit mind on PYTHONPATH")

from rabbitghost.console import handle_command


class FakeGhost:
    is_active = True

    def exit(self):
        return {"ok": True, "active": False}

    def recon(self, topic):
        return {"ok": True, "topic": topic}

    def forge(self, src, out):
        return {"forged": out}


def run(cmd, rest="", session=None, asks=None, pws=None):
    out = []
    ai = iter(asks or [])
    pi = iter(pws or [])
    session = {"pw": None} if session is None else session
    cont = handle_command(
        cmd, rest, FakeGhost(), session,
        ask=lambda *_: next(ai, ""),
        getpw=lambda *_: next(pi, ""),
        out=out.append,
    )
    return cont, out, session


def test_quit_returns_false():
    cont, out, _ = run("quit")
    assert cont is False and out[0]["active"] is False


def test_status():
    cont, out, _ = run("status")
    assert cont is True and out[0] == {"active": True}


def test_unknown_command():
    _, out, _ = run("bogus")
    assert "unknown" in out[0]


def test_forge_and_recon():
    assert run("forge", "f.py")[1][0] == {"forged": "f.py.forged"}
    assert run("recon", "topic")[1][0]["topic"] == "topic"


def test_encrypt_decrypt_roundtrip():
    token = run("encrypt", "secret message", pws=["mypassphrase"])[1][0]["sealed"]
    opened = run("decrypt", "", asks=[token], pws=["mypassphrase"])[1][0]["opened"]
    assert opened == "secret message"


def test_login_initializes_then_holds_session(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    _, out, session = run("login", pws=["MasterPassword1", "MasterPassword1"])
    assert "initialized" in out[0]["vault"] and session["pw"] == "MasterPassword1"


def test_login_password_mismatch(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    _, out, _ = run("login", pws=["aaaaaaaaaaaa", "bbbbbbbbbbbb"])
    assert "do not match" in out[0]["vault"]


def test_network_requires_login():
    _, out, _ = run("network", session={"pw": None})
    assert "locked" in out[0]


def test_network_builds_sealed_mesh(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    from rabbitghost import vault

    vault.initialize("MeshMasterKey1")
    _, out, _ = run(
        "network", session={"pw": "MeshMasterKey1"},
        asks=["", "tower", "1.2.3.4:51820", "iphone", "", ""],  # ≥2 devices
    )
    assert {"tower", "iphone"} <= set(out[-1]["mesh_sealed_in_vault"])
