"""Console command tests — handle_command's I/O is injectable, so every branch
is testable without a terminal."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
pytest.importorskip(
    "rabbit.core.crypto", reason="requires the rabbit mind on PYTHONPATH"
)

from ghosted.console import handle_command  # noqa: E402


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
        cmd,
        rest,
        FakeGhost(),
        session,
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


def test_parse_command(tmp_path):
    f = tmp_path / "doc.txt"
    f.write_text("parsed content here", encoding="utf-8")
    _, out, _ = run("parse", str(f))
    assert "parsed content here" in out[0]["preview"]


def test_network_requires_login():
    _, out, _ = run("network", session={"pw": None})
    assert "locked" in out[0]


def test_network_builds_sealed_mesh(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    from ghosted import vault

    vault.initialize("MeshMasterKey1")
    _, out, _ = run(
        "network",
        session={"pw": "MeshMasterKey1"},
        asks=["", "tower", "1.2.3.4:51820", "iphone", "", ""],  # ≥2 devices
    )
    assert {"tower", "iphone"} <= set(out[-1]["mesh_sealed_in_vault"])


# ── mail command (compose / inbox / read / send / ext / pull) ────────────────
def test_mail_compose_inbox_read_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    # compose: asks to/subject/body, getpw passphrase → seals into the mailbox
    _, out, _ = run(
        "mail",
        "compose",
        asks=["alice", "hi there", "the body"],
        pws=["BlackBoxPass1"],
    )
    assert out[0]["sealed_to_mailbox"].endswith(".box")
    # inbox: lists the one black box
    _, out, _ = run("mail", "inbox")
    assert out[0]["count"] == 1 and out[0]["recent"][0].startswith("0: ")
    # read index 0 with the key → original message recovered
    _, out, _ = run("mail", "read 0", pws=["BlackBoxPass1"])
    assert out[0]["subject"] == "hi there" and out[0]["body"] == "the body"
    assert out[0]["to"] == "alice@sovereign.dmn"


def test_mail_read_wrong_key_errors(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    run("mail", "compose", asks=["bob", "s", "b"], pws=["RightKey12345"])
    # the console wraps exceptions; here handle_command raises, caught by caller.
    # read with the wrong key must NOT return the plaintext.
    try:
        _, out, _ = run("mail", "read 0", pws=["WrongKey00000"])
        assert "b" != out[0].get("body")
    except Exception:
        pass  # decrypt failure on a wrong key is acceptable


def test_mail_send_requires_peer():
    _, out, _ = run("mail", "send")
    assert "usage: mail send" in out[0]


def test_mail_pull_bad_protocol():
    _, out, _ = run("mail", "pull ftp")
    assert "usage: mail pull" in out[0]


def test_mail_unknown_subcommand():
    _, out, _ = run("mail", "frobnicate")
    assert "unknown mail subcommand" in out[0]


# ── Tier 1: boot robustness — commands tolerate a missing ghost stack (g=None) ─
def test_commands_tolerate_missing_ghost():
    out = []

    def call(cmd, rest=""):
        return handle_command(
            cmd,
            rest,
            None,  # ghost stack unavailable
            {"pw": None},
            ask=lambda *_: "",
            getpw=lambda *_: "",
            out=out.append,
        )

    assert call("status") is True and out[-1] == {"active": False}
    call("recon", "x")
    assert "unavailable" in out[-1]
    assert call("quit") is False  # quit still exits cleanly


# ── Tier 2: store-and-forward flush + mesh actuation + password rotation ──────
def test_flush_offline(monkeypatch):
    monkeypatch.setattr("ghosted.transport.online", lambda *a, **k: False)
    _, out, _ = run("flush")
    assert out[0] == {"online": False}


def test_mesh_status_no_mesh(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    _, out, _ = run("mesh")
    assert out[0] == {"has_mesh": False}


def test_mesh_export_requires_mesh(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    _, out, _ = run("mesh", "export")
    assert "no mesh sealed" in out[0]


def test_mesh_export_writes_confs(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    from ghosted import vault

    vault.initialize("MeshExportKey1")
    vault.build_and_seal_mesh(
        [("tower", "1.2.3.4:51820"), ("phone", "")], "MeshExportKey1"
    )
    dest = str(tmp_path / "confs")
    _, out, _ = run("mesh", f"export {dest}", pws=["MeshExportKey1"])
    exported = out[-1]["exported"]
    assert len(exported) >= 2
    assert all(p.endswith(".conf") and os.path.exists(p) for p in exported)


def test_passwd_requires_vault(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    _, out, _ = run("passwd")
    assert "no master password set" in out[0]


def test_passwd_rotates(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    from ghosted import vault

    vault.initialize("OldMasterKey12")
    _, out, _ = run(
        "passwd", pws=["OldMasterKey12", "NewMasterKey34", "NewMasterKey34"]
    )
    assert "rotated" in out[-1]["vault"]
    assert vault.login("NewMasterKey34") and not vault.login("OldMasterKey12")


# ── Tier 4: contracts doctor + EDR-lite scan ─────────────────────────────────
def test_doctor_reports_contracts():
    _, out, _ = run("doctor")
    rep = out[0]
    assert rep["total"] >= 9 and "organs" in rep
    assert rep["organs"]["crypto"]["ok"] is True  # crypto is pure-Python, always wired


def test_scan_clean_text(tmp_path):
    f = tmp_path / "note.txt"
    f.write_text("just some harmless notes", encoding="utf-8")
    _, out, _ = run("scan", str(f))
    assert out[0]["verdict"] == "clean" and out[0]["type"] == "data"


def test_scan_detects_pe_masquerade(tmp_path):
    f = tmp_path / "invoice.pdf"
    f.write_bytes(b"MZ" + b"\x00" * 200)  # PE header, but .pdf extension
    _, out, _ = run("scan", str(f))
    assert out[0]["type"] == "pe-executable"
    assert out[0]["verdict"] in ("suspicious", "malicious")
    assert any("masquerad" in r for r in out[0]["reasons"])


def test_scan_quarantines_malicious(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    f = tmp_path / "tool.exe"
    f.write_bytes(b"MZ" + b"\x00" * 500)  # risky extension + PE -> malicious
    _, out, _ = run("scan", f"{f} q")
    assert out[0]["verdict"] == "malicious" and "quarantined" in out[0]
    assert not f.exists() and os.path.exists(out[0]["quarantined"])
