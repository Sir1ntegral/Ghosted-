"""Vault + app-login tests — needs the rabbit mind (crypto/wireguard). Skips if absent."""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

pytest.importorskip("rabbit.core.crypto", reason="requires the rabbit mind on PYTHONPATH")


def test_login_and_wireguard_vault(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    from rabbitghost import vault as v

    assert not v.is_initialized()
    v.initialize("CorrectHorse42")
    assert v.login("CorrectHorse42")
    assert not v.login("wrong-password")

    names = v.build_and_seal_mesh(
        [("tower", "1.2.3.4:51820"), ("iphone", "")], "CorrectHorse42", hub="tower"
    )
    assert set(names) == {"tower", "iphone"}

    # sealed opaque at rest — no key material readable
    raw = open(os.path.join(str(tmp_path), "RabbitGhost", "vault", "mesh.box")).read()
    assert "PrivateKey" not in raw and "[Interface]" not in raw

    cfgs = v.unseal_mesh("CorrectHorse42")
    assert "[Interface]" in cfgs["tower"] and "[Peer]" in cfgs["tower"]

    with pytest.raises(Exception):
        v.unseal_mesh("wrong-password")

    # rotation: old dies, new works, mesh survives
    assert v.change_password("CorrectHorse42", "NewPassword99")
    assert not v.login("CorrectHorse42")
    assert v.login("NewPassword99")
    assert "[Interface]" in v.unseal_mesh("NewPassword99")["tower"]


def test_short_passphrase_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    from rabbitghost import vault as v

    with pytest.raises(ValueError):
        v.initialize("abc")
