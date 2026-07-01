"""WireGuard enrollment (both directions) + tunnel activation + Gojo guarding."""

import re

import pytest


PW = "correcthorsebatterystaple"


def _priv(conf):
    return re.search(r"PrivateKey = (\S+)", conf).group(1)


def _addr(conf):
    return re.search(r"Address = (\S+)", conf).group(1)


def _vault(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    from ghosted import vault

    vault.initialize(PW)
    return vault


def test_add_peer_preserves_existing_keys_and_addresses(tmp_path, monkeypatch):
    _vault(tmp_path, monkeypatch)
    from ghosted import wg_enroll

    assert wg_enroll.add_peer("tower", endpoint="tower:51820", passphrase=PW, hub="tower")["ok"]
    assert wg_enroll.add_peer("phone", passphrase=PW)["ok"]
    p1 = wg_enroll.device_config("phone", PW)
    t1 = wg_enroll.device_config("tower", PW)
    # a third enrollment must NOT rekey or re-address the earlier devices
    assert wg_enroll.add_peer("laptop", passphrase=PW)["count"] == 3
    p2 = wg_enroll.device_config("phone", PW)
    t2 = wg_enroll.device_config("tower", PW)
    assert _priv(p1) == _priv(p2) and _addr(p1) == _addr(p2)
    assert _priv(t1) == _priv(t2)
    assert "laptop" in t2  # hub now peers with the new device


def test_add_peer_rejects_duplicate(tmp_path, monkeypatch):
    _vault(tmp_path, monkeypatch)
    from ghosted import wg_enroll

    wg_enroll.add_peer("nuc", passphrase=PW)
    assert wg_enroll.add_peer("nuc", passphrase=PW)["ok"] is False


def test_join_mesh_generates_local_keys_and_handback(tmp_path, monkeypatch):
    _vault(tmp_path, monkeypatch)
    from ghosted import wg_enroll
    from ghosted._sovereign_wireguard import (
        derive_public_key, encode_key, gen_private_key,
    )

    hub_pub = encode_key(derive_public_key(gen_private_key()))
    r = wg_enroll.join_mesh("mylaptop", hub_pub, "peer:51820", PW)
    assert r["ok"] and "PrivateKey" in r["config"] and r["public_key"]
    assert hub_pub in r["config"]  # peers with the hub


def test_join_mesh_rejects_bad_hub_key(tmp_path, monkeypatch):
    _vault(tmp_path, monkeypatch)
    from ghosted import wg_enroll

    assert wg_enroll.join_mesh("x", "not-a-key", "h:51820", PW)["ok"] is False


def test_enroll_peer_pubkey_without_private_key(tmp_path, monkeypatch):
    _vault(tmp_path, monkeypatch)
    from ghosted import wg_enroll
    from ghosted._sovereign_wireguard import (
        derive_public_key, encode_key, gen_private_key,
    )

    pub = encode_key(derive_public_key(gen_private_key()))
    r = wg_enroll.enroll_peer_pubkey("selfkeyed", pub, PW, endpoint="sk:51820")
    assert r["ok"] and r["address"]
    names = [d["name"] for d in wg_enroll.roster(PW)]
    assert "selfkeyed" in names


def test_tunnel_connect_never_fakes_when_wireguard_absent(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.delenv("GHOSTED_WIREGUARD", raising=False)
    from ghosted import wg_tunnel

    # force "not installed" regardless of host
    monkeypatch.setattr(wg_tunnel, "wireguard_exe", lambda: None)
    res = wg_tunnel.connect("t", "[Interface]\nPrivateKey=x\n")
    assert res["ok"] is False and res.get("exported")  # exported, not connected


def test_remote_wireguard_enroll_denied_by_source_boundary(tmp_path, monkeypatch):
    _vault(tmp_path, monkeypatch)
    from ghosted import wg_enroll

    r = wg_enroll.add_peer("phone", passphrase=PW, source_class="network_remote")
    assert r["ok"] is False and r.get("reason") == "source_not_permitted"


def test_local_wireguard_enroll_allowed(tmp_path, monkeypatch):
    _vault(tmp_path, monkeypatch)
    from ghosted import wg_enroll

    assert wg_enroll.add_peer("phone", passphrase=PW, source_class="internal")["ok"]


def test_source_class_derived_from_client_ip():
    from ghosted import homepage

    class H:
        def __init__(self, ip):
            self.client_address = (ip, 1)

    assert homepage._request_source_class(H("127.0.0.1")) == "internal"
    assert homepage._request_source_class(H("10.44.0.3")) == "network_mesh"
    assert homepage._request_source_class(H("8.8.8.8")) == "network_remote"


def test_guard_gojo_allows_and_audits(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    from ghosted import event_bus, security

    v = security.guard(action="wireguard_enroll", metadata={"device": "d"})
    assert v["decision"] == "allow"
    assert any(e.get("action") == "wireguard_enroll" for e in event_bus.recent(20))
