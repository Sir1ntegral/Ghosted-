"""Connectivity coordinator tests — structure + hotspot (mocked, non-intrusive)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from rabbitghost import connectivity as c  # noqa: E402


def test_structure():
    assert isinstance(c.interfaces(), list)
    assert isinstance(c.online(timeout=2), bool)
    st = c.ensure_online(timeout=2)
    assert {"online", "interfaces"} <= set(st)


def test_hotspot_short_password_rejected():
    if os.name == "nt":
        assert c.start_hotspot(password="short")["ok"] is False


def test_hotspot_uses_netsh_without_running_it(monkeypatch):
    if os.name != "nt":
        return
    import subprocess

    calls = []

    class R:
        returncode = 0
        stdout = "Hosted network started."
        stderr = ""

    def fake_run(args, **kw):
        calls.append(args)
        return R()

    monkeypatch.setattr(subprocess, "run", fake_run)
    res = c.start_hotspot(password="rabbitmesh1234")
    assert res["ok"] is True
    assert any("hostednetwork" in " ".join(a) for a in calls)


def test_sovereign_get_returns_structured_result():
    # bad scheme/host → ok False with an error (no crash); structure is the contract
    res = c.sovereign_get("http://nonexistent.invalid.tld.zzz/", timeout=4)
    assert isinstance(res, dict) and "ok" in res
