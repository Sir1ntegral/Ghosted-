"""Ghosted defense facade — one boot() brings up all pillars; embeddable by any app."""


def test_boot_brings_up_all_pillars(monkeypatch, tmp_path):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    from ghosted import defense

    st = defense.boot("test-app")
    assert st["booted"] is True and st["state"] == "ok"
    for pillar in ("gojo", "workflow", "encryption", "edr", "event_bus"):
        assert st["pillars"][pillar] == "available", pillar
    # protects the app itself, not the host
    assert "not the host" in st["protects"]


def test_boot_is_idempotent(monkeypatch, tmp_path):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    from ghosted import defense

    defense.boot()
    assert defense.is_booted() is True
    assert defense.boot()["booted"] is True  # second call is a no-op status


def test_facade_encrypt_decrypt_roundtrip(monkeypatch, tmp_path):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    from ghosted import defense

    blob = defense.encrypt("classified", "a-long-passphrase-123")
    assert defense.decrypt(blob, "a-long-passphrase-123") == "classified"


def test_facade_guard_gates_and_audits(monkeypatch, tmp_path):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    from ghosted import defense, event_bus

    v = defense.guard(action="wireguard_connect", metadata={"name": "n"})
    assert v["decision"] == "allow"
    assert any(e.get("event_type", "").startswith("guard.") for e in event_bus.recent(20))


def test_status_never_raises(monkeypatch, tmp_path):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    from ghosted import defense

    st = defense.status()
    assert isinstance(st, dict) and "pillars" in st and "state" in st
