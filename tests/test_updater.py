"""Auto-update: version compare, manifest check, EDR + hash-verified download."""

import hashlib
import json


def test_version_compare():
    from ghosted import updater

    assert updater._newer("1.2.0", "1.1.9")
    assert updater._newer("0.2.0", "0.1.0")
    assert updater._newer("v1.0.1", "1.0.0")
    assert not updater._newer("0.1.0", "0.1.0")
    assert not updater._newer("0.1.0", "0.2.0")


def test_check_detects_newer_version(monkeypatch):
    from ghosted import updater

    monkeypatch.setenv("GHOSTED_UPDATE_URL", "https://example/manifest.json")
    monkeypatch.setattr(updater, "current_version", lambda: "0.1.0")
    monkeypatch.setattr(updater, "_fetch", lambda url: json.dumps(
        {"version": "0.2.0", "url": "https://x/Ghosted-Setup.exe", "sha256": "", "notes": "new"}
    ).encode())
    info = updater.check()
    assert info["available"] is True and info["latest"] == "0.2.0"


def test_check_reports_up_to_date(monkeypatch):
    from ghosted import updater

    monkeypatch.setenv("GHOSTED_UPDATE_URL", "https://example/m.json")
    monkeypatch.setattr(updater, "current_version", lambda: "9.9.9")
    monkeypatch.setattr(updater, "_fetch", lambda url: json.dumps(
        {"version": "0.2.0", "url": "u"}).encode())
    assert updater.check()["available"] is False


def test_check_unreachable_source_is_soft(monkeypatch):
    from ghosted import updater

    monkeypatch.setenv("GHOSTED_UPDATE_URL", "https://example/m.json")
    monkeypatch.setattr(updater, "_fetch", lambda url: None)
    info = updater.check()
    assert info["available"] is False and "error" in info


def test_download_rejects_hash_mismatch(tmp_path, monkeypatch):
    from ghosted import updater

    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setattr(updater, "_fetch", lambda url: b"FAKE-INSTALLER")
    r = updater.download({"url": "https://x/Ghosted-Setup.exe", "sha256": "deadbeef"})
    assert r["ok"] is False and "mismatch" in r["error"]


def test_download_ok_with_matching_hash(tmp_path, monkeypatch):
    from ghosted import updater

    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    body = b"INSTALLER-BYTES-that-are-benign"
    monkeypatch.setattr(updater, "_fetch", lambda url: body)
    r = updater.download({"url": "https://x/Ghosted-Setup.exe",
                          "sha256": hashlib.sha256(body).hexdigest()})
    assert r["ok"] is True and r["path"].endswith("Ghosted-Setup.exe")
