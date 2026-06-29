"""Tests for the new capabilities: health, spell-check, feedback, open-use, contracts.

All offline / no network — health reads the local machine, the rest are pure logic.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ghosted import contracts, feedback, health, spellcheck  # noqa: E402


# ── device health ──────────────────────────────────────────────────────────────
def test_health_snapshot_shape():
    snap = health.snapshot()
    for key in ("cpu", "memory", "disk", "battery", "uptime", "network", "security", "overall"):
        assert key in snap
    assert snap["overall"] in ("healthy", "degraded", "critical", "unknown")


def test_health_never_raises_and_states_valid():
    snap = health.snapshot()
    for k in ("cpu", "memory", "disk"):
        st = snap[k].get("state")
        assert st in ("ok", "warn", "critical", None)


# ── spell-check ──────────────────────────────────────────────────────────────────
def test_spellcheck_fixes_obvious_typos():
    for typo, fixed in [
        ("privcy tols", "privacy tools"),
        ("encyrption", "encryption"),
        ("helth montoring", "health monitoring"),
        ("passwrd", "password"),
    ]:
        r = spellcheck.correct(typo)
        assert r["changed"] is True
        assert r["corrected"] == fixed


def test_spellcheck_never_corrupts_real_words():
    # The cardinal sin of spell-check: changing a correctly-spelled word.
    for good in ["hello world", "the quick brown fox", "new york", "sovereign", "setup an account"]:
        r = spellcheck.correct(good)
        assert r["changed"] is False, f"false positive on {good!r} -> {r['corrected']!r}"


def test_spellcheck_short_words_untouched():
    assert spellcheck.correct("fox cat dog")["changed"] is False


# ── feedback + learning loop ─────────────────────────────────────────────────────
def test_feedback_records_and_boosts(tmp_path, monkeypatch):
    # isolate the store to a temp file
    monkeypatch.setattr(feedback, "_STATE", None, raising=False)
    monkeypatch.setattr(feedback, "_path", lambda: str(tmp_path / "fb.json"))
    feedback.record_search("privacy tools", 10)
    assert feedback.boost("privacy tools", "https://x.io/") == 0.0  # no engagement yet
    feedback.record_click("privacy tools", "https://x.io/", 0, dwell=20)
    feedback.record_rating("privacy tools", 1.0, "", "https://x.io/")
    assert feedback.boost("privacy tools", "https://x.io/") > 0.0
    s = feedback.summary()
    assert s["searches"] >= 1 and s["clicks"] >= 1 and s["ratings"] >= 1


def test_feedback_adaptivity_grows_with_data(tmp_path, monkeypatch):
    monkeypatch.setattr(feedback, "_STATE", None, raising=False)
    monkeypatch.setattr(feedback, "_path", lambda: str(tmp_path / "fb2.json"))
    a0 = feedback.adaptivity()
    for i in range(40):
        feedback.record_click("q", f"https://e/{i}", i, dwell=15)
    assert feedback.adaptivity() > a0
    assert feedback.adaptivity() <= 0.6  # bounded — earns influence, never runs away


def test_feedback_never_raises_on_garbage(tmp_path, monkeypatch):
    monkeypatch.setattr(feedback, "_STATE", None, raising=False)
    monkeypatch.setattr(feedback, "_path", lambda: str(tmp_path / "fb3.json"))
    feedback.record_click("", "", -1, 0)  # empty url ignored, no raise
    feedback.record_rating("q", 5.0)  # 1..5 scale mapped, no url
    assert isinstance(feedback.summary(), dict)


# ── contracts / doctor ───────────────────────────────────────────────────────────
def test_doctor_includes_new_capabilities():
    report = contracts.verify_contracts()
    keys = set(report["organs"])
    for cap in ("health", "spellcheck", "feedback", "setup"):
        assert cap in keys
    assert not report["broken"]
