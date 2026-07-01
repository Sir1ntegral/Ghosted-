"""Session persistence — a stay-logged-in session survives an app restart; a plain
session and expired tokens do not. The master password is never persisted."""

import time


def _reset(homepage):
    with homepage._SESSIONS_LOCK:
        homepage._SESSIONS.clear()
        homepage._REMEMBER.clear()
        homepage._SESSIONS_LOADED = False


class _Req:
    def __init__(self, ip, tok=None):
        self.client_address = (ip, 1)
        self.headers = {"Cookie": f"rg_session={tok}"} if tok else {}


def test_remember_session_survives_restart(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    from ghosted import homepage

    _reset(homepage)
    tok = "tok-remember"
    exp = time.time() + homepage._REMEMBER_TTL
    with homepage._SESSIONS_LOCK:
        homepage._SESSIONS[tok] = exp
        homepage._REMEMBER[tok] = exp
        homepage._save_persisted_sessions()
    # simulate an app restart: wipe all in-memory session state
    _reset(homepage)
    homepage._ensure_sessions_loaded()
    assert tok in homepage._SESSIONS
    # a remote request carrying the cookie is authed after the "restart"
    assert homepage._is_authed(_Req("8.8.8.8", tok)) is True


def test_plain_session_not_persisted(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    from ghosted import homepage

    _reset(homepage)
    tok = "tok-plain"
    with homepage._SESSIONS_LOCK:
        homepage._SESSIONS[tok] = time.time() + homepage._SESSION_TTL  # NOT in _REMEMBER
        homepage._save_persisted_sessions()
    _reset(homepage)
    homepage._ensure_sessions_loaded()
    assert tok not in homepage._SESSIONS  # a non-remember session dies with the app


def test_expired_persisted_session_dropped(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    from ghosted import homepage

    _reset(homepage)
    tok = "tok-old"
    with homepage._SESSIONS_LOCK:
        homepage._REMEMBER[tok] = time.time() - 10  # already expired
        homepage._save_persisted_sessions()
    _reset(homepage)
    homepage._ensure_sessions_loaded()
    assert tok not in homepage._SESSIONS


def test_logout_forgets_persisted_session(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    from ghosted import homepage

    _reset(homepage)
    tok = "tok-logout"
    exp = time.time() + homepage._REMEMBER_TTL
    with homepage._SESSIONS_LOCK:
        homepage._REMEMBER[tok] = exp
        homepage._save_persisted_sessions()
    # emulate logout removing it
    with homepage._SESSIONS_LOCK:
        homepage._REMEMBER.pop(tok, None)
        homepage._save_persisted_sessions()
    _reset(homepage)
    homepage._ensure_sessions_loaded()
    assert tok not in homepage._SESSIONS


def test_master_password_never_written_to_sessions_file(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    from ghosted import homepage

    _reset(homepage)
    tok = "tok-secret"
    exp = time.time() + homepage._REMEMBER_TTL
    with homepage._SESSIONS_LOCK:
        homepage._REMEMBER[tok] = exp
        homepage._save_persisted_sessions()
    # the persisted file holds only tokens+expiry, never a passphrase/mail key
    with open(homepage._sessions_path(), encoding="utf-8") as fh:
        raw = fh.read()
    assert "pass" not in raw.lower() and tok in raw
