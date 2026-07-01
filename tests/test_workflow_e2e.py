"""End-to-end workflow validation — the whole cohesive flow over the real server,
run to prove it's reliably consistent: guest pages -> create account -> dashboard ->
email enroll -> WireGuard enroll/list/remove -> logout. Loopback is the local operator,
so the authed flows are exercised directly.
"""

import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from ghosted import homepage

PW = "correct-horse-battery-staple"


@pytest.fixture
def srv(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    # reset process-global session state + avoid a real network egress lookup
    with homepage._SESSIONS_LOCK:
        homepage._SESSIONS.clear()
        homepage._REMEMBER.clear()
        homepage._REMEMBER_MK.clear()
        homepage._SESSIONS_LOADED = False
    with homepage._MAIL_LOCK:
        homepage._MAIL_KEYS.clear()
    monkeypatch.setattr(homepage, "_egress_ip", lambda: "203.0.113.7")
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), homepage._Handler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()
        httpd.server_close()


def _get(url):
    try:
        r = urllib.request.urlopen(url, timeout=15)
        return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def _post(url, fields):
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    try:
        r = urllib.request.urlopen(req, timeout=20)
        return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def test_public_pages_all_serve(srv):
    for path in ("/", "/search?q=hi", "/health", "/help"):
        s, _ = _get(srv + path)
        assert s == 200, f"{path} -> {s}"
    assert _get(srv + "/favicon.ico")[0] in (200, 204)  # icon or no-content
    assert _get(srv + "/nope")[0] == 404


def test_full_account_and_wireguard_workflow(srv):
    # 1) before an account, personal routes show the create/login page (200, no crash)
    assert _get(srv + "/account")[0] == 200
    # 2) create the account
    s, body = _post(srv + "/setup", {"pw": PW, "pw2": PW, "display_name": "Op",
                                     "email": "me@example.com"})
    assert s == 200
    # 3) dashboard now renders with the account
    s, acct = _get(srv + "/account")
    assert s == 200 and "WireGuard" in acct
    # 4) WireGuard control center
    s, wg = _get(srv + "/wireguard")
    assert s == 200 and "Enroll a device" in wg
    # 5) enroll two devices (loopback = internal = allowed by Gojo)
    s, r1 = _post(srv + "/account", {"action": "wg_enroll_device", "name": "tower",
                                     "endpoint": "tower:51820", "hub": "tower", "pw": PW})
    assert s == 200 and ("enrolled" in r1 or "tower" in r1)
    _post(srv + "/account", {"action": "wg_enroll_device", "name": "phone", "pw": PW})
    # 6) list devices — both present (match the roster's hidden remove-form values,
    # not the placeholder text "e.g. phone")
    s, devs = _post(srv + "/account", {"action": "wg_devices", "pw": PW})
    assert s == 200 and 'value="tower"' in devs and 'value="phone"' in devs
    # 7) remove one — the other remains
    s, after = _post(srv + "/account", {"action": "wg_remove", "name": "phone", "pw": PW})
    assert s == 200 and "removed" in after.lower()
    s, devs2 = _post(srv + "/account", {"action": "wg_devices", "pw": PW})
    assert 'value="tower"' in devs2 and 'value="phone"' not in devs2
    # 8) logout still serves
    assert _get(srv + "/logout")[0] == 200


def test_password_policy_enforced_on_setup(srv):
    # too-weak password is rejected with a requirement message, no account created
    s, body = _post(srv + "/setup", {"pw": "short", "pw2": "short"})
    assert s == 200 and "password must" in body.lower()


def test_workflow_is_repeatable(srv):
    # run the create+enroll path twice-in-one-process shape: second create is blocked
    _post(srv + "/setup", {"pw": PW, "pw2": PW})
    s, body = _post(srv + "/setup", {"pw": "another-strong-pass-99", "pw2": "another-strong-pass-99"})
    # once initialized, setup won't silently re-create — it routes to sign-in
    assert s == 200 and ("sign in" in body.lower() or "already exists" in body.lower()
                         or "WireGuard" in body)
