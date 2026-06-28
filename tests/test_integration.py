"""Integration tests — boot-to-function across the app.

Exercises the homepage routes, the login flow, the XSS guard, the security
headers, the gate logic, and that every module imports (boot). Needs the rabbit
mind on PYTHONPATH; skips cleanly if absent.
"""

import http.client
import os
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
pytest.importorskip(
    "rabbit.core.crypto", reason="requires the rabbit mind on PYTHONPATH"
)

_PORT = 7690


def _get(path, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", _PORT, timeout=20)
    c.request("GET", path, headers=headers or {})
    r = c.getresponse()
    body = r.read().decode("utf-8", "replace")
    return r, body


def _post(path, data, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", _PORT, timeout=20)
    h = {"Content-Type": "application/x-www-form-urlencoded"}
    h.update(headers or {})
    c.request("POST", path, body=data, headers=h)
    r = c.getresponse()
    r.read()
    return r


@pytest.fixture(scope="module", autouse=True)
def _server(tmp_path_factory):
    base = tmp_path_factory.mktemp("appdata")
    os.environ["LOCALAPPDATA"] = str(base)
    from rabbitghost import homepage as h
    from rabbitghost import vault

    vault.initialize("IntegrationPass123")
    threading.Thread(target=h.serve, kwargs={"port": _PORT}, daemon=True).start()
    time.sleep(2)
    yield


def test_boot_all_modules_import():
    import rabbitghost.console  # noqa: F401
    import rabbitghost.homepage  # noqa: F401
    import rabbitghost.mail  # noqa: F401
    import rabbitghost.semantic_search  # noqa: F401
    import rabbitghost.vault  # noqa: F401


def test_home_route_and_security_headers():
    r, body = _get("/")
    assert r.status == 200
    assert "Rabbit Search" in body
    assert r.getheader("X-Content-Type-Options") == "nosniff"
    assert r.getheader("X-Frame-Options") == "DENY"
    assert r.getheader("Referrer-Policy") == "no-referrer"


def test_search_route_returns_results():
    r, body = _get("/search?q=sovereign+rabbit")
    assert r.status == 200
    assert 'class="r"' in body
    assert "relevance" in body  # semantic ranker ran


def test_xss_guard_on_dangerous_href(monkeypatch):
    from rabbitghost import homepage as h

    def fake_search(_q):
        return [
            type(
                "R", (), {"title": "evil", "url": "javascript:alert(1)", "snippet": "x"}
            )()
        ]

    monkeypatch.setattr(h, "_search", fake_search)
    _, body = _get("/search?q=evil")
    assert "javascript:alert(1)" not in body.split("href=")[1][:30]  # not in the href
    assert 'href="#"' in body  # rendered inert


def test_login_flow_and_logout():
    # wrong password → login page (we hit POST directly; localhost is auto-authed for GET)
    bad = _post("/login", "pw=wrong")
    assert bad.status == 200
    # correct password → 303 + session cookie
    ok = _post("/login", "pw=IntegrationPass123")
    assert ok.status == 303
    assert "rg_session=" in (ok.getheader("Set-Cookie") or "")
    # logout clears the cookie
    out = _get("/logout")[0]
    assert out.status == 303


def test_login_body_cap():
    r = _post("/login", "pw=" + "A" * (70 * 1024))
    assert r.status == 413  # over the 64KB cap


def test_gate_logic_local_remote_expiry():
    from rabbitghost import homepage as h

    class H:
        def __init__(self, ip, cookie=""):
            self.client_address = (ip, 1)
            self.headers = {"Cookie": cookie}

    assert h._is_authed(H("127.0.0.1"))  # local open
    assert not h._is_authed(H("10.44.0.9"))  # remote, no session
    h._SESSIONS["live"] = time.time() + 999
    h._SESSIONS["dead"] = time.time() - 1
    assert h._is_authed(H("10.44.0.9", "rg_session=live"))
    assert not h._is_authed(H("10.44.0.9", "rg_session=dead"))  # expired evicted


def test_404():
    r, _ = _get("/nope")
    assert r.status == 404
