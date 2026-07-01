"""End-to-end HTTP tests — start the real server and exercise routes over the wire.

Complements the function-level tests: this drives the actual ThreadingHTTPServer +
_Handler + routing stack. (127.0.0.1 is loopback, which the app treats as the local
operator, so these cover the served pages; remote/Gojo denial is unit-tested in
test_gate/test_wireguard.)
"""

import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from ghosted import homepage


@pytest.fixture
def base_url(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
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
        r = urllib.request.urlopen(url, timeout=10)
        return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def test_homepage_serves(base_url):
    s, b = _get(base_url + "/")
    assert s == 200 and "Ghosted" in b and "<form" in b


def test_health_route(base_url):
    s, _ = _get(base_url + "/health")
    assert s == 200


def test_search_route(base_url):
    s, _ = _get(base_url + "/search?q=hello")
    assert s == 200


def test_help_route(base_url):
    s, _ = _get(base_url + "/help")
    assert s == 200


def test_unknown_route_404(base_url):
    s, _ = _get(base_url + "/definitely-not-a-route")
    assert s == 404


def test_wireguard_route_never_crashes(base_url):
    # vault is uninitialized in a clean env → the personal route yields the login/
    # create page (200), never a 500. Confirms the route + auth gate wire up.
    s, _ = _get(base_url + "/wireguard")
    assert s == 200


def test_account_route_never_crashes(base_url):
    s, _ = _get(base_url + "/account")
    assert s == 200
