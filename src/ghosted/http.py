"""Ghosted's own masked HTTP GET.

Decoupled from rabbit.core.sovereign_downloader. A standalone tool fetches with its
own client. When curl_cffi is present the request wears a real-browser TLS/JA3 mask
(Chrome impersonation) so it blends in on the wire; otherwise it degrades to a stdlib
urllib client with a browser User-Agent (zero-dep baseline). Anonymized (Tor) egress
is the browser/sensitive path in ghosted/web.py + ghosted/tor.py — this helper is
clearnet by design (it also backs the egress-IP display, which must show real exposure).
Never raises — always returns a result object.

Contract preserved for homepage.py / connectivity.py:
    sovereign_http_get(url, connect_timeout=, read_timeout=) -> resp
        resp.success: bool   resp.body: bytes   resp.status: int   resp.error: str
"""

from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass

__all__ = ["sovereign_http_get", "HttpResult"]

_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


@dataclass
class HttpResult:
    """Result of a fetch. Mirrors the rabbit downloader's .success/.body/.error."""

    success: bool
    body: bytes = b""
    status: int = 0
    error: str = ""


def sovereign_http_get(
    url: str,
    *,
    connect_timeout: float = 15,
    read_timeout: float = 15,
    headers: dict | None = None,
) -> HttpResult:
    """Fetch *url* with a real-browser TLS/JA3 mask (curl_cffi) when available, else a
    stdlib urllib client with a browser UA. Fail-soft (never raises)."""
    timeout = max(int(connect_timeout or 0), int(read_timeout or 0)) or 15
    hdrs = {"User-Agent": _UA, **(headers or {})}

    # 1) TLS/JA3-masked path — a real Chrome fingerprint on the wire (blends in).
    try:
        from curl_cffi import requests as _creq

        r = _creq.get(url, headers=hdrs, impersonate="chrome", timeout=timeout)
        code = int(getattr(r, "status_code", 0) or 0)
        return HttpResult(
            success=200 <= code < 400,
            body=getattr(r, "content", b"") or b"",
            status=code,
            error="" if 200 <= code < 400 else f"HTTP {code}",
        )
    except Exception:  # noqa: BLE001 — curl_cffi absent/failed → stdlib baseline
        pass

    # 2) stdlib urllib baseline (zero-dep fallback).
    req = urllib.request.Request(url, headers=hdrs)
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return HttpResult(
                success=True,
                body=resp.read(),
                status=getattr(resp, "status", 200) or 200,
            )
    except urllib.error.HTTPError as exc:
        return HttpResult(success=False, status=exc.code, error=f"HTTP {exc.code}")
    except Exception as exc:  # noqa: BLE001 — fail-soft fetch, report not raise
        return HttpResult(success=False, error=str(exc))
