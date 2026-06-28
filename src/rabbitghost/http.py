"""Ghosted's own masked HTTP GET — stdlib urllib baseline, zero deps.

Decoupled from rabbit.core.sovereign_downloader. A standalone tool fetches with
its own client. Sends a browser-like User-Agent; richer TLS impersonation / Tor
masking can be layered later by ghosted/web.py without changing this contract.
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
    """Fetch *url* with a browser-like UA over TLS. Fail-soft (never raises)."""
    timeout = max(int(connect_timeout or 0), int(read_timeout or 0)) or 15
    req = urllib.request.Request(
        url, headers={"User-Agent": _UA, **(headers or {})}
    )
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
