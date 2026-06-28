"""
Connectivity coordinator — ensure the internet always reaches out, in sync with ghost.

One sane, coordinated path to "always online":
  1. multi-interface reachability — probe across every local interface (wifi / LAN /
     WAN); use whatever has a path (a dead interface or port is not fatal).
  2. sovereign egress — fetch through ghost's masked HTTP: the 5-engine TLS masks
     (chrome/firefox/edge/safari/tor145) + Tor-by-default + clearnet fallback, so the
     request "always enacts with the ISP" however the path is shaped.
  3. store-and-forward — if utterly offline, the intent is spooled and auto-completes
     the instant any link returns.
  4. self-hotspot — Rabbit can stand up its own WiFi so peers join and the mesh runs
     over it (Windows netsh hostednetwork).

Honest limit: zero physical link/radio = no traffic. This coordinates every path that
*does* exist; it cannot conjure one that doesn't.
"""

from __future__ import annotations

import os
import socket

from rabbitghost import transport


def interfaces() -> list[str]:
    """Local IPv4 addresses — each a candidate egress interface."""
    ips: set[str] = set()
    try:
        for fam, *_rest, sockaddr in socket.getaddrinfo(socket.gethostname(), None):
            if fam == socket.AF_INET:
                ips.add(sockaddr[0])
    except Exception:
        pass
    # the route the OS would actually use to reach out
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
    except Exception:
        pass
    finally:
        s.close()
    return sorted(ips)


def online(timeout: float = 3.0) -> bool:
    """Any sliver of connectivity, across any interface."""
    return transport.online(timeout=timeout)


def ensure_online(timeout: float = 4.0) -> dict:
    """Confirm a working path to the internet. Reports per-interface + overall."""
    return {"online": online(timeout), "interfaces": interfaces()}


def sovereign_get(url: str, *, timeout: float = 15.0) -> dict:
    """Fetch a URL through the coordinated sovereign egress (ghost masks + Tor-by-
    default + clearnet fallback). If utterly offline, spool the intent for
    store-and-forward and report it — never a hard failure."""
    try:
        from rabbit.core.sovereign_downloader import sovereign_http_get

        r = sovereign_http_get(
            url, connect_timeout=int(timeout), read_timeout=int(timeout)
        )
        if getattr(r, "success", False) and getattr(r, "body", None):
            return {"ok": True, "bytes": len(r.body), "via": "sovereign-masked"}
        return {"ok": False, "error": getattr(r, "error", "fetch failed")}
    except Exception as e:  # noqa: BLE001
        transport.Spool("fetch").enqueue({"url": url})
        return {"ok": False, "error": str(e), "spooled": True}


def start_hotspot(ssid: str = "RabbitMesh", password: str = "rabbitmesh1234") -> dict:
    """Stand up a WiFi hotspot so peers join + the mesh runs over it (Windows netsh).
    Needs admin + a hosted-network-capable adapter; reports the outcome, never crashes.
    """
    if os.name != "nt":
        return {"ok": False, "error": "self-hotspot is implemented for Windows here"}
    if len(password) < 8:
        return {"ok": False, "error": "hotspot password must be >= 8 chars"}
    import subprocess

    try:
        subprocess.run(
            [
                "netsh",
                "wlan",
                "set",
                "hostednetwork",
                "mode=allow",
                f"ssid={ssid}",
                f"key={password}",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=20,
        )
        r = subprocess.run(
            ["netsh", "wlan", "start", "hostednetwork"],
            capture_output=True,
            text=True,
            timeout=20,
        )
        ok = r.returncode == 0
        return {"ok": ok, "ssid": ssid, "detail": (r.stdout or r.stderr).strip()[:200]}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}


def stop_hotspot() -> dict:
    if os.name != "nt":
        return {"ok": False, "error": "Windows only"}
    import subprocess

    try:
        r = subprocess.run(
            ["netsh", "wlan", "stop", "hostednetwork"],
            capture_output=True,
            text=True,
            timeout=20,
        )
        return {"ok": r.returncode == 0, "detail": (r.stdout or r.stderr).strip()[:200]}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}
