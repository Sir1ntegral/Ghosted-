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
  4. dial-up / RAS — if no link is up, dial a configured ISP (modem/PPP/VPN/broadband)
     via `rasdial`; if there's a door to the internet, Ghosted uses it.
  5. self-hotspot — Ghosted can stand up its own WiFi so peers join and the mesh runs
     over it (Windows netsh hostednetwork), sharing whatever path it got.

Security model — getting a LINK never costs anonymity. This layer only obtains a path;
WHAT crosses it stays protected by the egress layer regardless of the door used:
  • identity + location stay secure — sensitive egress rides Tor (auto-started, always
    available) over whatever link the ladder got, so the ISP/dial-up sees only Tor;
  • boring routes look boring — every fetch wears a real-browser TLS/JA3 mask
    (chrome/firefox/edge/safari/tor145), so Ghosted traffic is indistinguishable from
    ordinary browsing; the reachability probes here are themselves plain/boring.

Honest limit: zero physical link/radio AND no answerable dial-up = no traffic. This
coordinates every door that *does* exist; it cannot conjure one that doesn't.
"""

from __future__ import annotations

import os
import socket

from ghosted import transport


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


# ── dial-up (RAS / PPP) — the last-resort physical path to the ISP ────────────────
def dialup_entries() -> list[str]:
    """Configured dial-up / RAS connection names from the Windows phonebook(s)."""
    names: set[str] = set()
    for base in (os.environ.get("APPDATA"),
                 os.environ.get("PROGRAMDATA") or os.environ.get("ALLUSERSPROFILE")):
        if not base:
            continue
        pbk = os.path.join(base, "Microsoft", "Network", "Connections", "Pbk", "rasphone.pbk")
        try:
            with open(pbk, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if line.startswith("[") and line.endswith("]") and len(line) > 2:
                        names.add(line[1:-1])
        except Exception:
            continue
    return sorted(names)


def dialup_connect(name: str, username: str = "", password: str = "", timeout: float = 90.0) -> dict:
    """Dial a configured RAS / dial-up entry (modem → local ISP) via `rasdial`. With no
    credentials it uses the ones saved in the phonebook entry."""
    if os.name != "nt":
        return {"ok": False, "error": "dial-up (RAS) is Windows-only here"}
    if not (name or "").strip():
        return {"ok": False, "error": "a dial-up connection name is required"}
    import subprocess

    cmd = ["rasdial", name] + ([username, password] if username else [])
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"ok": r.returncode == 0, "name": name,
                "detail": (r.stdout or r.stderr).strip()[:300]}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "name": name, "error": str(e)}


def dialup_disconnect(name: str = "") -> dict:
    if os.name != "nt":
        return {"ok": False, "error": "Windows only"}
    import subprocess

    cmd = ["rasdial", name, "/disconnect"] if name else ["rasdial", "/disconnect"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return {"ok": r.returncode == 0, "detail": (r.stdout or r.stderr).strip()[:200]}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}


def ensure_online_any(timeout: float = 4.0, dialup: bool = True, creds: dict | None = None) -> dict:
    """Get online by ANY available means, in order: use an existing link (wifi / LAN /
    ethernet) if one works; otherwise DIAL a configured dial-up ISP (RAS) and retry.
    Reports the full ladder it tried, plus whether the anonymized Tor egress face is
    ready to carry sensitive traffic over whatever link was obtained. (Sharing the
    result is `start_hotspot`.)"""
    report: dict = {"online": online(timeout), "interfaces": interfaces(), "tried": []}
    if report["online"]:
        report["via"] = "existing link"
        report["tor_ready"] = _tor_ready()
        return report
    if dialup and os.name == "nt":
        for name in dialup_entries():
            u, p = (creds or {}).get(name, ("", ""))
            res = dialup_connect(name, u, p)
            report["tried"].append(res)
            if res.get("ok") and online(timeout):
                report["online"], report["via"] = True, f"dial-up: {name}"
                report["tor_ready"] = _tor_ready()
                return report
    report["via"] = "no path available (no link, no answerable dial-up)"
    report["tor_ready"] = False
    return report


def _tor_ready() -> bool:
    """Fast, non-blocking check: is Ghosted's Tor egress face able to carry traffic
    right now? Never starts Tor or blocks the ladder — fail-soft to False."""
    try:
        from ghosted import tor

        return bool(tor.circuit_ready())
    except Exception:
        return False


def sovereign_get(url: str, *, timeout: float = 15.0) -> dict:
    """Fetch a URL through the coordinated sovereign egress (ghost masks + Tor-by-
    default + clearnet fallback). If utterly offline, spool the intent for
    store-and-forward and report it — never a hard failure."""
    try:
        from ghosted.http import sovereign_http_get

        r = sovereign_http_get(
            url, connect_timeout=int(timeout), read_timeout=int(timeout)
        )
        if getattr(r, "success", False) and getattr(r, "body", None):
            return {"ok": True, "bytes": len(r.body), "via": "sovereign-masked"}
        return {"ok": False, "error": getattr(r, "error", "fetch failed")}
    except Exception as e:  # noqa: BLE001
        transport.Spool("fetch").enqueue({"url": url})
        return {"ok": False, "error": str(e), "spooled": True}


def flush_fetch() -> dict:
    """Replay spooled GETs (store-and-forward): re-attempt each queued URL through the
    sovereign egress and drop only those that now succeed. No-ops when offline."""
    sp = transport.Spool("fetch")

    def _send(payload: dict) -> bool:
        try:
            from ghosted.http import sovereign_http_get

            r = sovereign_http_get(payload["url"], connect_timeout=15, read_timeout=15)
            return bool(getattr(r, "success", False))
        except Exception:
            return False

    return sp.flush(_send)


def start_hotspot(ssid: str = "GhostedMesh", password: str = "ghostedmesh1234") -> dict:
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
