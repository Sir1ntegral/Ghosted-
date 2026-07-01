"""
Ghosted — sovereign Tor manager.

Makes the Tor egress face ALWAYS work: locates a tor binary, launches a MANAGED Tor
daemon (SOCKS proxy on 127.0.0.1:9050) with its own data directory under the app, and
bootstraps it in the background. The browser/recon Tor paths call ensure() to wait
briefly for the circuit; everything still falls back to clearnet if Tor genuinely can't
start, so a request never hard-fails.

Binary search order: $GHOSTED_TOR → bundled (PyInstaller) → Tor Browser default
locations → tor/tor.exe on PATH. Pure-stdlib process + socket management, zero deps.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import threading
import time

SOCKS_PORT = 9050
_LOCK = threading.Lock()
_PROC: subprocess.Popen | None = None


def _candidates():
    env = os.environ.get("GHOSTED_TOR")
    if env:
        yield env
    base = getattr(sys, "_MEIPASS", None)
    if base:
        yield os.path.join(base, "tor", "tor.exe")
        yield os.path.join(base, "tor.exe")
        yield os.path.join(base, "tor", "tor")
    home = os.path.expanduser("~")
    rel = os.path.join("Tor Browser", "Browser", "TorBrowser", "Tor", "tor.exe")
    yield os.path.join(home, "Desktop", rel)
    for p in (os.environ.get("ProgramFiles", ""), os.environ.get("ProgramFiles(x86)", ""),
              os.environ.get("LOCALAPPDATA", ""), home):
        if p:
            yield os.path.join(p, rel)
    # Linux/mac system tor
    yield "/usr/bin/tor"
    yield "/usr/local/bin/tor"
    yield "tor.exe"
    yield "tor"


def tor_binary() -> str | None:
    """Path to a usable tor binary, or None if none is found."""
    for c in _candidates():
        if not c:
            continue
        if os.path.isfile(c):
            return c
        w = shutil.which(c)
        if w:
            return w
    return None


def is_socks_up(host: str = "127.0.0.1", port: int = SOCKS_PORT, timeout: float = 0.6) -> bool:
    """True if something is accepting connections on the Tor SOCKS port."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def _data_dir() -> str:
    try:
        from ghosted.mail import _data_root

        d = os.path.join(_data_root(), "tor")
    except Exception:
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        d = os.path.join(base, "Ghosted", "tor")
    os.makedirs(d, exist_ok=True)
    return d


def start() -> dict:
    """Launch a managed Tor daemon if one isn't already listening. Non-blocking — Tor
    bootstraps in the background. Idempotent (safe to call on every app launch)."""
    global _PROC
    with _LOCK:
        if is_socks_up():
            return {"ok": True, "managed": False, "note": "tor already running on 9050"}
        if _PROC is not None and _PROC.poll() is None:
            return {"ok": True, "managed": True, "note": "managed tor is starting"}
        binary = tor_binary()
        if not binary:
            return {"ok": False,
                    "error": "no tor binary found — install Tor Browser or set GHOSTED_TOR"}
        try:
            flags = 0x08000000 if os.name == "nt" else 0  # CREATE_NO_WINDOW
            _PROC = subprocess.Popen(
                [binary, "--SocksPort", str(SOCKS_PORT), "--DataDirectory", _data_dir(),
                 "--ClientOnly", "1", "--AvoidDiskWrites", "1"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL, creationflags=flags,
            )
            return {"ok": True, "managed": True, "binary": binary,
                    "note": "tor launched — bootstrapping in the background"}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def circuit_ready(test_host: str = "check.torproject.org", test_port: int = 443,
                  timeout: float = 8.0) -> bool:
    """Probe whether Tor can actually CARRY traffic — i.e. a circuit is built — by doing
    a SOCKS5 CONNECT through 9050 to a real host. The SOCKS port opens within ~0.5s but
    can't route until circuits exist, so this (not is_socks_up) is the real readiness."""
    if not is_socks_up():
        return False
    s = None
    try:
        s = socket.create_connection(("127.0.0.1", SOCKS_PORT), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(b"\x05\x01\x00")  # SOCKS5 greeting: no-auth
        if s.recv(2) != b"\x05\x00":
            return False
        host_b = test_host.encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b + test_port.to_bytes(2, "big"))
        rep = s.recv(10)
        return len(rep) >= 2 and rep[1] == 0x00  # 0x00 = CONNECT succeeded → circuit up
    except Exception:
        return False
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass


def ensure(block: bool = True, timeout: float = 45.0) -> bool:
    """Make Tor usable: start it if needed and (optionally) wait for a real circuit.
    Returns True only once Tor can actually route traffic."""
    if circuit_ready():
        return True
    start()
    if not block:
        return is_socks_up()
    deadline = time.time() + timeout
    while time.time() < deadline:
        if circuit_ready():
            return True
        time.sleep(2.0)
    return circuit_ready()


def stop() -> bool:
    """Stop the managed Tor daemon (leaves an externally-run Tor alone)."""
    global _PROC
    with _LOCK:
        if _PROC is not None and _PROC.poll() is None:
            try:
                _PROC.terminate()
            except Exception:
                pass
            _PROC = None
            return True
    return False


def egress_ip() -> str:
    """The IP the world sees THROUGH Tor — proves the circuit actually works."""
    if not ensure(block=True, timeout=30):
        return "unavailable (tor not up)"
    try:
        from curl_cffi import requests as creq  # type: ignore

        r = creq.get(
            "https://api.ipify.org",
            proxies={"https": f"socks5h://127.0.0.1:{SOCKS_PORT}",
                     "http": f"socks5h://127.0.0.1:{SOCKS_PORT}"},
            timeout=20,
        )
        return (r.text or "").strip() or "unknown"
    except Exception as e:  # noqa: BLE001
        return f"unknown ({type(e).__name__})"


def status() -> dict:
    """Tor manager status for the console `tor` command / doctor."""
    up = is_socks_up()
    return {
        "binary": tor_binary() or "(none found — install Tor Browser or set GHOSTED_TOR)",
        "socks": f"127.0.0.1:{SOCKS_PORT}",
        "socks_up": up,
        "circuit_ready": circuit_ready() if up else False,
        "managed": _PROC is not None and _PROC.poll() is None,
    }
