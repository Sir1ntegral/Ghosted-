"""
Ghosted — WireGuard tunnel activator (Windows). Brings sealed mesh configs UP as REAL
tunnels via the official WireGuard for Windows service, guarded by Gojo and audited on
the security event bus.

Every activation runs through ``ghosted.security.guard`` first (Gojo boundary +
throttle + audit), then installs the tunnel with ``wireguard.exe /installtunnelservice``
(a real kernel WireGuard interface managed by the WireGuard service). Bring-down uses
``/uninstalltunnelservice``.

Honest boundary (never fakes a connection):
  • WireGuard for Windows not installed  → export the .conf + a one-line instruction,
    return ok=False. Nothing pretends to be connected.
  • Not elevated / service refuses       → surface the real error, unchanged.
Installing a tunnel service needs Administrator; that requirement is reported, not hidden.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from ghosted import event_bus, security

__all__ = [
    "wireguard_exe",
    "is_installed",
    "conf_dir",
    "connect",
    "disconnect",
    "status",
    "active_tunnels",
]

# Standard install locations for WireGuard for Windows.
_WG_CANDIDATES = (
    r"C:\Program Files\WireGuard\wireguard.exe",
    r"C:\Program Files (x86)\WireGuard\wireguard.exe",
)


def wireguard_exe() -> str | None:
    """Path to the official WireGuard for Windows CLI, or None if not installed."""
    env = os.environ.get("GHOSTED_WIREGUARD")
    if env and os.path.isfile(env):
        return env
    for c in _WG_CANDIDATES:
        if os.path.isfile(c):
            return c
    import shutil

    return shutil.which("wireguard") or shutil.which("wireguard.exe")


def is_installed() -> bool:
    return wireguard_exe() is not None


def conf_dir() -> str:
    """Directory where tunnel .conf files are written before activation (0700)."""
    try:
        from ghosted.mail import _data_root

        d = os.path.join(_data_root(), "wireguard")
    except Exception:
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        d = os.path.join(base, "Ghosted", "wireguard")
    os.makedirs(d, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except Exception:
        pass
    return d


def _write_conf(name: str, conf_text: str) -> str:
    """Write a tunnel config to conf_dir/<name>.conf with tight perms. Returns path."""
    safe = "".join(c for c in name if c.isalnum() or c in ("-", "_")) or "ghosted"
    path = os.path.join(conf_dir(), f"{safe}.conf")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(conf_text)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass
    return path


def connect(name: str, conf_text: str, *, actor_role: str = "operator") -> dict:
    """Bring tunnel *name* UP from *conf_text* as a real WireGuard service.

    Guarded by Gojo first; then, if WireGuard for Windows is present, installs the
    tunnel service. If WireGuard is absent, exports the .conf and returns ok=False with
    a clear hint — it never reports a connection that did not happen.
    """
    verdict = security.guard(
        action="wireguard_connect",
        actor_role=actor_role,
        source_class="internal",
        metadata={"name": name},
    )
    if verdict.get("decision") != "allow":
        return {"ok": False, "name": name, "error": "blocked by boundary",
                "reason": verdict.get("reason", "denied")}

    path = _write_conf(name, conf_text)
    exe = wireguard_exe()
    if not exe:
        event_bus.announce({
            "component": "wireguard", "event_type": "connect_export_only",
            "name": name, "severity": "warning",
            "reason": "wireguard_for_windows_not_installed",
        })
        return {
            "ok": False, "name": name, "exported": path,
            "error": "WireGuard for Windows is not installed",
            "hint": f'install WireGuard, then: wireguard.exe /installtunnelservice "{path}"',
        }

    if os.name != "nt":
        return {"ok": False, "name": name, "exported": path,
                "error": "tunnel activation is Windows-only (wireguard.exe)"}

    try:
        r = subprocess.run(
            [exe, "/installtunnelservice", path],
            capture_output=True, text=True, timeout=40,
        )
        ok = r.returncode == 0
        detail = (r.stdout or r.stderr).strip()[:300]
    except Exception as e:  # noqa: BLE001
        ok, detail = False, f"{type(e).__name__}: {e}"

    event_bus.announce({
        "component": "wireguard",
        "event_type": "connect" if ok else "connect_failed",
        "name": name, "severity": "info" if ok else "warning",
        "detail": detail,
    })
    result = {"ok": ok, "name": name, "detail": detail}
    if not ok and ("admin" in detail.lower() or "access" in detail.lower()):
        result["hint"] = "installing a tunnel service requires Administrator"
    return result


def disconnect(name: str, *, actor_role: str = "operator") -> dict:
    """Bring tunnel *name* DOWN (uninstall its WireGuard service). Guarded + audited."""
    security.guard(
        action="wireguard_disconnect", actor_role=actor_role,
        source_class="internal", metadata={"name": name},
    )
    exe = wireguard_exe()
    if not exe:
        return {"ok": False, "name": name, "error": "WireGuard for Windows not installed"}
    safe = "".join(c for c in name if c.isalnum() or c in ("-", "_")) or name
    try:
        r = subprocess.run(
            [exe, "/uninstalltunnelservice", safe],
            capture_output=True, text=True, timeout=30,
        )
        ok = r.returncode == 0
        detail = (r.stdout or r.stderr).strip()[:300]
    except Exception as e:  # noqa: BLE001
        ok, detail = False, f"{type(e).__name__}: {e}"
    event_bus.announce({
        "component": "wireguard", "event_type": "disconnect" if ok else "disconnect_failed",
        "name": name, "severity": "info" if ok else "warning", "detail": detail,
    })
    return {"ok": ok, "name": name, "detail": detail}


def active_tunnels() -> list[str]:
    """Names of WireGuard tunnel services currently installed on this machine."""
    if os.name != "nt":
        return []
    try:
        r = subprocess.run(
            ["sc", "query", "type=", "service", "state=", "all"],
            capture_output=True, text=True, timeout=15,
        )
    except Exception:
        return []
    names: list[str] = []
    for line in (r.stdout or "").splitlines():
        line = line.strip()
        if line.upper().startswith("SERVICE_NAME:") and "WireGuardTunnel$" in line:
            names.append(line.split("WireGuardTunnel$", 1)[1].strip())
    return names


def status() -> dict:
    """Tunnel-activation status for the console / account page / doctor."""
    return {
        "installed": is_installed(),
        "wireguard_exe": wireguard_exe() or "(not found — install WireGuard for Windows)",
        "active_tunnels": active_tunnels(),
        "conf_dir": conf_dir(),
    }
