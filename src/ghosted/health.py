"""
Ghosted — device health monitoring.

A sovereign, pure-Python read of the machine's vitals + network + security posture.
Zero third-party deps: Windows numbers come from the Win32 API via ctypes, POSIX
numbers from /proc and stdlib. Every probe is wrapped so a single unsupported metric
degrades to {"ok": None} instead of crashing the report — the console `health`
command and the website /health panel both render from one call to snapshot().

Each metric carries a state: "ok" | "warn" | "critical" | None (unknown), so the UI
can colour it without re-deriving thresholds. overall() folds them into one word.
"""

from __future__ import annotations

import os
import shutil
import time
from typing import Any

_NT = os.name == "nt"


# ── CPU ────────────────────────────────────────────────────────────────────────
def _cpu_percent(sample: float = 0.18) -> float | None:
    """Whole-machine CPU utilisation %, sampled over a short window."""
    try:
        if _NT:
            import ctypes
            from ctypes import wintypes

            class _FT(ctypes.Structure):
                _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]

            def _times():
                idle, kern, user = _FT(), _FT(), _FT()
                ctypes.windll.kernel32.GetSystemTimes(
                    ctypes.byref(idle), ctypes.byref(kern), ctypes.byref(user)
                )
                q = lambda f: (f.high << 32) | f.low  # noqa: E731
                return q(idle), q(kern), q(user)

            i0, k0, u0 = _times()
            time.sleep(sample)
            i1, k1, u1 = _times()
            busy = (k1 - k0) + (u1 - u0) - (i1 - i0)
            total = (k1 - k0) + (u1 - u0)
            return round(100.0 * busy / total, 1) if total > 0 else 0.0
        # POSIX: derive from /proc/stat deltas
        def _stat():
            with open("/proc/stat") as fh:
                parts = [float(x) for x in fh.readline().split()[1:]]
            idle = parts[3] + (parts[4] if len(parts) > 4 else 0)
            return sum(parts), idle

        t0, i0 = _stat()
        time.sleep(sample)
        t1, i1 = _stat()
        dt, di = (t1 - t0), (i1 - i0)
        return round(100.0 * (dt - di) / dt, 1) if dt > 0 else 0.0
    except Exception:
        return None


# ── memory ──────────────────────────────────────────────────────────────────────
def _memory() -> dict[str, Any]:
    try:
        if _NT:
            import ctypes
            from ctypes import wintypes

            class _MS(ctypes.Structure):
                _fields_ = [
                    ("dwLength", wintypes.DWORD),
                    ("dwMemoryLoad", wintypes.DWORD),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            ms = _MS()
            ms.dwLength = ctypes.sizeof(_MS)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(ms))
            total, avail, pct = ms.ullTotalPhys, ms.ullAvailPhys, float(ms.dwMemoryLoad)
        else:
            info = {}
            with open("/proc/meminfo") as fh:
                for line in fh:
                    k, _, v = line.partition(":")
                    info[k.strip()] = int(v.strip().split()[0]) * 1024
            total = info.get("MemTotal", 0)
            avail = info.get("MemAvailable", info.get("MemFree", 0))
            pct = round(100.0 * (total - avail) / total, 1) if total else None
        return {
            "percent": pct,
            "used_gb": round((total - avail) / 1e9, 2),
            "total_gb": round(total / 1e9, 2),
            "state": _state(pct, 80, 92),
        }
    except Exception:
        return {"percent": None, "state": None}


# ── disk ──────────────────────────────────────────────────────────────────────
def _disk() -> dict[str, Any]:
    try:
        path = os.environ.get("SystemDrive", "C:") + "\\" if _NT else "/"
        u = shutil.disk_usage(path)
        pct = round(100.0 * u.used / u.total, 1) if u.total else None
        return {
            "path": path,
            "percent": pct,
            "used_gb": round(u.used / 1e9, 1),
            "free_gb": round(u.free / 1e9, 1),
            "total_gb": round(u.total / 1e9, 1),
            "state": _state(pct, 85, 95),
        }
    except Exception:
        return {"percent": None, "state": None}


# ── battery ──────────────────────────────────────────────────────────────────────
def _battery() -> dict[str, Any]:
    try:
        if _NT:
            import ctypes

            class _SPS(ctypes.Structure):
                _fields_ = [
                    ("ACLineStatus", ctypes.c_byte),
                    ("BatteryFlag", ctypes.c_byte),
                    ("BatteryLifePercent", ctypes.c_byte),
                    ("SystemStatusFlag", ctypes.c_byte),
                    ("BatteryLifeTime", ctypes.c_ulong),
                    ("BatteryFullLifeTime", ctypes.c_ulong),
                ]

            sps = _SPS()
            if not ctypes.windll.kernel32.GetSystemPowerStatus(ctypes.byref(sps)):
                return {"present": None}
            pct = int(sps.BatteryLifePercent)
            if pct == 255 or (sps.BatteryFlag & 128):  # 255/flag128 = no battery
                return {"present": False, "plugged": sps.ACLineStatus == 1}
            plugged = sps.ACLineStatus == 1
            # low + unplugged is the only battery-driven warn/critical
            st = "ok"
            if not plugged and pct <= 10:
                st = "critical"
            elif not plugged and pct <= 25:
                st = "warn"
            return {"present": True, "percent": pct, "plugged": plugged, "state": st}
        # POSIX
        base = "/sys/class/power_supply"
        for name in os.listdir(base) if os.path.isdir(base) else []:
            cap = os.path.join(base, name, "capacity")
            if os.path.exists(cap):
                with open(cap) as fh:
                    pct = int(fh.read().strip())
                return {"present": True, "percent": pct, "state": "ok"}
        return {"present": False}
    except Exception:
        return {"present": None}


# ── uptime ──────────────────────────────────────────────────────────────────────
def _uptime() -> dict[str, Any]:
    try:
        if _NT:
            import ctypes

            ms = ctypes.windll.kernel32.GetTickCount64()
            secs = int(ms / 1000)
        else:
            with open("/proc/uptime") as fh:
                secs = int(float(fh.read().split()[0]))
        d, rem = divmod(secs, 86400)
        h, rem = divmod(rem, 3600)
        m = rem // 60
        human = (f"{d}d " if d else "") + f"{h}h {m}m"
        return {"seconds": secs, "human": human.strip()}
    except Exception:
        return {"seconds": None, "human": "unknown"}


# ── network / connectivity ───────────────────────────────────────────────────────
def _network() -> dict[str, Any]:
    try:
        from ghosted import connectivity

        online = bool(connectivity.online(timeout=2.5))
        try:
            ifaces = connectivity.interfaces()
        except Exception:
            ifaces = []
        return {
            "online": online,
            "interfaces": ifaces,
            "state": "ok" if online else "warn",
        }
    except Exception:
        return {"online": None, "interfaces": [], "state": None}


# ── security posture ──────────────────────────────────────────────────────────────
def _security() -> dict[str, Any]:
    """EDR-lite availability + egress exposure. Posture, not a live scan."""
    out: dict[str, Any] = {}
    try:
        from ghosted import scan  # EDR-lite file scanner present?

        out["edr"] = "available" if hasattr(scan, "scan_file") else "absent"
    except Exception:
        out["edr"] = "absent"
    try:
        from ghosted import vault

        out["vault"] = "initialized" if vault.is_initialized() else "not set"
    except Exception:
        out["vault"] = "unknown"
    try:
        from ghosted.http import sovereign_http_get

        r = sovereign_http_get(
            "https://api.ipify.org", connect_timeout=4, read_timeout=4
        )
        out["egress_ip"] = (
            r.body.decode(errors="replace").strip()
            if (getattr(r, "success", False) and r.body)
            else "unknown"
        )
    except Exception:
        out["egress_ip"] = "unknown"
    out["state"] = "ok" if out.get("edr") == "available" else "warn"
    return out


# ── helpers ──────────────────────────────────────────────────────────────────────
def _state(pct: float | None, warn: float, crit: float) -> str | None:
    if pct is None:
        return None
    if pct >= crit:
        return "critical"
    if pct >= warn:
        return "warn"
    return "ok"


def overall(snap: dict[str, Any]) -> str:
    """Fold every metric's state into one word for the headline."""
    states = []
    for k in ("cpu", "memory", "disk", "battery", "network", "security"):
        v = snap.get(k)
        if isinstance(v, dict):
            states.append(v.get("state"))
    if "critical" in states:
        return "critical"
    if "warn" in states:
        return "degraded"
    if any(s == "ok" for s in states):
        return "healthy"
    return "unknown"


def snapshot() -> dict[str, Any]:
    """One full device-health read. Never raises; unknown metrics report None."""
    cpu = _cpu_percent()
    snap: dict[str, Any] = {
        "cpu": {"percent": cpu, "state": _state(cpu, 85, 96)},
        "memory": _memory(),
        "disk": _disk(),
        "battery": _battery(),
        "uptime": _uptime(),
        "network": _network(),
        "security": _security(),
    }
    snap["overall"] = overall(snap)
    return snap


# Module self-check symbol used by contracts.verify_contracts / doctor.
def health() -> dict[str, Any]:
    """Public entry point — alias of snapshot() for the console `health` command."""
    return snapshot()
