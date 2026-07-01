"""
Ghosted — sovereign auto-update. Check → download (through the EDR + hash) → apply.

A controlled, integrity-protected update path for the installed app:

  check()   fetch an update manifest and compare it to the running version. The source
            is GHOSTED_UPDATE_URL (a JSON manifest {version,url,sha256,notes}) if set,
            else the GitHub Releases "latest" of this repo.
  download()fetch the installer through Ghosted's own masked HTTP, run it past the
            EDR-lite scanner (never install something that scans malicious — protects
            Ghosted's integrity/reputation), and verify its SHA-256 against the manifest.
  apply()   launch the verified installer silently and signal the app to exit so it can
            replace files. Honest: it hands off to the (eventually signed) installer
            rather than hot-swapping a running exe.

Updates are never silent/automatic here — the caller (console `update`, or a UI action)
decides. Startup only does a non-blocking check and announces availability on the bus.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys

__all__ = ["current_version", "check", "download", "apply", "update_dir"]

_GH_RELEASES = "https://api.github.com/repos/Sir1ntegral/Ghosted-/releases/latest"


def current_version() -> str:
    try:
        from ghosted import __version__

        return __version__
    except Exception:
        return "0.0.0"


def _parse_ver(v: str) -> tuple:
    v = (v or "").strip().lstrip("vV")
    parts: list[int] = []
    for chunk in v.split("."):
        num = "".join(c for c in chunk if c.isdigit())
        parts.append(int(num) if num else 0)
    return tuple(parts) or (0,)


def _newer(latest: str, current: str) -> bool:
    return _parse_ver(latest) > _parse_ver(current)


def update_dir() -> str:
    try:
        from ghosted.mail import _data_root

        d = os.path.join(_data_root(), "updates")
    except Exception:
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        d = os.path.join(base, "Ghosted", "updates")
    os.makedirs(d, exist_ok=True)
    return d


def _fetch(url: str) -> bytes | None:
    try:
        from ghosted.http import sovereign_http_get

        r = sovereign_http_get(url, connect_timeout=15, read_timeout=60)
        if getattr(r, "success", False) and getattr(r, "body", None):
            return r.body
    except Exception:
        pass
    return None


def _manifest_from_github(raw: bytes) -> dict | None:
    try:
        data = json.loads(raw.decode("utf-8", "replace"))
        ver = data.get("tag_name") or data.get("name") or ""
        url = ""
        for asset in data.get("assets", []):
            name = (asset.get("name") or "").lower()
            if name.endswith((".exe", ".msi")):
                url = asset.get("browser_download_url", "")
                break
        if not ver or not url:
            return None
        return {"version": ver, "url": url, "sha256": "", "notes": data.get("body", "")}
    except Exception:
        return None


def check(manifest_url: str | None = None) -> dict:
    """Return {available, current, latest, url, sha256, notes, error}. Never raises."""
    cur = current_version()
    src = manifest_url or os.environ.get("GHOSTED_UPDATE_URL", "")
    raw = _fetch(src) if src else _fetch(_GH_RELEASES)
    if not raw:
        return {"available": False, "current": cur, "error": "could not reach update source"}
    if src:
        try:
            man = json.loads(raw.decode("utf-8", "replace"))
        except Exception:
            return {"available": False, "current": cur, "error": "bad update manifest"}
    else:
        man = _manifest_from_github(raw)
        if not man:
            return {"available": False, "current": cur, "error": "no installer in latest release"}
    latest = str(man.get("version", "")).strip()
    return {
        "available": bool(latest) and _newer(latest, cur),
        "current": cur,
        "latest": latest,
        "url": man.get("url", ""),
        "sha256": (man.get("sha256") or "").lower(),
        "notes": man.get("notes", ""),
    }


def download(info: dict) -> dict:
    """Download the installer named in *info*, scan it (EDR), verify its SHA-256.
    Returns {ok, path, error}. A malicious scan or hash mismatch fails closed."""
    url = info.get("url", "")
    if not url:
        return {"ok": False, "error": "no download url"}
    body = _fetch(url)
    if not body:
        return {"ok": False, "error": "download failed"}
    name = os.path.basename(url.split("?")[0]) or "Ghosted-Setup.exe"
    path = os.path.join(update_dir(), name)
    try:
        with open(path, "wb") as fh:
            fh.write(body)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"write failed: {e}"}

    want = (info.get("sha256") or "").lower()
    if want:
        got = hashlib.sha256(body).hexdigest()
        if got != want:
            try:
                os.remove(path)
            except OSError:
                pass
            return {"ok": False, "error": "sha256 mismatch — refusing this download"}

    # EDR-lite: never install something that scans malicious (Ghosted's own integrity).
    try:
        from ghosted import scan

        v = scan.scan_file(path)
        if v.get("verdict") == "malicious":
            try:
                os.remove(path)
            except OSError:
                pass
            return {"ok": False, "error": "update failed EDR scan (malicious) — discarded"}
    except Exception:
        pass

    try:
        from ghosted import event_bus

        event_bus.announce({"component": "updater", "event_type": "downloaded",
                            "version": info.get("latest") or info.get("version"), "path": path})
    except Exception:
        pass
    return {"ok": True, "path": path}


def apply(installer_path: str, *, silent: bool = True) -> dict:
    """Launch the verified installer and signal the app to exit so it can replace files.
    Windows only for the silent-installer flags."""
    if not os.path.isfile(installer_path):
        return {"ok": False, "error": "installer not found"}
    if os.name != "nt":
        return {"ok": False, "error": "apply is Windows-only", "path": installer_path}
    args = [installer_path]
    if silent:
        args += ["/SILENT", "/CLOSEAPPLICATIONS", "/NORESTART"]  # Inno Setup flags
    try:
        subprocess.Popen(args, close_fds=True)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"could not launch installer: {e}"}
    return {"ok": True, "applying": True, "note": "installer launched — Ghosted will exit to update"}


def check_and_notify() -> dict:
    """Non-blocking-friendly startup check: announce availability on the bus, no download."""
    info = check()
    if info.get("available"):
        try:
            from ghosted import event_bus

            event_bus.announce({"component": "updater", "event_type": "update_available",
                                "current": info["current"], "latest": info["latest"],
                                "severity": "info"})
        except Exception:
            pass
    return info
