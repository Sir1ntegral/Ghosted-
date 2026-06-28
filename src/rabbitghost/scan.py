"""
EDR-lite — a standalone file-safety scanner for RabbitGhost (no YARA, no cloud, no deps).

The README advertises that fetched files are scanned; that scanning lives in the rabbit
mind. Run standalone, this module is RabbitGhost's own lightweight analogue: dependency-
free heuristics over a file, an optional consult of the rabbit EDR when present, and an
inert quarantine for anything that trips the bar. It is a triage aid, not a full AV.
"""

from __future__ import annotations

import hashlib
import math
import os
import shutil
import time

# Extensions that can execute / script on Windows.
_RISKY_EXT = {
    ".exe",
    ".scr",
    ".com",
    ".pif",
    ".bat",
    ".cmd",
    ".ps1",
    ".psm1",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".wsh",
    ".hta",
    ".jar",
    ".msi",
    ".dll",
    ".cpl",
    ".lnk",
    ".reg",
    ".sys",
}
_EXE_EXT = {".exe", ".dll", ".scr", ".sys", ".com", ".cpl", ".msi"}

# First-bytes magic -> type sniff (don't trust the extension alone).
_MAGIC = [
    (b"MZ", "pe-executable"),
    (b"\x7fELF", "elf-executable"),
    (b"PK\x03\x04", "zip/office/jar"),
    (b"%PDF", "pdf"),
    (b"#!", "script-shebang"),
]

# Known-bad SHA-256 digests (extend as intel arrives). Lowercase hex.
_DENYLIST_SHA256: set[str] = set()


def _entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte (0..8). >7.2 over a sizeable file ~ packed/encrypted."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def _quarantine_dir() -> str:
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    d = os.path.join(base, "RabbitGhost", "quarantine")
    os.makedirs(d, exist_ok=True)
    return d


def scan_file(
    path: str, *, quarantine: bool = False, read_bytes: int = 1 << 20
) -> dict:
    """Heuristically assess a file's safety; return a verdict report.

    verdict is 'clean' / 'suspicious' / 'malicious' from a weighted score (denylist,
    risky extension, executable image, extension/content mismatch, high entropy). When
    quarantine=True and the verdict is 'malicious', the file is moved (inert, renamed)
    into the quarantine vault and the original path is freed.
    """
    if not os.path.isfile(path):
        return {"verdict": "error", "error": "not a file", "path": path}
    size = os.path.getsize(path)
    sha = hashlib.sha256()
    head = b""
    with open(path, "rb") as fh:
        head = fh.read(read_bytes)
        sha.update(head)
        for chunk in iter(lambda: fh.read(65536), b""):
            sha.update(chunk)
    digest = sha.hexdigest()
    ext = os.path.splitext(path)[1].lower()
    sniff = next((name for magic, name in _MAGIC if head.startswith(magic)), "data")
    ent = _entropy(head)

    reasons: list[str] = []
    score = 0
    if digest in _DENYLIST_SHA256:
        score += 100
        reasons.append("sha256 on denylist")
    if ext in _RISKY_EXT:
        score += 30
        reasons.append(f"risky extension {ext}")
    if sniff in ("pe-executable", "elf-executable"):
        score += 30
        reasons.append(f"executable image ({sniff})")
    if sniff == "pe-executable" and ext not in _EXE_EXT:
        score += 25
        reasons.append("executable masquerading under a non-exe extension")
    if ent > 7.2 and size > 4096:
        score += 15
        reasons.append(f"high entropy {ent:.2f} (packed/encrypted)")
    if size == 0:
        reasons.append("empty file")

    verdict = "malicious" if score >= 60 else ("suspicious" if score >= 30 else "clean")

    # Defense in depth: consult the rabbit mind's EDR if this host has it.
    rabbit_edr = None
    try:
        from rabbit.security.edr import scan_path as _rabbit_scan  # type: ignore

        rabbit_edr = _rabbit_scan(path)
    except Exception:
        rabbit_edr = None

    report = {
        "path": path,
        "sha256": digest,
        "size": size,
        "type": sniff,
        "extension": ext,
        "entropy": round(ent, 2),
        "score": score,
        "reasons": reasons,
        "verdict": verdict,
        "rabbit_edr": rabbit_edr,
    }
    if quarantine and verdict == "malicious":
        report["quarantined"] = _quarantine(path, digest)
    return report


def _quarantine(path: str, digest: str) -> str:
    """Move a file into the inert quarantine vault, renamed so it cannot execute."""
    import json

    qdir = _quarantine_dir()
    stamp = int(time.time() * 1000)
    base = os.path.basename(path)
    dest = os.path.join(qdir, f"{stamp}-{digest[:12]}-{base}.quarantined")
    shutil.move(path, dest)
    with open(dest + ".json", "w", encoding="utf-8") as fh:
        json.dump({"original": path, "sha256": digest, "ts": stamp}, fh)
    return dest
