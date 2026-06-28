"""
Contracts — the explicit interface between RabbitGhost (the tool) and the rabbit mind.

Every rabbit organ RabbitGhost borrows is declared here in ONE place: its module path,
the symbols it must expose, and what capability it backs. This makes the seam visible
and checkable instead of scattered across try/except imports.

`verify_contracts()` probes the current host and reports, per organ, whether it is
importable and exposes the expected surface — the single source of truth for "how much
of the mind is wired in right now, and what degrades if a piece is missing."

The Protocols below document the shape of the most-used organs for type readers; the
registry (CONTRACTS) is what the runtime check and the console `doctor` command use.
"""

from __future__ import annotations

import importlib
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class CryptoModule(Protocol):
    """rabbit.core.crypto — RABBIT-CIPHER-1 seal/open used by vault + mail."""

    def encrypt(self, plaintext: str, passphrase: str) -> Any: ...
    def decrypt(self, blob: Any, passphrase: str) -> str: ...


@runtime_checkable
class DownloaderModule(Protocol):
    """rabbit.core.sovereign_downloader — masked HTTP egress (.success/.body result)."""

    def sovereign_http_get(self, url: str, **kw: Any) -> Any: ...


# (organ key, module path, required symbols, capability it backs, hard|soft)
#   hard = a core command breaks without it; soft = a feature gracefully degrades.
CONTRACTS: list[tuple[str, str, list[str], str, str]] = [
    (
        "crypto",
        "rabbit.core.crypto",
        ["encrypt", "decrypt", "EncryptedBlob"],
        "vault + black-box mail (encrypt/decrypt)",
        "hard",
    ),
    (
        "wireguard",
        "rabbit.network.sovereign_wireguard",
        ["PackMesh"],
        "WireGuard mesh (network/mesh)",
        "hard",
    ),
    (
        "downloader",
        "rabbit.core.sovereign_downloader",
        ["sovereign_http_get"],
        "sovereign egress (connect/fetch/egress-IP)",
        "soft",
    ),
    (
        "browser",
        "rabbit.research.sovereign_browser_engine",
        ["SovereignBrowserEngine"],
        "web search (browse/recon/homepage)",
        "hard",
    ),
    (
        "gojo",
        "rabbit.security.boundary.gojo_boundary",
        ["GojoBoundaryGate"],
        "homepage remote boundary (advisory)",
        "soft",
    ),
    (
        "ghost_mode",
        "rabbit.security.ghost.ghost_mode",
        ["GhostMode"],
        "stealth recon/forge",
        "hard",
    ),
    (
        "ghost_cloak",
        "rabbit.security.ghost.ghost_cloak",
        ["GhostCloak"],
        "stego cloak/uncloak",
        "hard",
    ),
    (
        "semantic",
        "rabbit.core.sovereign_semantic",
        ["SovereignSemanticModel"],
        "meaning-ranking of search results",
        "soft",
    ),
    (
        "dominance",
        "rabbit.council.dominance",
        ["FacultyDominanceEngine"],
        "intent weighting of search results",
        "soft",
    ),
    (
        "ocr",
        "rabbit.perception.sovereign_ocr",
        ["SovereignOCR"],
        "image OCR in parse",
        "soft",
    ),
    ("maw", "rabbit.maw.maw", ["Maw"], "document extraction in parse", "soft"),
]


def verify_contracts() -> dict[str, Any]:
    """Probe every declared rabbit seam on this host.

    Returns a report: per-organ {ok, present, missing, error, capability, severity}
    plus a summary. ok == importable AND every required symbol present. A failed
    'soft' organ means a feature degrades; a failed 'hard' organ means a command is
    unavailable."""
    organs: dict[str, Any] = {}
    hard_broken: list[str] = []
    soft_broken: list[str] = []
    for key, mod_path, symbols, capability, severity in CONTRACTS:
        present: list[str] = []
        missing: list[str] = []
        error: str | None = None
        try:
            mod = importlib.import_module(mod_path)
            for s in symbols:
                (present if hasattr(mod, s) else missing).append(s)
        except Exception as exc:  # import failed entirely
            error = f"{type(exc).__name__}: {exc}"
            missing = list(symbols)
        ok = error is None and not missing
        if not ok:
            (hard_broken if severity == "hard" else soft_broken).append(key)
        organs[key] = {
            "ok": ok,
            "module": mod_path,
            "present": present,
            "missing": missing,
            "error": error,
            "capability": capability,
            "severity": severity,
        }
    total = len(CONTRACTS)
    wired = sum(1 for o in organs.values() if o["ok"])
    return {
        "wired": wired,
        "total": total,
        "all_ok": wired == total,
        "hard_broken": hard_broken,
        "soft_broken": soft_broken,
        "organs": organs,
    }
