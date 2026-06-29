"""
Contracts — Ghosted's own capability registry (the `doctor` command's source of truth).

Ghosted is a standalone tool: it no longer borrows from the rabbit mind. Every
capability is now backed by one of Ghosted's OWN modules (always importable) plus,
where relevant, an OPTIONAL third-party library that upgrades it. This registry
declares each capability in one place — its module, the symbols it must expose, the
optional dep that enriches it, and what degrades when that dep is absent.

`verify_contracts()` probes the host and reports, per capability, whether its module
is wired and whether its optional backing dep is installed — the single answer to
"what can this install do right now, and what would `pip install ghosted[...]`
unlock."
"""

from __future__ import annotations

import importlib
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class CryptoModule(Protocol):
    """ghosted.crypto — GHOSTED-CIPHER-1 seal/open used by vault + mail."""

    def encrypt(self, plaintext: str, passphrase: str) -> Any: ...
    def decrypt(self, blob: Any, passphrase: str) -> str: ...


@runtime_checkable
class WebModule(Protocol):
    """ghosted.web — masked search/fetch (.web_search/.fetch_page)."""

    def web_search(self, query: str, **kw: Any) -> Any: ...


# (key, module path, required symbols, capability, optional_dep|None, degrade-note)
#   module is always one of Ghosted's own (so it imports); optional_dep, when set,
#   names the pip extra that enriches the capability beyond its pure-Python floor.
CONTRACTS: list[tuple[str, str, list[str], str, str | None, str]] = [
    ("crypto", "ghosted.crypto", ["encrypt", "decrypt", "EncryptedBlob"],
     "vault + black-box mail", None, "pure-Python — always available"),
    ("wireguard", "ghosted.wireguard", ["PackMesh"],
     "WireGuard mesh (network/mesh)", None, "pure-Python — always available"),
    ("http", "ghosted.http", ["sovereign_http_get"],
     "sovereign egress (connect/fetch/egress-IP)", None, "stdlib urllib floor"),
    ("gate", "ghosted.gate", ["GojoBoundaryGate"],
     "homepage remote boundary (rate-limit + audit)", None, "pure-Python — always available"),
    ("web", "ghosted.web", ["SovereignBrowserEngine"],
     "web search (browse/recon/homepage)", "curl_cffi",
     "without curl_cffi+bs4: stdlib fetch + regex parse"),
    ("ghost", "ghosted.ghost", ["GhostMode", "GhostCloak"],
     "stealth recon/forge + stego cloak", "PIL",
     "cloak/uncloak needs Pillow; recon/forge are pure-Python"),
    ("semantic", "ghosted.semantic_search", ["rerank"],
     "meaning-ranking of search results", "numpy",
     "without numpy + model: lexical + sentiment ranking"),
    ("ocr", "ghosted.ocr", ["OCR"],
     "image OCR in parse", "rapidocr_onnxruntime",
     "without an OCR backend: image text is empty"),
    ("docparse", "ghosted.docparse", ["Maw"],
     "document extraction in parse", "pypdf",
     "without pypdf/python-docx: pdf/docx degrade; stdlib formats fine"),
]


def verify_contracts() -> dict[str, Any]:
    """Probe every declared capability on this host.

    Returns a report: per-capability {ok, module_ok, dep_ok, present, missing,
    error, capability, optional_dep, note} plus a summary. ok == the module is
    importable with its symbols AND (if it declares an optional dep) that dep is
    installed. A capability whose module is wired but whose optional dep is absent
    is reported degraded, not broken."""
    organs: dict[str, Any] = {}
    degraded: list[str] = []
    broken: list[str] = []
    for key, mod_path, symbols, capability, optional_dep, note in CONTRACTS:
        present: list[str] = []
        missing: list[str] = []
        error: str | None = None
        try:
            mod = importlib.import_module(mod_path)
            for s in symbols:
                (present if hasattr(mod, s) else missing).append(s)
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            missing = list(symbols)
        module_ok = error is None and not missing

        dep_ok = True
        if optional_dep:
            try:
                importlib.import_module(optional_dep)
            except Exception:
                dep_ok = False

        ok = module_ok and dep_ok
        if not module_ok:
            broken.append(key)
        elif not dep_ok:
            degraded.append(key)
        organs[key] = {
            "ok": ok,
            "module": mod_path,
            "module_ok": module_ok,
            "dep_ok": dep_ok,
            "present": present,
            "missing": missing,
            "error": error,
            "capability": capability,
            "optional_dep": optional_dep,
            "note": note,
        }
    total = len(CONTRACTS)
    wired = sum(1 for o in organs.values() if o["ok"])
    return {
        "wired": wired,
        "total": total,
        "all_ok": wired == total,
        "broken": broken,        # module missing/incomplete — a real problem
        "degraded": degraded,    # module fine, optional dep absent — feature reduced
        "organs": organs,
    }
