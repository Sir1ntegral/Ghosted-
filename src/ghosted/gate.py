"""Ghosted's own request boundary gate — pure-Python rate-limit + JSONL audit.

Decoupled from rabbit.security.boundary.gojo_boundary. A tool carries its own
simple DoS gate rather than summoning Rabbit's Gojo organ. Because Ghosted now
OWNS the gate, ``homepage_get`` is a *known* action it actively throttles per
client — upgrading the homepage boundary from advisory to a real enforcing
ceiling (loopback is admitted by the caller before this gate is consulted).

Contract preserved for homepage.py:
    GojoBoundaryGate(audit_log_path=...)
    .evaluate_request(actor_role=, action=, source_class=, metadata=) -> dict
        {"decision": "allow"|"deny", "reason": str, ...}
"""

from __future__ import annotations

import json
import threading
import time
from collections import defaultdict, deque

__all__ = ["GojoBoundaryGate"]

# Per-action ceilings: (max_requests, window_seconds) per client.
_LIMITS: dict[str, tuple[int, float]] = {
    "homepage_get": (60, 60.0),  # 60 requests / 60s per client IP
}
_DEFAULT_LIMIT: tuple[int, float] = (120, 60.0)

# Boundary policy: WHO (actor role) may perform each action, and FROM WHERE (source
# class). Gojo ENFORCES this — a request outside the allowed roles/sources is denied
# before it is ever throttled. Actions absent here carry no role/source boundary (they
# are still rate-limited). This is what makes Gojo a boundary, not just a rate limiter:
# e.g. only the local authenticated operator may drive WireGuard; a remote web visitor
# may only fetch the homepage.
_POLICY: dict[str, dict[str, frozenset[str]]] = {
    "homepage_get": {
        "roles": frozenset({"anonymous_web", "operator"}),
        "sources": frozenset({"internal", "network_remote", "network_mesh"}),
    },
    "wireguard_connect": {"roles": frozenset({"operator"}), "sources": frozenset({"internal"})},
    "wireguard_disconnect": {"roles": frozenset({"operator"}), "sources": frozenset({"internal"})},
    "wireguard_enroll": {"roles": frozenset({"operator"}), "sources": frozenset({"internal"})},
    "wireguard_remove": {"roles": frozenset({"operator"}), "sources": frozenset({"internal"})},
    "wireguard_join": {"roles": frozenset({"operator"}), "sources": frozenset({"internal"})},
}


class GojoBoundaryGate:
    """Per-(client, action) sliding-window rate limiter with JSONL audit."""

    def __init__(
        self,
        audit_log_path: str | None = None,
        limits: dict[str, tuple[int, float]] | None = None,
        policy: dict[str, dict[str, frozenset[str]]] | None = None,
    ) -> None:
        self._audit = audit_log_path or ""
        self._limits = dict(_LIMITS)
        if limits:
            self._limits.update(limits)
        self._policy = dict(_POLICY)
        if policy:
            self._policy.update(policy)
        self._hits: dict[tuple[str, str], deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def evaluate_request(
        self,
        *,
        actor_role: str,
        action: str,
        source_class: str,
        metadata: dict | None = None,
    ) -> dict:
        """Enforce the boundary (role + source class) then the per-client rate ceiling.

        A request whose actor_role / source_class is outside the action's policy is
        DENIED outright — Gojo's boundary — before any throttle accounting. Actions with
        no policy entry skip the boundary check and are only rate-limited.
        """
        pol = self._policy.get(action)
        if pol is not None:
            if actor_role not in pol["roles"]:
                verdict = {"decision": "deny", "reason": "role_not_permitted",
                           "action": action, "actor_role": actor_role}
                self._audit_write(actor_role, action, source_class, metadata, verdict)
                return verdict
            if source_class not in pol["sources"]:
                verdict = {"decision": "deny", "reason": "source_not_permitted",
                           "action": action, "source_class": source_class}
                self._audit_write(actor_role, action, source_class, metadata, verdict)
                return verdict
        limit, window = self._limits.get(action, _DEFAULT_LIMIT)
        client = str((metadata or {}).get("client", "?"))
        key = (client, action)
        now = time.monotonic()
        with self._lock:
            dq = self._hits[key]
            while dq and now - dq[0] > window:
                dq.popleft()
            if len(dq) >= limit:
                verdict = {
                    "decision": "deny",
                    "reason": "throttled",
                    "action": action,
                    "retry_after": round(window - (now - dq[0]), 1),
                }
            else:
                dq.append(now)
                verdict = {"decision": "allow", "reason": "ok", "action": action}
        self._audit_write(actor_role, action, source_class, metadata, verdict)
        return verdict

    def _audit_write(
        self,
        actor_role: str,
        action: str,
        source_class: str,
        metadata: dict | None,
        verdict: dict,
    ) -> None:
        if not self._audit:
            return
        try:
            rec = {
                "ts": time.time(),
                "actor_role": actor_role,
                "action": action,
                "source_class": source_class,
                "decision": verdict["decision"],
                "reason": verdict["reason"],
                "meta": metadata or {},
            }
            with open(self._audit, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except Exception:  # noqa: BLE001 — audit is best-effort, never blocks a request
            pass
