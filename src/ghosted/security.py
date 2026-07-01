"""
Ghosted — sovereign security workflow. Gojo gate → decision → event bus → monitor.

This is the single chain every sensitive action runs through. ``guard()`` asks the
Gojo boundary gate (ghosted.gate) to allow or throttle the action, announces the
verdict on the security event bus (ghosted.event_bus), and returns it. A built-in
monitor subscribes to the bus and escalates when one actor piles up denials — a small,
closed detection→response loop.

WireGuard connect/enrollment are the first callers: Gojo guards the tunnel. Decoupled
from rabbit — Ghosted carries its own gate + bus + monitor rather than summoning
Rabbit's Watchtower. Fail-open by design: if the gate is unavailable the action is
allowed but still audited, so a broken gate never bricks the tool.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from typing import Any

from ghosted import event_bus

__all__ = ["guard", "allowed", "recent_events"]

_GATE: Any = None
_GATE_LOCK = threading.Lock()

# Deny-streak escalation: actor -> recent deny timestamps.
_DENY_STREAKS: dict[str, deque] = defaultdict(lambda: deque(maxlen=64))
_DENY_LOCK = threading.Lock()
_DENY_THRESHOLD = 5
_DENY_WINDOW = 300.0  # 5 minutes


def _gate() -> Any:
    global _GATE
    if _GATE is not None:
        return _GATE
    with _GATE_LOCK:
        if _GATE is None:
            from ghosted.gate import GojoBoundaryGate

            _GATE = GojoBoundaryGate(audit_log_path=event_bus.audit_path())
    return _GATE


def guard(
    *,
    action: str,
    actor_role: str = "operator",
    source_class: str = "internal",
    metadata: dict | None = None,
) -> dict:
    """Run a sensitive *action* through the Gojo gate, announce the verdict, return it.

    Returns the gate verdict dict ({"decision": "allow"|"deny", "reason": ...}). Fail
    open (allow) if the gate itself errors, but still announce it so nothing is silent.
    """
    md = metadata or {}
    try:
        verdict = _gate().evaluate_request(
            actor_role=actor_role,
            action=action,
            source_class=source_class,
            metadata=md,
        )
    except Exception as e:  # noqa: BLE001 — a broken gate must not brick the action
        verdict = {"decision": "allow", "reason": f"gate_unavailable:{type(e).__name__}"}

    decision = verdict.get("decision", "allow")
    event_bus.announce(
        {
            "component": "gojo",
            "event_type": f"guard.{action}",
            "action": action,
            "actor": actor_role,
            "source_class": source_class,
            "decision": decision,
            "reason": verdict.get("reason"),
            "severity": "warning" if decision != "allow" else "info",
            "meta": {
                k: md[k] for k in ("device", "name", "endpoint", "client") if k in md
            },
        }
    )
    if decision != "allow":
        _record_deny(actor_role, action, verdict.get("reason", "denied"))
    return verdict


def allowed(**kwargs: Any) -> bool:
    """Convenience: True iff guard() allowed the action."""
    return guard(**kwargs).get("decision") == "allow"


def recent_events(limit: int = 50) -> list[dict]:
    """Recent security events from the bus (for the console/health surfaces)."""
    return event_bus.recent(limit)


def _record_deny(actor: str, action: str, reason: str) -> None:
    """Track denials per actor; announce a high-severity escalation on a streak."""
    now = time.time()
    with _DENY_LOCK:
        dq = _DENY_STREAKS[actor]
        cutoff = now - _DENY_WINDOW
        while dq and dq[0] < cutoff:
            dq.popleft()
        dq.append(now)
        count = len(dq)
    if count >= _DENY_THRESHOLD:
        event_bus.announce(
            {
                "component": "security",
                "event_type": "deny_streak",
                "actor": actor,
                "action": action,
                "count": count,
                "window_sec": _DENY_WINDOW,
                "latest_reason": reason,
                "severity": "high",
            }
        )
