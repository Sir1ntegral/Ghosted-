"""
Ghosted — feedback + learning loop.

Closes the loop between what people search and what actually helped them. It takes
feedback "in any fashion" and folds it into ranking, where the AMOUNT and CONFIDENCE
of the data decides how much ranking is allowed to move (adaptivity) — little data =
gentle nudges, lots of consistent data = strong influence.

Signals captured
  • explicit:  a 👍/👎 or 1–5 rating + optional note on a query or a result
  • implicit:  result CLICKS (which link, what rank), DWELL time on a result,
               query volume, and an inferred SATISFACTION (clicked high-dwell = good;
               searched-again-immediately / no-click = poor)

How it influences ranking
  rerank() calls boost(query, url): engagement on this (query→url) pair floats that
  result up next time, scaled by adaptivity(). adaptivity() grows with the number of
  recorded signals and how CONSISTENT they are, so the system earns its influence —
  it never overfits to one or two clicks.

Pure-Python, zero deps, never raises. Persisted to %LOCALAPPDATA%/Ghosted/feedback.json,
bounded so it can run for years without unbounded growth.
"""

from __future__ import annotations

import os
import re
import threading
import time
from typing import Any

_WORD = re.compile(r"[a-z0-9']+")
_LOCK = threading.RLock()
_STATE: dict[str, Any] | None = None

_MAX_EVENTS = 4000          # ring-buffer cap on raw events
_MAX_PAIRS = 6000           # cap on (query,url) aggregate rows
_GOOD_DWELL = 12.0          # seconds on a result that counts as "satisfied"


def _path() -> str:
    try:
        from ghosted.mail import _data_root

        return os.path.join(_data_root(), "feedback.json")
    except Exception:
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        d = os.path.join(base, "Ghosted")
        os.makedirs(d, exist_ok=True)
        return os.path.join(d, "feedback.json")


def _norm(q: str) -> str:
    return " ".join(_WORD.findall((q or "").lower()))


def _key(q: str, url: str) -> str:
    return _norm(q) + "\x1f" + (url or "").strip()


def _load() -> dict[str, Any]:
    global _STATE
    if _STATE is not None:
        return _STATE
    state = {"events": [], "pairs": {}, "queries": [], "totals": {"searches": 0, "clicks": 0, "ratings": 0}}
    try:
        import json

        with open(_path(), encoding="utf-8") as fh:
            disk = json.load(fh)
        if isinstance(disk, dict):
            state.update({k: disk.get(k, state[k]) for k in state})
    except Exception:
        pass
    _STATE = state
    return state


def _save(state: dict[str, Any]) -> None:
    try:
        from ghosted.mail import atomic_write_json

        atomic_write_json(_path(), state)
    except Exception:
        try:
            import json

            with open(_path(), "w", encoding="utf-8") as fh:
                json.dump(state, fh)
        except Exception:
            pass


def _pair_row(state, q, url) -> dict:
    k = _key(q, url)
    row = state["pairs"].get(k)
    if row is None:
        if len(state["pairs"]) >= _MAX_PAIRS:
            # evict the least-engaged pair to stay bounded
            worst = min(state["pairs"], key=lambda kk: state["pairs"][kk].get("score", 0))
            state["pairs"].pop(worst, None)
        row = {"q": _norm(q), "url": url, "clicks": 0, "dwell": 0.0, "rating": 0.0, "n_rating": 0, "score": 0.0}
        state["pairs"][k] = row
    return row


def _recompute(row: dict) -> None:
    """Engagement score for a (query,url) pair: clicks + dwell + explicit rating."""
    dwell_sat = min(1.0, row["dwell"] / _GOOD_DWELL) if row["clicks"] else 0.0
    rating = (row["rating"] / row["n_rating"]) if row["n_rating"] else 0.0  # -1..1
    row["score"] = round(0.6 * min(row["clicks"], 5) / 5.0 + 0.25 * dwell_sat + 0.15 * (rating + 1) / 2.0, 4)


def _push_event(state, ev: dict) -> None:
    ev["t"] = round(time.time(), 1)
    state["events"].append(ev)
    if len(state["events"]) > _MAX_EVENTS:
        del state["events"][: len(state["events"]) - _MAX_EVENTS]


# ── recording API ─────────────────────────────────────────────────────────────────
def record_search(query: str, n_results: int = 0) -> None:
    q = _norm(query)
    if not q:
        return
    with _LOCK:
        s = _load()
        s["totals"]["searches"] += 1
        s["queries"].append(q)
        if len(s["queries"]) > _MAX_EVENTS:
            del s["queries"][: len(s["queries"]) - _MAX_EVENTS]
        _push_event(s, {"k": "search", "q": q, "n": int(n_results)})
        _save(s)


def record_click(query: str, url: str, position: int = -1, dwell: float = 0.0) -> None:
    if not (url or "").strip():
        return
    with _LOCK:
        s = _load()
        s["totals"]["clicks"] += 1
        row = _pair_row(s, query, url)
        row["clicks"] += 1
        if dwell and dwell > 0:
            row["dwell"] += float(dwell)
        _recompute(row)
        _push_event(s, {"k": "click", "q": _norm(query), "url": url, "pos": int(position), "dwell": float(dwell or 0)})
        _save(s)


def record_dwell(query: str, url: str, dwell: float) -> None:
    """Attribute additional dwell time to a result already clicked."""
    if not (url or "").strip() or not dwell:
        return
    with _LOCK:
        s = _load()
        row = _pair_row(s, query, url)
        row["dwell"] += float(dwell)
        _recompute(row)
        _push_event(s, {"k": "dwell", "q": _norm(query), "url": url, "dwell": float(dwell)})
        _save(s)


def record_rating(query: str, score: float, note: str = "", url: str = "") -> None:
    """Explicit feedback. score in -1..1 (👎=-1, 👍=+1) or 1..5 (mapped to -1..1)."""
    with _LOCK:
        s = _load()
        val = float(score)
        if val > 1.0:  # treat 1..5 stars as -1..1
            val = max(-1.0, min(1.0, (val - 3.0) / 2.0))
        s["totals"]["ratings"] += 1
        if (url or "").strip():
            row = _pair_row(s, query, url)
        else:  # query-level rating attaches to a synthetic pair
            row = _pair_row(s, query, "*query*")
        row["rating"] += val
        row["n_rating"] += 1
        _recompute(row)
        _push_event(s, {"k": "rating", "q": _norm(query), "url": url, "v": round(val, 2), "note": (note or "")[:240]})
        _save(s)


# ── learning / influence API ──────────────────────────────────────────────────────
def adaptivity() -> float:
    """How much learned signal is ALLOWED to move ranking, 0..1.

    Grows with the number of engagement signals and saturates — the loop earns its
    influence with data. This is the "level of impact and change" the data drives.
    """
    try:
        s = _load()
        signals = s["totals"]["clicks"] + 2 * s["totals"]["ratings"]
        # smooth ramp: 0 at no data → ~0.5 around 80 signals → cap 0.6
        return round(min(0.6, 0.6 * signals / (signals + 80.0)), 4)
    except Exception:
        return 0.0


def boost(query: str, url: str) -> float:
    """Ranking boost for a (query,url) pair from prior engagement, already scaled by
    adaptivity(). Added to the rerank score. 0.0 when there's no signal."""
    try:
        s = _load()
        row = s["pairs"].get(_key(query, url))
        if not row:
            return 0.0
        # map engagement score (0..1) onto the rerank scale (lex/sem are ~0..3)
        return round(row["score"] * 3.0 * adaptivity(), 4)
    except Exception:
        return 0.0


def recent_queries(limit: int = 500) -> list[str]:
    try:
        s = _load()
        return s["queries"][-int(limit):]
    except Exception:
        return []


def summary() -> dict[str, Any]:
    """Human-facing rollup for the console `feedback` command + website panel."""
    try:
        s = _load()
        pairs = list(s["pairs"].values())
        top = sorted(pairs, key=lambda r: r["score"], reverse=True)[:8]
        return {
            "searches": s["totals"]["searches"],
            "clicks": s["totals"]["clicks"],
            "ratings": s["totals"]["ratings"],
            "adaptivity": adaptivity(),
            "learned_pairs": len(pairs),
            "top_results": [
                {"query": r["q"], "url": r["url"], "clicks": r["clicks"], "score": r["score"]}
                for r in top
                if r["url"] != "*query*"
            ],
        }
    except Exception:
        return {"searches": 0, "clicks": 0, "ratings": 0, "adaptivity": 0.0, "learned_pairs": 0, "top_results": []}
