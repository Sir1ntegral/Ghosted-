"""
Rabbit Semantic Search — re-rank web results by meaning, context, and sentiment.

Google ranks on keywords + link graph. Rabbit re-ranks the candidate set on:
  • relevance  — BM25-lite term scoring, title-weighted
  • context    — query-bigram/phrase proximity + query-term coverage (completeness)
  • meaning    — cosine over the trained SovereignSemanticModel vectors WHEN available
                 (numpy + trained corpus); silently skipped otherwise
  • sentiment  — sovereign pure-Python lexicon (positive sources float up on ties)

Pure-Python core, zero hard deps. NEVER raises: on any failure the original order
is returned unchanged, so search degrades but never breaks (exemplary consistency).
"""

from __future__ import annotations

import math
import re
from collections import Counter

_WORD = re.compile(r"[a-z0-9']+")


def _toks(s: str) -> list[str]:
    return _WORD.findall((s or "").lower())


# Sovereign sentiment lexicon — small, owned, no deps.
_POS = {
    "good",
    "great",
    "best",
    "excellent",
    "trusted",
    "secure",
    "reliable",
    "fast",
    "free",
    "official",
    "verified",
    "safe",
    "proven",
    "accurate",
    "helpful",
    "recommended",
    "powerful",
    "robust",
    "stable",
    "open",
    "privacy",
}
_NEG = {
    "bad",
    "worst",
    "scam",
    "insecure",
    "slow",
    "broken",
    "fake",
    "malware",
    "danger",
    "dangerous",
    "unsafe",
    "error",
    "fail",
    "vulnerable",
    "useless",
    "deprecated",
    "warning",
    "phishing",
    "tracking",
    "breach",
}


def _sentiment(text: str) -> float:
    t = _toks(text)
    if not t:
        return 0.0
    p = sum(w in _POS for w in t)
    n = sum(w in _NEG for w in t)
    if p + n == 0:
        return 0.0
    return (p - n) / (p + n)


_MODEL = None
_MODEL_TRIED = False


def _semantic_model():
    """Load the bundled TRAINED SovereignSemanticModel (meaning-vectors). Cached once.
    Missing model / numpy → None (rerank degrades to lexical+sentiment+intent)."""
    global _MODEL, _MODEL_TRIED
    if _MODEL_TRIED:
        return _MODEL
    _MODEL_TRIED = True
    try:
        import os

        from ghosted._sovereign_semantic import SovereignSemanticModel

        path = os.path.join(os.path.dirname(__file__), "data", "semantic_model.json")
        m = SovereignSemanticModel.load(path)
        _MODEL = m if (m is not None and getattr(m, "is_trained", False)) else None
    except Exception:
        _MODEL = None
    return _MODEL


_DOM_ENGINE = None


def _dominance_engine():
    """Intent-domain detection.

    This was Rabbit's council FacultyDominanceEngine — a faculty of the greater
    being. A standalone tool does not summon the council, so it is dropped in the
    decouple. rerank() degrades cleanly without it (lexical + meaning-vector +
    sentiment carry the ranking; intent-domain was only a minor tie-breaker)."""
    return None


def _intent_domain(text: str):
    """The dominant faculty/domain of *text* — the reasoning engine's read of intent."""
    eng = _dominance_engine()
    if eng is None:
        return None
    try:
        ranked = eng.assess(text).ranked()
        return ranked[0][0] if ranked else None
    except Exception:
        return None


def _cos(a, b) -> float:
    if not a or not b:
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


def _lexical(qtoks: list[str], dtoks: list[str]) -> float:
    """BM25-lite relevance + phrase proximity + query-coverage (context completeness)."""
    if not dtoks or not qtoks:
        return 0.0
    dc = Counter(dtoks)
    dl = len(dtoks)
    qset = set(qtoks)
    score = 0.0
    for w in qset:
        tf = dc.get(w, 0)
        if tf:
            score += (tf * 2.2) / (tf + 1.2 * (0.25 + 0.75 * dl / 20.0))
    # phrase proximity: shared query bigrams (nuance — word order matters)
    qb = set(zip(qtoks, qtoks[1:]))
    db = set(zip(dtoks, dtoks[1:]))
    score += 1.5 * len(qb & db)
    # coverage: how completely the result addresses the whole query (context depth)
    cover = sum(1 for w in qset if w in dc) / max(1, len(qset))
    return score * (0.5 + 0.5 * cover)


def warm() -> None:
    """Pre-pay the one-time dominance lexicon load (~2.7s) so the FIRST search is fast.
    Call at server startup (background thread). After this, intent is ~0.9ms/call."""
    try:
        _intent_domain("warmup query")
    except Exception:
        pass


def rerank(query: str, results: list):
    """Re-rank web results with surgical precision. Returns the same objects,
    re-ordered, each annotated with _rabbit_score / _rabbit_sentiment / _rabbit_semantic.
    """
    try:
        qtoks = _toks(query)
        if not qtoks or not results:
            return results
        model = _semantic_model()
        qvec = model.embed(query) if model else None
        q_intent = _intent_domain(
            query
        )  # the reasoning dominance engine's read of intent
        scored = []
        for r in results:
            title = getattr(r, "title", "") or ""
            snip = getattr(r, "snippet", "") or ""
            text = f"{title} {snip}"
            dtoks = _toks(text)
            # title weighted higher than snippet (signal density)
            lex = _lexical(qtoks, dtoks) + 0.6 * _lexical(qtoks, _toks(title))
            sem = 0.0
            if qvec is not None and model is not None:
                try:
                    dv = model.embed(text)
                    sem = _cos(qvec, dv) if dv else 0.0
                except Exception:
                    sem = 0.0
            senti = _sentiment(text)
            # intent: result whose dominant domain matches the query's intent-domain is
            # surgically boosted — tightens accuracy to what the search actually MEANS.
            intent_boost = (
                1.2
                if (q_intent is not None and _intent_domain(text) == q_intent)
                else 0.0
            )
            # blended: meaning (when available) + lexical context + intent + positive tiebreak
            score = (
                (2.0 * sem if qvec is not None else 0.0)
                + lex
                + intent_boost
                + 0.3 * max(0.0, senti)
            )
            scored.append((score, senti, sem, r))
        scored.sort(key=lambda x: x[0], reverse=True)
        out = []
        for score, senti, sem, r in scored:
            try:
                r._rabbit_score = round(float(score), 3)
                r._rabbit_sentiment = round(float(senti), 2)
                r._rabbit_semantic = round(float(sem), 3)
            except Exception:
                pass
            out.append(r)
        return out
    except Exception:
        return results  # never break search — degrade, don't fail
