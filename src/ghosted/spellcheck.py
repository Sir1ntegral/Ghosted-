"""
Ghosted — sovereign spell-check correction.

A pure-Python "did you mean" / "showing results for…" corrector. No cloud, no deps.
It is a Norvig-style edit-distance corrector over a frequency-weighted vocabulary
built from three owned sources, in priority order:

  1. a curated base lexicon of common English + tech/privacy/search terms (shipped),
  2. the trained semantic model's vocabulary (the words Ghosted already understands),
  3. the user's own past queries (so personal jargon stops getting "corrected").

correct() returns a small verdict the search layer renders directly:
  {"original", "corrected", "changed": bool, "did_you_mean": str|None, "tokens": [...]}

Design choices that keep it intuitive (not annoying):
  • a known word is NEVER altered — correction only fires on out-of-vocab tokens;
  • a correction must clear a frequency margin over the typo, else we leave it alone;
  • edit distance is capped (1 for short words, 2 for long) so it never "guesses wild";
  • short tokens (<=2) and pure numbers/symbols are passed through untouched.
"""

from __future__ import annotations

import re
from collections import Counter

_WORD = re.compile(r"[a-z][a-z']+")

# ── curated base lexicon ─────────────────────────────────────────────────────────
# Frequency-ordered enough for tie-breaking; weights are coarse tiers, not corpus
# counts. Tuned toward what people actually type into THIS app (search + privacy).
_BASE = """
the of and to in is you that it he for was on are as with his they at be this from
i have or by one had not but what all were when we there can an your which their said
if do will each about how up out them then she many some so these would other into has
more her two like him see time could no make than first been its who now people my made
over did down only way find use may water long little very after word world called just
most know get through back much go good new write our used me man too any day same right
look think also around another came come work three must because does part even place well
such here take why help put different away again off went old number great tell men say
small every found still between name should home big give air line set own under read last
never us left end along while might next sound below saying something hello world please
thanks yes open source tools tool free best top guide list review compare learn course
search engine
privacy secure security sovereign encryption encrypt decrypt vault password account email
mail inbox message browser website internet network connection online offline download
upload file document image video audio photo picture page link button menu setting option
config configure install update version build software application program system device
health monitor cpu memory disk battery storage process service window linux unix windows
google bing youtube search results result ranking relevance meaning sentiment context
anonymous stealth ghost cloak mask proxy tor onion mesh wireguard tunnel identity domain
report feedback rating satisfaction accuracy click time spent dwell signal learning model
""".split()

# Tech terms that share spelling with rarer words — pin them HIGH so typos snap here.
_PIN = {
    "privacy": 60,
    "security": 55,
    "search": 70,
    "secure": 50,
    "password": 45,
    "account": 45,
    "email": 50,
    "sovereign": 40,
    "ghosted": 40,
    "results": 50,
    "browser": 40,
    "settings": 35,
    "encryption": 30,
}

_VOCAB: Counter | None = None


def _build_vocab() -> Counter:
    c: Counter = Counter()
    # tier 1: base lexicon — earlier words weigh slightly more (rough Zipf)
    n = len(_BASE)
    for i, w in enumerate(_BASE):
        c[w] += max(1, (n - i) // 12 + 2)
    # tier 2: semantic model vocabulary (words Ghosted already knows)
    try:
        from ghosted import semantic_search

        model = semantic_search._semantic_model()
        if model is not None and getattr(model, "_vocab", None):
            for w in model._vocab:
                if _WORD.fullmatch(w):
                    c[w] += 3
    except Exception:
        pass
    # tier 3: the user's own queries (don't "correct" their jargon)
    try:
        from ghosted import feedback

        for q in feedback.recent_queries(limit=500):
            for w in _WORD.findall(q.lower()):
                c[w] += 4
    except Exception:
        pass
    for w, extra in _PIN.items():
        c[w] += extra
    return c


def _vocab() -> Counter:
    global _VOCAB
    if _VOCAB is None:
        _VOCAB = _build_vocab()
    return _VOCAB


def reload_vocab() -> None:
    """Drop the cache so freshly-learned queries enter the dictionary."""
    global _VOCAB
    _VOCAB = None


_ALPHA = "abcdefghijklmnopqrstuvwxyz"


def _edits1(word: str) -> set[str]:
    splits = [(word[:i], word[i:]) for i in range(len(word) + 1)]
    deletes = [a + b[1:] for a, b in splits if b]
    transposes = [a + b[1] + b[0] + b[2:] for a, b in splits if len(b) > 1]
    replaces = [a + c + b[1:] for a, b in splits if b for c in _ALPHA]
    inserts = [a + c + b for a, b in splits for c in _ALPHA]
    return set(deletes + transposes + replaces + inserts)


def _known(words, vocab) -> set[str]:
    return {w for w in words if w in vocab}


def _correct_word(word: str) -> str:
    vocab = _vocab()
    # Words of 3 or fewer letters have too many near-neighbours for a compact
    # dictionary (fox→for, cat→car), and a wrong "fix" is worse than a missed one,
    # so we only correct words long enough to make a typo unambiguous.
    if len(word) <= 3 or word in vocab:
        return word
    cands = _known(_edits1(word), vocab)
    dist = 1
    if not cands and len(word) >= 5:  # only long words get the wider distance-2 net
        cands = _known((e for w in _edits1(word) for e in _edits1(w)), vocab)
        dist = 2
    if not cands:
        return word
    # First-letter guard: real typos almost never change the FIRST letter, so a
    # candidate that does is far more likely to be a different word than a fix
    # (stops "hello"→"well" and "york"→"work"). Always require the first letter to
    # match — missing a rare first-letter typo is cheaper than corrupting a real word.
    pool = {c for c in cands if c[0] == word[0]}
    # Distance-2 must also stay close in length — a typo rarely adds/drops 2 chars,
    # so a much shorter match is a different word, not a fix (stops "setup" → "set").
    if dist == 2:
        pool = {c for c in pool if abs(len(c) - len(word)) <= 1}
    if not pool:
        return word
    best = max(pool, key=lambda w: vocab[w])
    # Margin gate: distance-2 fixes must clear a higher frequency bar than distance-1,
    # so a rare distant match never overrides a plausibly-correct rare word.
    if vocab[best] < (3 if dist == 1 else 8):
        return word
    return best


def correct(query: str) -> dict:
    """Correct an entire query. Returns a verdict the search layer renders directly."""
    q = (query or "").strip()
    if not q:
        return {"original": q, "corrected": q, "changed": False, "did_you_mean": None, "tokens": []}
    out_tokens: list[str] = []
    changed = False
    # preserve the original spacing/casing skeleton by walking word-tokens only
    def _repl(m: re.Match) -> str:
        nonlocal changed
        w = m.group(0)
        low = w.lower()
        fixed = _correct_word(low)
        if fixed != low:
            changed = True
            out_tokens.append(fixed)
            # keep original capitalisation pattern (Title / UPPER / lower)
            if w.isupper():
                return fixed.upper()
            if w[0].isupper():
                return fixed.capitalize()
            return fixed
        out_tokens.append(low)
        return w

    corrected = _WORD.sub(_repl, q)
    return {
        "original": q,
        "corrected": corrected,
        "changed": changed,
        "did_you_mean": corrected if changed else None,
        "tokens": out_tokens,
    }
