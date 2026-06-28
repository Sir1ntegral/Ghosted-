"""rabbit.core.sovereign_semantic — Rabbit's OWN meaning-vectors. No LLM. No borrowed weights.

Distributional semantics from his OWN corpus: "you shall know a word by the company it keeps"
(J.R. Firth, 1957) — which is exactly the language foundation made numeric (a word's meaning is
the company it keeps; see ``rabbit.council.sovereign_language``). This builds a term x context
co-occurrence matrix from the text Rabbit has actually absorbed, weights it by PPMI (positive
pointwise mutual information), reduces it with a truncated randomized SVD to dense term vectors,
and composes sentence vectors via SIF (smooth inverse frequency + common-component removal,
Arora et al. 2017). Deterministic, offline, 100% his — trains and retrains from his growing
corpus (harvested faculty knowledge, memory, ingested documents).

Why this and not BM25: BM25 hash-projection matches by SHARED SURFACE WORDS (syntactic). This
matches by MEANING — "a determined attacker" and "a persistent adversary" land near each other
even with no shared content word, because they keep similar company across the corpus. That is
what real recall/RAG needs.

SoC: this module is the meaning->vector MODEL only. It does not store (memory owns that), does
not reason (the reasoning core owns that), does not fetch. ``SovereignEmbeddingEngine`` composes
it as the semantic tier above the always-available BM25 cold-start tier.

Dependency: training/inference use numpy (math, not an LLM). If numpy is absent the model simply
stays untrained (``is_trained`` False) and callers fall back to BM25 — never a hard failure.
"""

from __future__ import annotations

import json
import logging
import re
from collections import Counter
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

__all__ = ["SovereignSemanticModel"]

# ── defaults ───────────────────────────────────────────────────────────────────────────
_DIMS = 200  # dense vector dimensionality (truncated-SVD rank)
_WINDOW = 5  # co-occurrence context window (each side)
_MIN_COUNT = 2  # drop words seen fewer than this many times
_MAX_VOCAB = 4000  # cap vocabulary to the most frequent N (bounds the V x V matrix)
_SIF_A = 1e-3  # SIF smoothing constant
_OVERSAMPLE = 10  # randomized-SVD oversampling for numerical stability
_SVD_ITERS = 2  # power iterations (sharper top components)

# Code-aware-ish word splitter (camelCase/snake/kebab/dots/digits boundaries), words only —
# no character trigrams here (semantics is about words keeping company, not subword overlap).
_SPLIT_RE = re.compile(
    r"[_\-\.\/\s]+"
    r"|(?<=[a-z])(?=[A-Z])"
    r"|(?<=[A-Z])(?=[A-Z][a-z])"
    r"|(?<=\d)(?=[A-Za-z])"
    r"|(?<=[A-Za-z])(?=\d)"
)
_STOPWORDS: frozenset[str] = frozenset(
    {
        "the",
        "a",
        "an",
        "and",
        "or",
        "but",
        "is",
        "it",
        "to",
        "of",
        "in",
        "on",
        "at",
        "for",
        "with",
        "that",
        "this",
        "was",
        "are",
        "be",
        "by",
        "as",
        "from",
        "not",
        "so",
        "do",
        "if",
        "we",
        "i",
        "you",
        "he",
        "she",
        "they",
        "our",
        "your",
        "its",
        "my",
        "has",
        "have",
        "had",
        "will",
        "would",
        "could",
        "should",
        "can",
        "may",
        "what",
        "which",
        "who",
        "how",
        "when",
        "where",
        "why",
        "their",
        "them",
        "then",
        "than",
        "into",
        "out",
        "up",
        "down",
        "over",
    }
)


def _tokenize_words(text: str) -> list[str]:
    """Words only, lowercased, code-aware boundaries; drop stopwords and single chars."""
    out: list[str] = []
    for part in _SPLIT_RE.split(text):
        tok = part.strip().lower()
        if len(tok) < 2 or not tok.isalnum() or tok in _STOPWORDS:
            continue
        out.append(tok)
    return out


class SovereignSemanticModel:
    """A distributional meaning-vector model trained on Rabbit's own corpus.

    Train once (or nightly) from the texts he has absorbed; thereafter ``embed`` maps any text
    to a dense vector by MEANING, offline and deterministic. Untrained models return ``None``
    from ``embed`` so callers fall back to BM25.
    """

    def __init__(
        self,
        *,
        dims: int = _DIMS,
        window: int = _WINDOW,
        min_count: int = _MIN_COUNT,
        max_vocab: int = _MAX_VOCAB,
        sif_a: float = _SIF_A,
    ) -> None:
        self.dims = int(dims)
        self.window = int(window)
        self.min_count = int(min_count)
        self.max_vocab = int(max_vocab)
        self.sif_a = float(sif_a)

        self._vocab: dict[str, int] = {}  # word -> row index
        self._vectors: Optional[list[list[float]]] = None  # V x dims term vectors
        self._word_prob: dict[str, float] = {}  # word -> unigram probability (for SIF)
        self._common: Optional[list[float]] = None  # SIF common component (dims,)
        self._trained = False

    # ── status ───────────────────────────────────────────────────────────────────────
    @property
    def is_trained(self) -> bool:
        return self._trained and self._vectors is not None

    @property
    def vocab_size(self) -> int:
        return len(self._vocab)

    # ── training ──────────────────────────────────────────────────────────────────────
    def train(
        self,
        texts: list[str],
        *,
        relations: Optional[list[list[str]]] = None,
        relation_weight: float = 6.0,
    ) -> bool:
        """Learn meaning-vectors from a corpus, optionally SEEDED with curated relations.

        ``texts`` supplies distributional signal (company words keep). ``relations`` injects
        Rabbit's OWN curated structure: each inner list is a group of mutually-related terms
        (e.g. the words of one principle-ladder symbol, a lexicon cluster, or a KG neighbourhood).
        Every pair within a group gets a strong co-occurrence boost (``relation_weight``), so
        meaning is learned from his structure even when the raw corpus is small — the right bet
        for a curated, data-light mind. Returns True on success; never raises on ordinary failure.
        """
        try:
            import numpy as np
        except Exception:  # noqa: BLE001 — numpy optional; degrade to BM25
            logger.info(
                "sovereign_semantic: numpy unavailable — model stays untrained (BM25)."
            )
            return False

        if not texts:
            return False

        token_lists = [
            _tokenize_words(t) for t in texts if isinstance(t, str) and t.strip()
        ]
        token_lists = [t for t in token_lists if t]
        if len(token_lists) < 3:
            logger.info("sovereign_semantic: too little corpus to train (<3 docs).")
            return False

        # Normalize curated relation groups into the same token space as the corpus.
        rel_groups: list[list[str]] = []
        if relations:
            for group in relations:
                terms: list[str] = []
                for t in group:
                    terms.extend(_tokenize_words(str(t)))
                terms = list(dict.fromkeys(terms))  # dedup, preserve order
                if len(terms) >= 2:
                    rel_groups.append(terms)

        # 1) vocabulary: keep frequent words, cap to max_vocab.
        counts: Counter = Counter()
        total_tokens = 0
        for toks in token_lists:
            counts.update(toks)
            total_tokens += len(toks)
        # Curated relation terms qualify for the vocabulary even if rare in the raw corpus —
        # his structure is signal, not noise.
        for terms in rel_groups:
            for t in terms:
                if counts[t] < self.min_count:
                    counts[t] = self.min_count
        kept = [w for w, c in counts.most_common(self.max_vocab) if c >= self.min_count]
        if len(kept) < self.dims + _OVERSAMPLE + 2:
            logger.info(
                "sovereign_semantic: vocabulary too small (%d) for %d dims.",
                len(kept),
                self.dims,
            )
            return False
        vocab = {w: i for i, w in enumerate(kept)}
        v = len(vocab)

        # 2) co-occurrence (symmetric, distance-weighted within the window).
        cooc = np.zeros((v, v), dtype=np.float64)
        for toks in token_lists:
            idxs = [vocab[w] for w in toks if w in vocab]
            n = len(idxs)
            for a in range(n):
                ia = idxs[a]
                lo = max(0, a - self.window)
                hi = min(n, a + self.window + 1)
                for b in range(lo, hi):
                    if b == a:
                        continue
                    ib = idxs[b]
                    cooc[ia, ib] += 1.0 / abs(a - b)  # closer company counts more

        # 2b) Seed curated relations: every pair within a relation group gets a strong
        # co-occurrence boost, so his own structure (ladders/lexicon/KG) teaches meaning even
        # where the raw corpus is thin.
        for terms in rel_groups:
            ridx = [vocab[w] for w in terms if w in vocab]
            for a in range(len(ridx)):
                for b in range(len(ridx)):
                    if a != b:
                        cooc[ridx[a], ridx[b]] += relation_weight

        # 3) PPMI: max(0, log( P(i,j) / (P(i) P(j)) )).
        total = cooc.sum()
        if total <= 0:
            return False
        row = cooc.sum(axis=1)  # marginal per word
        with np.errstate(divide="ignore", invalid="ignore"):
            expected = np.outer(row, row) / total
            pmi = np.log(
                np.divide(cooc, expected, out=np.zeros_like(cooc), where=expected > 0)
                + 1e-12
            )
        ppmi = np.maximum(pmi, 0.0)

        # 4) truncated randomized SVD on the symmetric PPMI matrix -> term vectors.
        try:
            u, s = self._randomized_svd(np, ppmi, self.dims)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "sovereign_semantic: SVD failed (%s) — staying untrained.", exc
            )
            return False
        vectors = u * np.sqrt(np.maximum(s, 0.0))  # V x dims, scaled by singular values

        # 5) unigram probabilities (for SIF weighting).
        word_prob = {w: counts[w] / total_tokens for w in vocab}

        # 6) SIF common component: first principal direction of the corpus sentence vectors.
        self._vocab = vocab
        self._vectors = vectors.tolist()
        self._word_prob = word_prob
        self._common = None
        self._trained = True
        try:
            sent = np.array(
                [self._raw_sentence_vec(np, toks) for toks in token_lists],
                dtype=np.float64,
            )
            sent = sent[np.linalg.norm(sent, axis=1) > 0]
            if len(sent) >= 2:
                uu, _ = self._randomized_svd(np, sent, 1)
                # principal direction in vector space = sent^T u1, normalized
                comp = sent.T @ uu[:, 0]
                norm = np.linalg.norm(comp)
                if norm > 0:
                    self._common = (comp / norm).tolist()
        except (
            Exception
        ) as exc:  # noqa: BLE001 — common-component removal is optional polish
            logger.debug("sovereign_semantic: common-component step skipped (%s).", exc)

        logger.info(
            "sovereign_semantic: trained — vocab=%d dims=%d docs=%d.",
            v,
            self.dims,
            len(token_lists),
        )
        return True

    # ── inference ──────────────────────────────────────────────────────────────────────
    def embed(self, text: str) -> Optional[list[float]]:
        """Map text to a meaning-vector, or None if untrained / no known words (caller falls
        back to BM25). Deterministic, no LLM."""
        if not self.is_trained or not isinstance(text, str):
            return None
        try:
            import numpy as np
        except Exception:  # noqa: BLE001
            return None
        toks = _tokenize_words(text)
        vec = self._raw_sentence_vec(np, toks)
        v = np.asarray(vec, dtype=np.float64)
        if not np.any(v):
            return None
        if self._common is not None:  # remove the common (uninformative) direction
            c = np.asarray(self._common, dtype=np.float64)
            v = v - (v @ c) * c
        norm = np.linalg.norm(v)
        if norm == 0:
            return None
        return (v / norm).tolist()

    def _raw_sentence_vec(self, np, toks: list[str]):  # type: ignore[no-untyped-def]
        """SIF-weighted average of term vectors (pre common-component removal)."""
        dims = self.dims
        acc = np.zeros(dims, dtype=np.float64)
        n = 0
        for w in toks:
            i = self._vocab.get(w)
            if i is None:
                continue
            weight = self.sif_a / (self.sif_a + self._word_prob.get(w, 0.0))
            acc += weight * np.asarray(self._vectors[i], dtype=np.float64)
            n += 1
        if n == 0:
            return acc
        return acc / n

    @staticmethod
    def _randomized_svd(np, m, k: int):  # type: ignore[no-untyped-def]
        """Randomized truncated SVD (Halko et al.). Returns (U[:, :k], S[:k]).

        Pure numpy, fast for the top-k components of a dense matrix. Deterministic seed so
        vectors are stable across runs (cross-session compatibility)."""
        rng = np.random.default_rng(1957)  # Firth, deterministic
        rows, cols = m.shape
        p = min(k + _OVERSAMPLE, cols)
        omega = rng.standard_normal((cols, p))
        y = m @ omega
        for _ in range(_SVD_ITERS):  # power iterations sharpen the spectrum
            y = m @ (m.T @ y)
        q, _ = np.linalg.qr(y)
        b = q.T @ m
        ub, s, _ = np.linalg.svd(b, full_matrices=False)
        u = q @ ub
        return u[:, :k], s[:k]

    # ── persistence ──────────────────────────────────────────────────────────────────
    def save(self, path: str | Path) -> bool:
        """Persist the trained model (JSON). Returns False if untrained or on error."""
        if not self.is_trained:
            return False
        try:
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "config": {
                    "dims": self.dims,
                    "window": self.window,
                    "min_count": self.min_count,
                    "max_vocab": self.max_vocab,
                    "sif_a": self.sif_a,
                },
                "vocab": self._vocab,
                "vectors": self._vectors,
                "word_prob": self._word_prob,
                "common": self._common,
            }
            p.write_text(json.dumps(payload), encoding="utf-8")
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("sovereign_semantic: save failed (%s).", exc)
            return False

    @classmethod
    def load(cls, path: str | Path) -> Optional["SovereignSemanticModel"]:
        """Load a trained model, or None if absent/corrupt."""
        try:
            payload = json.loads(Path(path).read_text(encoding="utf-8"))
            cfg = payload.get("config", {})
            model = cls(
                dims=int(cfg.get("dims", _DIMS)),
                window=int(cfg.get("window", _WINDOW)),
                min_count=int(cfg.get("min_count", _MIN_COUNT)),
                max_vocab=int(cfg.get("max_vocab", _MAX_VOCAB)),
                sif_a=float(cfg.get("sif_a", _SIF_A)),
            )
            model._vocab = {str(k): int(v) for k, v in payload["vocab"].items()}
            model._vectors = payload["vectors"]
            model._word_prob = {
                str(k): float(v) for k, v in payload["word_prob"].items()
            }
            model._common = payload.get("common")
            model._trained = bool(model._vectors)
            return model if model._trained else None
        except Exception as exc:  # noqa: BLE001
            logger.debug("sovereign_semantic: load failed (%s).", exc)
            return None
