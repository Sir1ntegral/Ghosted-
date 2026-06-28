"""Train the Ghosted semantic meaning-vectors from a text corpus.

Usage:  python tools/train_semantic.py [RABBIT_HOME]

Reads canon/doc prose from the Rabbit mind, trains a SovereignSemanticModel
(PPMI+SVD+SIF, sovereign — no external embeddings), and saves it to
src/ghosted/data/semantic_model.json so the homepage search ranks by meaning.
Needs numpy + the rabbit mind importable. Re-run to refresh on a new corpus.
"""
import os
import re
import sys

_RABBIT = sys.argv[1] if len(sys.argv) > 1 else r"C:\Users\Admin\Desktop\RabbitProject-clean"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, _RABBIT)

_SOURCES = [
    "_charm_full.txt", "_jester_full.txt", "_judge_full.txt", "directions.txt",
    "RABBIT_LAWS.md", "ARCHITECTURE.md", "RABBIT_HANDBOOK.md",
]


def main() -> int:
    from rabbit.core.sovereign_semantic import SovereignSemanticModel

    texts: list[str] = []
    for fn in _SOURCES:
        p = os.path.join(_RABBIT, fn)
        if os.path.exists(p):
            raw = open(p, encoding="utf-8", errors="replace").read()
            texts += [s.strip() for s in re.split(r"[.!?\n]+", raw) if len(s.strip()) > 20]
    print(f"corpus: {len(texts)} sentences from {_RABBIT}")
    if not texts:
        print("no corpus found — pass RABBIT_HOME as arg 1")
        return 1

    m = SovereignSemanticModel()
    if not m.train(texts):
        print("training failed (numpy missing?)")
        return 1

    out = os.path.join(os.path.dirname(__file__), "..", "src", "ghosted", "data", "semantic_model.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    m.save(out)
    print(f"trained vocab={m.vocab_size} -> {out} ({os.path.getsize(out) / 1e6:.1f} MB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
