"""Smoke tests — import + the pure-Python ranker (no network, no rabbit mind needed)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def test_semantic_search_imports_and_ranks():
    from rabbitghost import semantic_search as ss

    def R(title, snippet):
        return type("R", (), {"title": title, "snippet": snippet, "url": "http://x"})()

    results = [
        R("soup recipe", "cooking pasta"),
        R("secure private browser", "trusted sovereign secure encrypted tor privacy browser"),
    ]
    ranked = ss.rerank("secure private browser", results)
    assert ranked[0].title == "secure private browser"      # relevant floats up
    assert hasattr(ranked[0], "_rabbit_score")
    assert hasattr(ranked[0], "_rabbit_sentiment")


def test_ranker_never_raises_on_bad_input():
    from rabbitghost import semantic_search as ss

    assert ss.rerank("", []) == []
    assert len(ss.rerank("x", [type("B", (), {})()])) == 1   # missing attrs → safe


def test_sentiment_lexicon():
    from rabbitghost import semantic_search as ss

    assert ss._sentiment("trusted secure reliable") > 0
    assert ss._sentiment("scam malware dangerous") < 0
