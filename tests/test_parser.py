"""Parser tests — pure-stdlib paths run without the rabbit mind (it degrades)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from rabbitghost import parser


def test_parse_text_json():
    r = parser.parse_text('{"a": 1, "b": [2, 3]}')
    assert r["type"] == "json" and r["data"]["a"] == 1


def test_parse_text_csv():
    r = parser.parse_text("a,b,c\n1,2,3\n4,5,6")
    assert r["type"] == "csv" and len(r["rows"]) == 3 and r["rows"][1] == ["1", "2", "3"]


def test_parse_text_html():
    r = parser.parse_text("<html><body><p>Hello world</p></body></html>")
    assert r["type"] == "html" and "Hello world" in r["text"] and "<p>" not in r["text"]


def test_parse_text_plain():
    r = parser.parse_text("just some words")
    assert r["type"] == "text" and r["text"] == "just some words"


def test_parse_file_text(tmp_path):
    f = tmp_path / "note.txt"
    f.write_text("hello from file", encoding="utf-8")
    assert "hello from file" in parser.parse_file(str(f))["text"]


def test_parse_file_json(tmp_path):
    f = tmp_path / "d.json"
    f.write_text('{"k": "value-here"}', encoding="utf-8")
    assert "value-here" in parser.parse_file(str(f))["text"]


def test_parse_missing_file():
    assert parser.parse_file("Z:/nope/missing.txt")["type"] == "error"


def test_parse_dispatch_string_vs_file(tmp_path):
    assert parser.parse("plain string")["type"] == "text"
    f = tmp_path / "x.json"
    f.write_text("[1, 2, 3]", encoding="utf-8")
    assert "1" in parser.parse(str(f))["text"]


def test_parse_never_raises_on_garbage():
    # empty, binary-ish, weird inputs must not blow up
    assert parser.parse_text("")["type"] == "text"
    assert parser.parse("\x00\x01\x02")["type"] == "text"
