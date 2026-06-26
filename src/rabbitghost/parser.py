"""
Parser — extract clean text + structure from a file or a raw string.

Strategy (no duplication, graceful):
  * files → Rabbit's Maw (MediaExtractor: pdf / docx / html / csv / json / txt / md)
    when the mind is importable; otherwise a pure-stdlib fallback for the lightweight
    formats (json / csv / html / text) with zero extra deps.
  * images → RABBIT-OCR-1 (rabbit.perception.sovereign_ocr) when available.
  * strings → format sniffing (json → csv → html → plain).

Every entry point returns a dict: {"type", "text", ... , optional "data"/"rows"}.
Never raises — failures return {"type": "error", ...}.
"""
from __future__ import annotations

import csv
import io
import json
import os
from html.parser import HTMLParser

_IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".bmp", ".tiff", ".tif", ".gif", ".webp"}
_MAX_BYTES = 16 * 1024 * 1024  # cap untrusted input — memory-exhaustion guard


class _TextHTML(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._buf: list[str] = []

    def handle_data(self, data: str) -> None:
        self._buf.append(data)

    def text(self) -> str:
        return " ".join(" ".join(self._buf).split())


def _html_to_text(s: str) -> str:
    p = _TextHTML()
    try:
        p.feed(s)
    except Exception:
        return s
    return p.text()


def parse_text(text: str) -> dict:
    """Sniff and parse a raw string: json → csv → html → plain."""
    t = (text or "")[:_MAX_BYTES].strip()
    if not t:
        return {"type": "text", "text": ""}
    # JSON
    if t[0] in "{[":
        try:
            return {"type": "json", "data": json.loads(t), "text": text}
        except Exception:
            pass
    # HTML
    low = t[:256].lower()
    if "<!doctype html" in low or "<html" in low or ("</" in t and "<" in t and ">" in t):
        return {"type": "html", "text": _html_to_text(t)}
    # CSV (uniform multi-column rows)
    if "," in t and "\n" in t:
        try:
            rows = list(csv.reader(io.StringIO(t)))
            if len(rows) > 1 and len(rows[0]) > 1 and all(len(r) == len(rows[0]) for r in rows[:5]):
                return {"type": "csv", "rows": rows, "text": text}
        except Exception:
            pass
    return {"type": "text", "text": text}


def _ocr(path: str) -> dict:
    try:
        from rabbit.perception.sovereign_ocr import SovereignOCR

        res = SovereignOCR().extract(path)
        txt = getattr(res, "text", None)
        if txt is None:
            txt = res if isinstance(res, str) else ""
        return {"type": "image", "text": txt or "", "backend": "RABBIT-OCR-1", "path": path}
    except Exception as e:  # noqa: BLE001
        return {"type": "image", "text": "", "error": f"OCR unavailable: {e}", "path": path}


def parse_file(path: str, *, max_chars: int | None = None) -> dict:
    """Parse a file into clean text/structure."""
    if not os.path.isfile(path):
        return {"type": "error", "text": "", "error": "file not found", "path": path}
    ext = os.path.splitext(path)[1].lower()
    if ext in _IMAGE_EXTS:
        return _ocr(path)
    # Prefer Rabbit's Maw (robust: pdf/docx/html/csv/json/txt/md)
    try:
        from rabbit.maw.maw import Maw

        txt = Maw().ingest(path, max_chars=max_chars)
        return {"type": ext.lstrip(".") or "text", "text": txt or "", "source": "maw", "path": path}
    except Exception:
        pass
    # Stdlib fallback (lightweight formats)
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            raw = fh.read(_MAX_BYTES)  # capped read — DoS guard
    except Exception as e:  # noqa: BLE001
        return {"type": "error", "text": "", "error": str(e), "path": path}
    result = parse_text(raw)
    result.update({"source": "stdlib", "path": path})
    if max_chars:
        result["text"] = (result.get("text") or "")[:max_chars]
    return result


def parse(target: str, *, max_chars: int | None = None) -> dict:
    """Dispatch: an existing file path → parse_file, else treat as a raw string."""
    try:
        if isinstance(target, str) and os.path.isfile(target):
            return parse_file(target, max_chars=max_chars)
    except Exception:
        pass
    return parse_text(target if isinstance(target, str) else str(target))
