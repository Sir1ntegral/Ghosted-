"""Ghosted's own document extraction — Maw. Decoupled from rabbit.maw.maw.

PDF via pypdf, DOCX via python-docx (both optional — the [docs] extra), and
stdlib for html/csv/json/txt/md/images. Anything missing degrades to a clean
best-effort or '' rather than crashing.

    Maw().ingest(path, max_chars=None) -> str
"""

from __future__ import annotations

import csv
import html
import json
import os
import re

__all__ = ["Maw"]


def _pdf(path: str) -> str:
    try:
        from pypdf import PdfReader  # type: ignore

        reader = PdfReader(path)
        return "\n".join((pg.extract_text() or "") for pg in reader.pages).strip()
    except Exception:
        return ""


def _docx(path: str) -> str:
    try:
        import docx  # type: ignore

        d = docx.Document(path)
        return "\n".join(p.text for p in d.paragraphs).strip()
    except Exception:
        return ""


def _html(path: str) -> str:
    try:
        raw = open(path, encoding="utf-8", errors="replace").read()
    except Exception:
        return ""
    try:
        from bs4 import BeautifulSoup  # type: ignore

        return BeautifulSoup(raw, "html.parser").get_text(" ", strip=True)
    except Exception:
        return html.unescape(re.sub(r"<[^>]+>", " ", raw)).strip()


def _csv(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace", newline="") as fh:
            return "\n".join(", ".join(row) for row in csv.reader(fh)).strip()
    except Exception:
        return ""


def _json(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return json.dumps(json.load(fh), ensure_ascii=False, indent=2)
    except Exception:
        return ""


def _text(path: str) -> str:
    try:
        return open(path, encoding="utf-8", errors="replace").read()
    except Exception:
        return ""


class Maw:
    """Multi-format text extraction. Mirrors the rabbit Maw().ingest contract."""

    def ingest(self, path: str, *, max_chars: int | None = None) -> str:
        ext = os.path.splitext(path)[1].lower()
        if ext == ".pdf":
            text = _pdf(path)
        elif ext == ".docx":
            text = _docx(path)
        elif ext in (".html", ".htm"):
            text = _html(path)
        elif ext == ".csv":
            text = _csv(path)
        elif ext == ".json":
            text = _json(path)
        elif ext in (".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff", ".webp", ".gif"):
            from ghosted.ocr import OCR

            text = OCR().extract(path)
        else:
            text = _text(path)
        text = text or ""
        if max_chars and len(text) > max_chars:
            text = text[:max_chars]
        return text
