"""Ghosted's own OCR — rapidocr-onnxruntime primary, pytesseract fallback.

Decoupled from rabbit.perception.sovereign_ocr. Degrades to '' when no OCR
backend is installed (the optional [ocr] extra provides one). The engine is
cached after first construction (RapidOCR init is expensive).

    OCR().extract(path) -> str
"""

from __future__ import annotations

__all__ = ["OCR"]

_RAPID = None
_RAPID_TRIED = False


def _rapid():
    global _RAPID, _RAPID_TRIED
    if _RAPID_TRIED:
        return _RAPID
    _RAPID_TRIED = True
    try:
        from rapidocr_onnxruntime import RapidOCR  # type: ignore

        _RAPID = RapidOCR()
    except Exception:
        _RAPID = None
    return _RAPID


class OCR:
    """Image → text. Returns '' (never raises) when no backend is available."""

    def extract(self, path: str) -> str:
        engine = _rapid()
        if engine is not None:
            try:
                result, _ = engine(path)
                if result:
                    return "\n".join(str(line[1]) for line in result).strip()
                return ""
            except Exception:
                pass
        try:
            import pytesseract  # type: ignore
            from PIL import Image

            return (pytesseract.image_to_string(Image.open(path)) or "").strip()
        except Exception:
            return ""
