"""OCR test — RABBIT-OCR-1 via the parser. Skips unless the engine + mind + PIL present."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
pytest.importorskip(
    "rapidocr_onnxruntime", reason="OCR engine not installed (pip install .[ocr])"
)
pytest.importorskip(
    "rabbit.perception.sovereign_ocr", reason="requires the rabbit mind"
)
PIL = pytest.importorskip("PIL")

from rabbitghost import parser  # noqa: E402


def test_ocr_extracts_text_from_image(tmp_path):
    from PIL import Image, ImageDraw, ImageFont

    p = str(tmp_path / "ocr.png")
    img = Image.new("RGB", (520, 140), "white")
    d = ImageDraw.Draw(img)
    try:
        font = ImageFont.truetype("arial.ttf", 48)
    except Exception:
        font = ImageFont.load_default()
    d.text((20, 40), "RABBIT OCR WORKS", fill="black", font=font)
    img.save(p)

    res = parser.parse_file(p)
    assert res["type"] == "image"
    assert res.get("backend") == "ghosted-ocr"
    txt = (res.get("text") or "").upper()
    assert ("RABBIT" in txt) or ("OCR" in txt) or ("WORKS" in txt)
