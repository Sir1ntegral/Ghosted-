"""Stego black-box round-trip (Ghosted's own GhostCloak). Needs PIL; skips if absent."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
pytest.importorskip("PIL")


def test_stego_blackbox_roundtrip(tmp_path):
    from PIL import Image

    from ghosted.ghost import GhostCloak

    carrier = str(tmp_path / "carrier.png")
    out = str(tmp_path / "out.png")
    Image.new("RGB", (256, 256), (240, 240, 240)).save(carrier)
    secret = b"TOP SECRET: meet at the bridge at dawn"

    GhostCloak(passphrase="hunter2pass").cloak_payload(carrier, secret, out)
    raw = open(out, "rb").read()
    assert raw[:8] == b"\x89PNG\r\n\x1a\n"  # a real PNG
    assert secret not in raw  # encrypted + embedded (black box)

    recovered = GhostCloak(passphrase="hunter2pass").extract_payload(out)
    assert recovered == secret  # round-trips with the key

    with pytest.raises(Exception):  # wrong key cannot extract
        GhostCloak(passphrase="wrong-pass").extract_payload(out)
