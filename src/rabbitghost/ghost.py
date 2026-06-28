"""Ghosted's own stealth kit — recon, forge, cloak. Decoupled from the rabbit
ghost organ (rabbit.security.ghost.*). The rabbit organ is built to call Rabbit's
greater being; a tool stands on its own, so this is a fresh, self-contained kit.

    GhostMode().enter() / .exit() / .is_active
              .recon(topic)        -> drive a stealth web search (web.py)
              .forge(path, out)    -> a byte-distinct, equivalent artifact
    GhostCloak(passphrase=).cloak_payload(carrier, payload, out)  -> PNG (LSB)
                           .extract_payload(img)                  -> bytes

Cloak embeds an (optionally encrypted, via rabbitghost.crypto) payload in the
low bits of a PNG's pixels. Encryption makes the payload a black box; wrong key
cannot extract. Needs Pillow (degrades with a clear error if absent).
"""

from __future__ import annotations

import hashlib
import os

__all__ = ["GhostMode", "GhostCloak"]


# --- bit helpers -------------------------------------------------------------
def _to_bits(data: bytes) -> list[int]:
    return [(byte >> (7 - i)) & 1 for byte in data for i in range(8)]


def _from_bits(bits: list[int]) -> bytes:
    out = bytearray()
    for i in range(0, len(bits) - len(bits) % 8, 8):
        b = 0
        for k in range(8):
            b = (b << 1) | bits[i + k]
        out.append(b)
    return bytes(out)


class GhostMode:
    """On-demand stealth posture: web recon + artifact forging."""

    def __init__(self) -> None:
        self.is_active = False

    def enter(self) -> str:
        self.is_active = True
        return "ghost mode engaged — stealth web recon, stego, and forge are online."

    def exit(self) -> dict:
        self.is_active = False
        return {"ghost": "stood down"}

    def recon(self, topic: str) -> dict:
        """Stealth-investigate *topic* via the sovereign web engine."""
        topic = (topic or "").strip()
        if not topic:
            return {"recon": "no topic given"}
        from rabbitghost.web import SovereignBrowserEngine

        results = SovereignBrowserEngine().web_search(topic, limit=10)
        return {
            "recon": topic,
            "count": len(results),
            "findings": [
                {"title": r.title, "url": r.url, "snippet": r.snippet} for r in results
            ],
        }

    def forge(self, path: str, out_path: str | None = None) -> dict:
        """Produce a byte-distinct but functionally-equivalent copy of *path*.

        Text/code gets a unique benign trailing comment; other files get neutral
        trailing bytes (most container formats ignore trailing data). The result
        hashes differently from the original — a fresh artifact, same behaviour."""
        out_path = out_path or (path + ".forged")
        with open(path, "rb") as fh:
            raw = fh.read()
        ext = os.path.splitext(path)[1].lower()
        marker = os.urandom(8).hex()
        comment = {
            ".py": b"# ghosted:",
            ".sh": b"# ghosted:",
            ".rb": b"# ghosted:",
            ".js": b"// ghosted:",
            ".ts": b"// ghosted:",
            ".css": b"/* ghosted:",
            ".html": b"<!-- ghosted:",
        }.get(ext)
        if comment is not None:
            suffix = b"\n" + comment + marker.encode()
            if ext == ".html":
                suffix += b" -->"
            elif ext == ".css":
                suffix += b" */"
            forged = raw + suffix
        else:
            forged = raw + b"\x00" + bytes.fromhex(marker)
        with open(out_path, "wb") as fh:
            fh.write(forged)
        return {
            "forged": out_path,
            "original_sha256": hashlib.sha256(raw).hexdigest(),
            "forged_sha256": hashlib.sha256(forged).hexdigest(),
            "marker": marker,
        }


class GhostCloak:
    """LSB image steganography with optional RABBIT-CIPHER-1 payload encryption."""

    def __init__(self, passphrase: str | None = None) -> None:
        self._pw = passphrase or None

    def cloak_payload(self, carrier_path: str, payload, out_path: str) -> str:
        """Embed *payload* (bytes) in the LSBs of *carrier_path*; write PNG to
        *out_path*. With a passphrase the payload is encrypted first (black box)."""
        from PIL import Image

        if isinstance(payload, str):
            payload = payload.encode("utf-8")

        if self._pw:
            import base64

            from rabbitghost.crypto import encrypt

            token = base64.b64encode(payload).decode("ascii")
            data = encrypt(token, self._pw).to_bytes()
            flag = 1
        else:
            data, flag = bytes(payload), 0

        blob = bytes([flag]) + len(data).to_bytes(4, "big") + data
        bits = _to_bits(blob)

        img = Image.open(carrier_path).convert("RGB")
        pixels = list(img.getdata())
        if len(bits) > len(pixels) * 3:
            raise ValueError(
                f"carrier too small: need {len(bits)} bits, have {len(pixels) * 3}"
            )

        out_pixels: list[tuple] = []
        bi = 0
        n = len(bits)
        for (r, g, b) in pixels:
            chans = [r, g, b]
            for k in range(3):
                if bi < n:
                    chans[k] = (chans[k] & ~1) | bits[bi]
                    bi += 1
            out_pixels.append((chans[0], chans[1], chans[2]))
        img.putdata(out_pixels)
        img.save(out_path, "PNG")
        return out_path

    def extract_payload(self, img_path: str) -> bytes:
        """Recover the embedded payload. Raises if a wrong/missing key can't open it."""
        from PIL import Image

        img = Image.open(img_path).convert("RGB")
        bits: list[int] = []
        for (r, g, b) in img.getdata():
            bits.append(r & 1)
            bits.append(g & 1)
            bits.append(b & 1)

        header = _from_bits(bits[:40])  # flag(1) + length(4)
        flag = header[0]
        length = int.from_bytes(header[1:5], "big")
        data = _from_bits(bits[40 : 40 + length * 8])

        if flag == 1:
            import base64

            from rabbitghost.crypto import EncryptedBlob, decrypt

            token = decrypt(EncryptedBlob.from_bytes(data), self._pw or "")
            return base64.b64decode(token)
        return data
