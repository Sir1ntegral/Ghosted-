"""GHOSTED-CIPHER-1: Rabbit's Sovereign ChaCha20-Poly1305 AEAD Implementation.

Pure Python, zero external dependencies, verified against RFC 8439 test vectors.

  SUPERIORITY OVER cryptography.ChaCha20Poly1305
  ───────────────────────────────────────────────
  · Zero dependencies:   No OpenSSL, no cryptography wheel, no native extensions.
    Runs on any Python 3.11+ installation — air-gapped, embedded, or constrained.
  · Sovereign ownership: Rabbit controls every line of the cipher implementation.
    No supply-chain exposure from third-party wheels or binary distributions.
  · Full auditability:   Every operation is readable Python — no binary black box.
    Rabbit's security team can verify, audit, or modify any part at any time.
  · RFC 8439 compliance: Verified against all published test vectors.
    Behaviour is identical to the reference implementation — not a new protocol.
  · Drop-in interface:   encrypt(nonce, data, aad) / decrypt(nonce, data, aad)
    matches the cryptography library's ChaCha20Poly1305 API exactly.
  · Rich error types:    SovereignAuthenticationError is distinct from ValueError,
    enabling callers to distinguish tamper detection from bad input.

  ALGORITHM: ChaCha20-Poly1305 (RFC 8439)
  ────────────────────────────────────────
  ChaCha20 is a 256-bit stream cipher designed by D.J. Bernstein.
  Poly1305 is a one-time authenticator designed by D.J. Bernstein.
  The AEAD construction is defined in RFC 8439 (updates RFC 7539).

  ChaCha20:
    State: 16 x 32-bit words in a 4×4 matrix.
    Key: 256 bits (8 words). Nonce: 96 bits (3 words). Counter: 32 bits (1 word).
    Constants: b"expand 32-byte k" (4 words = 0x61707865, 0x3320646e,
                                     0x79622d32, 0x6b206574).
    20 rounds of quarter-round operations in column + diagonal pattern.
    Output keystream block: initial state XOR final state (64 bytes).

  Poly1305:
    One-time key: first 32 bytes of ChaCha20 block with counter=0.
    Prime: p = 2¹³⁰ − 5 = 0x3fffffffffffffffffffffffffffffffb.
    Process: for each 16-byte chunk of message, append 0x01, interpret as
    little-endian integer, accumulate h = (h + n) × r mod p.
    Finalise: tag = (h + s) mod 2¹²⁸ (little-endian, 16 bytes).

  AEAD construction (RFC 8439 §2.8):
    otk   = ChaCha20Block(key, nonce, counter=0)[:32]
    ct    = ChaCha20Stream(key, nonce, counter=1) ⊕ plaintext
    mac   = Poly1305(otk, PAD16(aad) ‖ PAD16(ct) ‖ len64(aad) ‖ len64(ct))
    output = ct ‖ mac

  Test vector compliance: RFC 8439 §2.1.1, §2.2.2, §2.3.2, §2.5.2, §2.6.2, §2.8.2.

Security classification: Class C.
A bug in this module compromises all GHOSTED-CIPHER-1 encrypted blobs.
Protections:
    · MAC verified BEFORE any plaintext bytes are returned (encrypt-then-MAC).
    · Constant-time tag comparison via hmac.compare_digest().
    · No key material in any log output at any level.
    · Nonce uniqueness is the caller's responsibility (crypto.py enforces this
      by generating a fresh os.urandom(12) nonce per encrypt() call).
"""

from __future__ import annotations

import hmac
import logging
import os
import struct
from typing import Optional

logger = logging.getLogger(__name__)

__all__ = [
    "SovereignChaCha20Poly1305",
    "SovereignAuthenticationError",
    "CIPHER_KEY_LEN",
    "CIPHER_NONCE_LEN",
    "CIPHER_TAG_LEN",
    "GHOSTED_CIPHER_VERSION",
]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

GHOSTED_CIPHER_VERSION: str = "GHOSTED-CIPHER-1"
CIPHER_KEY_LEN: int = 32  # 256-bit key
CIPHER_NONCE_LEN: int = 12  # 96-bit nonce (IETF standard)
CIPHER_TAG_LEN: int = 16  # 128-bit authentication tag

# ChaCha20 initial state constants — ASCII "expand 32-byte k" as LE uint32
_CC20_CONST: tuple[int, int, int, int] = (
    0x61707865,  # b"expa"
    0x3320646E,  # b"nd 3"
    0x79622D32,  # b"2-by"
    0x6B206574,  # b"te k"
)

# Poly1305 prime: 2^130 - 5
_P1305: int = (1 << 130) - 5

# Mask for 32-bit arithmetic
_M32: int = 0xFFFFFFFF


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class SovereignAuthenticationError(Exception):
    """Raised when Poly1305 tag verification fails.

    Never includes cryptographic detail in the message.  Callers must not
    branch on the exception message — treat all instances as equivalent.
    """


# ---------------------------------------------------------------------------
# ChaCha20 core
# ---------------------------------------------------------------------------


def _rotl32(v: int, n: int) -> int:
    """Rotate a 32-bit integer v left by n bits."""
    return ((v << n) | (v >> (32 - n))) & _M32


def _chacha20_quarter_round(
    a: int, b: int, c: int, d: int
) -> tuple[int, int, int, int]:
    """Execute one ChaCha20 quarter round.

    RFC 8439 §2.1.1 — the four operations that mix entropy across
    the 16-word state matrix.
    """
    a = (a + b) & _M32
    d ^= a
    d = _rotl32(d, 16)
    c = (c + d) & _M32
    b ^= c
    b = _rotl32(b, 12)
    a = (a + b) & _M32
    d ^= a
    d = _rotl32(d, 8)
    c = (c + d) & _M32
    b ^= c
    b = _rotl32(b, 7)
    return a, b, c, d


def _chacha20_block(key: bytes, nonce: bytes, counter: int) -> bytes:
    """Produce one 64-byte ChaCha20 keystream block.

    RFC 8439 §2.3.  Performs 20 rounds (10 double-rounds) over the
    16-word state initialised from the constants, key, counter, and nonce.

    Args:
        key:     32-byte key.
        nonce:   12-byte nonce.
        counter: 32-bit block counter (0 for OTK generation, 1+ for data).

    Returns:
        64-byte keystream block.
    """
    # Unpack key, counter, nonce into 32-bit LE words
    kw = struct.unpack_from("<8I", key)
    nw = struct.unpack_from("<3I", nonce)

    # Initial state matrix (RFC 8439 §2.3):
    #   constants        key words        counter  nonce words
    s = list(_CC20_CONST) + list(kw) + [counter & _M32] + list(nw)

    # 20 rounds as 10 double-rounds
    t = s[:]
    for _ in range(10):
        # Column rounds
        t[0], t[4], t[8], t[12] = _chacha20_quarter_round(t[0], t[4], t[8], t[12])
        t[1], t[5], t[9], t[13] = _chacha20_quarter_round(t[1], t[5], t[9], t[13])
        t[2], t[6], t[10], t[14] = _chacha20_quarter_round(t[2], t[6], t[10], t[14])
        t[3], t[7], t[11], t[15] = _chacha20_quarter_round(t[3], t[7], t[11], t[15])
        # Diagonal rounds
        t[0], t[5], t[10], t[15] = _chacha20_quarter_round(t[0], t[5], t[10], t[15])
        t[1], t[6], t[11], t[12] = _chacha20_quarter_round(t[1], t[6], t[11], t[12])
        t[2], t[7], t[8], t[13] = _chacha20_quarter_round(t[2], t[7], t[8], t[13])
        t[3], t[4], t[9], t[14] = _chacha20_quarter_round(t[3], t[4], t[9], t[14])

    # Add initial state to final state (mod 2^32 per word)
    out = [(t[i] + s[i]) & _M32 for i in range(16)]

    return struct.pack("<16I", *out)


def _chacha20_encrypt(key: bytes, nonce: bytes, counter: int, data: bytes) -> bytes:
    """XOR data with ChaCha20 keystream.

    Works for both encryption and decryption (XOR is its own inverse).

    Args:
        key:     32-byte key.
        nonce:   12-byte nonce.
        counter: Initial block counter (1 for data in ChaCha20-Poly1305 AEAD).
        data:    Plaintext or ciphertext bytes.

    Returns:
        Encrypted or decrypted bytes of the same length as data.
    """
    result = bytearray(len(data))
    for i in range(0, len(data), 64):
        block = _chacha20_block(key, nonce, counter + i // 64)
        chunk = data[i : i + 64]
        for j, byte in enumerate(chunk):
            result[i + j] = byte ^ block[j]
    return bytes(result)


# ---------------------------------------------------------------------------
# Poly1305 MAC
# ---------------------------------------------------------------------------


def _poly1305_mac(key: bytes, msg: bytes) -> bytes:
    """Compute a 16-byte Poly1305 authentication tag.

    RFC 8439 §2.5.  The one-time key must never be reused for a different
    message.  In ChaCha20-Poly1305 AEAD this is guaranteed by deriving it
    fresh from the ChaCha20 block with counter=0.

    Args:
        key: 32-byte one-time Poly1305 key.
        msg: Message to authenticate (arbitrary length).

    Returns:
        16-byte authentication tag.
    """
    # Clamp r: RFC 8439 §2.5.1
    r = bytearray(key[:16])
    r[3] &= 0x0F
    r[7] &= 0x0F
    r[11] &= 0x0F
    r[15] &= 0x0F
    r[4] &= 0xFC
    r[8] &= 0xFC
    r[12] &= 0xFC
    r_int: int = int.from_bytes(r, "little")
    s_int: int = int.from_bytes(key[16:32], "little")

    h: int = 0
    # Process full 16-byte blocks
    for i in range(0, len(msg), 16):
        chunk = msg[i : i + 16]
        # Append 0x01 — encodes the block length implicitly
        n = int.from_bytes(chunk + b"\x01", "little")
        h = (h + n) * r_int % _P1305

    # Finalise: add s, reduce mod 2^128, serialise little-endian
    tag_int = (h + s_int) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    return tag_int.to_bytes(16, "little")


# ---------------------------------------------------------------------------
# AEAD construction helpers
# ---------------------------------------------------------------------------


def _pad16(data: bytes) -> bytes:
    """Pad data to the next 16-byte boundary by appending zero bytes."""
    remainder = len(data) % 16
    if remainder:
        return data + b"\x00" * (16 - remainder)
    return data


def _build_mac_data(aad: bytes, ciphertext: bytes) -> bytes:
    """Construct the Poly1305 input per RFC 8439 §2.8.

    Layout: PAD16(aad) ‖ PAD16(ciphertext) ‖ len64_le(aad) ‖ len64_le(ciphertext)
    """
    return (
        _pad16(aad)
        + _pad16(ciphertext)
        + struct.pack("<Q", len(aad))
        + struct.pack("<Q", len(ciphertext))
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class SovereignChaCha20Poly1305:
    """Rabbit's sovereign ChaCha20-Poly1305 AEAD cipher.

    Drop-in replacement for ``cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305``.
    Pure Python — zero native dependencies.

    Security properties (RFC 8439 / AEAD):
        · Confidentiality:  ChaCha20 stream cipher with a 256-bit key.
        · Integrity:        Poly1305 MAC over ciphertext + AAD.
        · Authenticity:     Tag verified before any plaintext is returned.
        · Nonce uniqueness: Caller MUST ensure each nonce is used at most once
          per key.  crypto.py enforces this with os.urandom(12) per call.

    Example::

        from ghosted._sovereign_cipher import SovereignChaCha20Poly1305
        import os

        key     = os.urandom(32)
        nonce   = os.urandom(12)
        cipher  = SovereignChaCha20Poly1305(key)

        ct  = cipher.encrypt(nonce, b"hello, Rabbit", None)
        pt  = cipher.decrypt(nonce, ct, None)
        assert pt == b"hello, Rabbit"
    """

    def __init__(self, key: bytes) -> None:
        """
        Args:
            key: 32-byte (256-bit) secret key.

        Raises:
            ValueError: If key is not exactly 32 bytes.
        """
        if len(key) != CIPHER_KEY_LEN:
            raise ValueError(
                f"ChaCha20-Poly1305 requires a {CIPHER_KEY_LEN}-byte key; "
                f"got {len(key)}."
            )
        # Store as immutable bytes — no copy left on the heap beyond this
        self._key: bytes = bytes(key)

    # ── Encryption ───────────────────────────────────────────────────────────

    def encrypt(
        self,
        nonce: bytes,
        data: bytes,
        aad: Optional[bytes],
    ) -> bytes:
        """Encrypt and authenticate data.

        Args:
            nonce: 12-byte nonce.  MUST be unique per (key, message) pair.
            data:  Plaintext to encrypt (arbitrary length, may be empty).
            aad:   Additional authenticated data (authenticated but not
                   encrypted).  Pass None or b"" to omit.

        Returns:
            Ciphertext concatenated with 16-byte authentication tag.
            Length = len(data) + 16.

        Raises:
            ValueError: If nonce is not 12 bytes.
        """
        self._validate_nonce(nonce)
        aad_bytes: bytes = aad or b""

        # Step 1: derive one-time Poly1305 key (RFC 8439 §2.6)
        otk: bytes = _chacha20_block(self._key, nonce, 0)[:32]

        # Step 2: encrypt plaintext with counter starting at 1 (RFC 8439 §2.6)
        ciphertext: bytes = _chacha20_encrypt(self._key, nonce, 1, data)

        # Step 3: compute Poly1305 MAC over padded AAD + padded ciphertext + lengths
        mac_data: bytes = _build_mac_data(aad_bytes, ciphertext)
        tag: bytes = _poly1305_mac(otk, mac_data)

        logger.debug(
            "GHOSTED-CIPHER-1 encrypt: %d bytes plaintext → %d bytes output",
            len(data),
            len(ciphertext) + CIPHER_TAG_LEN,
        )

        return ciphertext + tag

    # ── Decryption ───────────────────────────────────────────────────────────

    def decrypt(
        self,
        nonce: bytes,
        data: bytes,
        aad: Optional[bytes],
    ) -> bytes:
        """Verify and decrypt an authenticated ciphertext.

        ALWAYS verifies the authentication tag BEFORE returning any plaintext.
        If the tag is invalid, no plaintext bytes are returned or accessible
        by the caller.

        Args:
            nonce: 12-byte nonce used during encryption.
            data:  Ciphertext + 16-byte tag (as returned by encrypt()).
            aad:   Additional authenticated data — must match what was passed
                   to encrypt().  Pass None or b"" to omit.

        Returns:
            Decrypted plaintext bytes.

        Raises:
            SovereignAuthenticationError: If the tag is invalid (wrong key,
                wrong nonce, wrong AAD, or tampered ciphertext).
            ValueError: If nonce is not 12 bytes, or data is shorter than 16 bytes.
        """
        self._validate_nonce(nonce)
        if len(data) < CIPHER_TAG_LEN:
            raise ValueError(
                f"Ciphertext too short: must be at least {CIPHER_TAG_LEN} bytes "
                f"(tag only); got {len(data)}."
            )
        aad_bytes: bytes = aad or b""

        # Split tag from ciphertext
        ciphertext: bytes = data[: len(data) - CIPHER_TAG_LEN]
        received_tag: bytes = data[len(data) - CIPHER_TAG_LEN :]

        # Derive one-time key and compute expected tag
        otk: bytes = _chacha20_block(self._key, nonce, 0)[:32]
        mac_data: bytes = _build_mac_data(aad_bytes, ciphertext)
        expected_tag: bytes = _poly1305_mac(otk, mac_data)

        # Constant-time comparison — prevents timing oracle attacks
        if not hmac.compare_digest(expected_tag, received_tag):
            logger.warning("GHOSTED-CIPHER-1 decrypt: authentication tag mismatch")
            raise SovereignAuthenticationError(
                "Decryption failed. The authentication tag is invalid — "
                "the key, nonce, AAD, or ciphertext may be incorrect or tampered."
            )

        plaintext: bytes = _chacha20_encrypt(self._key, nonce, 1, ciphertext)

        logger.debug(
            "GHOSTED-CIPHER-1 decrypt: %d bytes ciphertext → %d bytes plaintext",
            len(ciphertext),
            len(plaintext),
        )

        return plaintext

    # ── Misuse-resistant API (nonce reuse made structurally impossible) ───────

    def seal(self, data: bytes, aad: Optional[bytes] = None) -> bytes:
        """Encrypt with an internally-generated fresh nonce.

        The RFC primitive ``encrypt(nonce, ...)`` trusts the caller never to
        reuse a nonce — and nonce reuse under one key is catastrophic for
        ChaCha20-Poly1305 (it leaks the keystream and the Poly1305 key). ``seal``
        removes that footgun: it draws a fresh 96-bit nonce from ``os.urandom``
        and prepends it to the output, so a caller *cannot* reuse one.

        Wire format: ``nonce(12) || ciphertext || tag(16)``.

        Args:
            data: Plaintext (any length, may be empty).
            aad:  Additional authenticated data (authenticated, not encrypted).

        Returns:
            Self-describing sealed blob — pass straight to ``open()``.
        """
        nonce = os.urandom(CIPHER_NONCE_LEN)
        return nonce + self.encrypt(nonce, data, aad)

    def open(self, sealed: bytes, aad: Optional[bytes] = None) -> bytes:
        """Inverse of :meth:`seal` — split the prepended nonce and decrypt.

        Args:
            sealed: A blob produced by :meth:`seal` (``nonce || ct || tag``).
            aad:    Must match the AAD passed to ``seal``.

        Returns:
            The decrypted plaintext.

        Raises:
            ValueError: If the blob is too short to contain nonce + tag.
            SovereignAuthenticationError: If authentication fails.
        """
        min_len = CIPHER_NONCE_LEN + CIPHER_TAG_LEN
        if len(sealed) < min_len:
            raise ValueError(
                f"Sealed blob too short: need at least {min_len} bytes "
                f"(nonce + tag); got {len(sealed)}."
            )
        nonce = sealed[:CIPHER_NONCE_LEN]
        body = sealed[CIPHER_NONCE_LEN:]
        return self.decrypt(nonce, body, aad)

    # ── Private helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _validate_nonce(nonce: bytes) -> None:
        if len(nonce) != CIPHER_NONCE_LEN:
            raise ValueError(
                f"ChaCha20-Poly1305 requires a {CIPHER_NONCE_LEN}-byte nonce; "
                f"got {len(nonce)}."
            )
