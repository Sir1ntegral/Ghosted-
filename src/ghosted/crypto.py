"""Ghosted's own authenticated encryption — self-contained, zero external deps.

Decoupled from ``rabbit.core.crypto``: this module owns its crypto outright so
Ghosted is a standalone tool, not a dependent of Rabbit's greater being. The
primitives are vendored pure-Python implementations (``_sovereign_kdf`` =
GHOSTED-KDF-1, ``_sovereign_cipher`` = ChaCha20-Poly1305), so there is nothing to
``pip install`` and nothing reaching into the rabbit package.

Byte-format compatibility is intentional and load-bearing: the on-disk blob
layout, KDF preset (INTERACTIVE), and domain tag are identical to the original
Rabbit crypto, so vaults/mail already sealed on disk keep opening after the
decouple. Do not change the layout, preset, or domain tag without a migration.

    Blob layout:  MAGIC(2) + kdf_id(1) + salt(16) + nonce(12) + ciphertext(+tag)

Public contract (unchanged for callers — vault, mail, console):
    encrypt(text, passphrase) -> EncryptedBlob
    decrypt(blob, passphrase) -> str
    EncryptedBlob.to_bytes() / EncryptedBlob.from_bytes(raw)
"""

from __future__ import annotations

import hashlib
import logging
import os
from dataclasses import dataclass

from ._sovereign_cipher import (
    SovereignAuthenticationError,
    SovereignChaCha20Poly1305,
)
from ._sovereign_kdf import KDFPreset
from ._sovereign_kdf import SovereignKDF as _SovereignKDF

logger = logging.getLogger(__name__)

__all__ = [
    "encrypt",
    "decrypt",
    "migrate_blob",
    "is_legacy_blob",
    "EncryptedBlob",
    "DecryptionError",
    "KDF_ARGON2ID",
    "KDF_SCRYPT",
    "KDF_GHOSTED",
]

# --- Crypto sizing (inlined from the original rabbit.core.constants) ---------
CRYPTO_KEY_LEN = 32
CRYPTO_SALT_LEN = 16
CRYPTO_NONCE_LEN = 12
CRYPTO_MAX_PLAINTEXT_BYTES = 10 * 1024 * 1024  # 10 MB

# --- KDF identifiers — serialised into every blob; decrypt() dispatches on these
KDF_ARGON2ID: int = 0x01  # legacy (decrypt-only; needs `cryptography`, optional)
KDF_SCRYPT: int = 0x02  # legacy fallback (hashlib.scrypt, stdlib)
KDF_GHOSTED: int = 0x03  # GHOSTED-KDF-1 — pure-Python primary path

# 2-byte sentinel that cannot begin a legacy (pre-tag) blob with meaningful
# probability — old blobs start with 16 random salt bytes.
_BLOB_MAGIC = b"\xfa\xbb"

# Optional legacy argon2id support — used ONLY to decrypt old KDF_ARGON2ID blobs.
# Ghosted never *produces* argon2id blobs, so this stays optional (no hard dep).
try:
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

    _probe = Argon2id(salt=b"\x00" * 16, length=32, iterations=1, lanes=1, memory_cost=8)
    _probe.derive(b"probe")
    _ARGON2_AVAILABLE: bool = True
    del _probe
except Exception:  # noqa: BLE001 — argon2 is an optional legacy decrypt path
    _ARGON2_AVAILABLE = False
    Argon2id = None  # type: ignore[assignment,misc]

# GHOSTED-KDF-1 — pure Python, always available. Preset + domain tag MUST match
# the original rabbit.core.crypto values for on-disk compatibility.
_kdf_preset_name = os.environ.get("GHOSTED_KDF_PRESET", "INTERACTIVE").upper()
_kdf_preset = getattr(KDFPreset, _kdf_preset_name, KDFPreset.INTERACTIVE)
_GHOSTED_KDF = _SovereignKDF(
    preset=_kdf_preset, domain_tag="ghosted:crypto:chacha20-poly1305:v1"
)


class DecryptionError(Exception):
    """Raised when decryption fails (wrong key or tampered ciphertext).

    Carries no cryptographic detail — callers must not branch on the message.
    """


@dataclass(frozen=True, slots=True)
class EncryptedBlob:
    """Self-contained encrypted payload (ciphertext+tag, salt, nonce, kdf id)."""

    ciphertext: bytes
    salt: bytes
    nonce: bytes
    kdf_id: int = KDF_GHOSTED

    def to_bytes(self) -> bytes:
        """Serialise: MAGIC(2) + kdf_id(1) + salt(16) + nonce(12) + ciphertext."""
        return (
            _BLOB_MAGIC + bytes([self.kdf_id]) + self.salt + self.nonce + self.ciphertext
        )

    @classmethod
    def from_bytes(cls, raw: bytes) -> "EncryptedBlob":
        """Parse to_bytes() output. Accepts the versioned and legacy layouts."""
        if len(raw) >= 2 and raw[:2] == _BLOB_MAGIC:
            min_len = 2 + 1 + CRYPTO_SALT_LEN + CRYPTO_NONCE_LEN + 1
            if len(raw) < min_len:
                raise ValueError(
                    f"Blob too short: expected >= {min_len} bytes, got {len(raw)}."
                )
            kdf_id = raw[2]
            offset = 3
            salt = raw[offset : offset + CRYPTO_SALT_LEN]
            offset += CRYPTO_SALT_LEN
            nonce = raw[offset : offset + CRYPTO_NONCE_LEN]
            ciphertext = raw[offset + CRYPTO_NONCE_LEN :]
        else:
            min_len = CRYPTO_SALT_LEN + CRYPTO_NONCE_LEN + 1
            if len(raw) < min_len:
                raise ValueError(
                    f"Blob too short: expected >= {min_len} bytes, got {len(raw)}."
                )
            kdf_id = KDF_ARGON2ID
            salt = raw[:CRYPTO_SALT_LEN]
            nonce = raw[CRYPTO_SALT_LEN : CRYPTO_SALT_LEN + CRYPTO_NONCE_LEN]
            ciphertext = raw[CRYPTO_SALT_LEN + CRYPTO_NONCE_LEN :]
        return cls(ciphertext=ciphertext, salt=salt, nonce=nonce, kdf_id=kdf_id)


def _derive_key(passphrase: str, salt: bytes, kdf_id: int = KDF_GHOSTED) -> bytes:
    """Derive a 32-byte key from passphrase + salt, dispatching on kdf_id."""
    if not passphrase:
        raise ValueError("Passphrase must not be empty.")

    if kdf_id == KDF_GHOSTED:
        return _GHOSTED_KDF.derive_raw(passphrase, salt, CRYPTO_KEY_LEN)

    if kdf_id == KDF_SCRYPT:
        return hashlib.scrypt(
            passphrase.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=CRYPTO_KEY_LEN
        )

    if kdf_id == KDF_ARGON2ID:
        if not _ARGON2_AVAILABLE:
            raise DecryptionError(
                "Decryption failed. This blob was encrypted with argon2id, which "
                "is unavailable here (install the optional `cryptography` package)."
            )
        kdf = Argon2id(
            salt=salt, length=CRYPTO_KEY_LEN, iterations=3, lanes=4, memory_cost=65536
        )
        return kdf.derive(passphrase.encode("utf-8"))

    raise DecryptionError(f"Unknown KDF identifier: {kdf_id:#04x}")


def encrypt(plaintext: str, passphrase: str) -> EncryptedBlob:
    """Encrypt a UTF-8 string (ChaCha20-Poly1305 + GHOSTED-KDF-1). Fresh salt+nonce."""
    if not plaintext:
        raise ValueError("Plaintext must not be empty.")

    encoded = plaintext.encode("utf-8")
    if len(encoded) > CRYPTO_MAX_PLAINTEXT_BYTES:
        raise ValueError(
            f"Plaintext exceeds maximum of {CRYPTO_MAX_PLAINTEXT_BYTES} bytes "
            f"({len(encoded)} provided)."
        )

    salt = os.urandom(CRYPTO_SALT_LEN)
    nonce = os.urandom(CRYPTO_NONCE_LEN)
    key = _derive_key(passphrase, salt, KDF_GHOSTED)
    ciphertext = SovereignChaCha20Poly1305(key).encrypt(nonce, encoded, None)
    return EncryptedBlob(ciphertext=ciphertext, salt=salt, nonce=nonce, kdf_id=KDF_GHOSTED)


def decrypt(blob: EncryptedBlob, passphrase: str) -> str:
    """Decrypt an EncryptedBlob. Verifies the AEAD tag before returning plaintext."""
    if not passphrase:
        raise ValueError("Passphrase must not be empty.")

    key = _derive_key(passphrase, blob.salt, blob.kdf_id)
    try:
        plaintext = SovereignChaCha20Poly1305(key).decrypt(blob.nonce, blob.ciphertext, None)
    except SovereignAuthenticationError as exc:
        # Never surface the underlying error — it could leak oracle information.
        raise DecryptionError(
            "Decryption failed. The passphrase may be incorrect, or the data "
            "may have been tampered with."
        ) from exc
    return plaintext.decode("utf-8")


def is_legacy_blob(blob: EncryptedBlob) -> bool:
    """True if the blob uses a legacy KDF (not GHOSTED-KDF-1)."""
    return blob.kdf_id != KDF_GHOSTED


def migrate_blob(blob: EncryptedBlob, passphrase: str) -> EncryptedBlob:
    """Re-encrypt a legacy blob under GHOSTED-KDF-1. No-op if already sovereign."""
    if blob.kdf_id == KDF_GHOSTED:
        return blob
    return encrypt(decrypt(blob, passphrase), passphrase)
