"""
Vault + app login — a RABBIT-KDF passphrase gate for RabbitGhost.

App login
    A single master passphrase. We store only a *verifier* — an encrypted sentinel,
    never the password itself. ``login(pw)`` succeeds iff ``pw`` opens the sentinel
    (RABBIT-CIPHER-1 AEAD auth makes a wrong password fail closed).

WireGuard vault
    The PackMesh private keys + per-device configs are sealed AT REST with the master
    passphrase (RABBIT-CIPHER-1). To anyone without it the vault is a black box; the
    mesh can only be brought up after ``unseal_mesh(pw)``. Underneath, every link
    still carries its own clamped key + symmetric PSK (consistent auth, task #14).

All crypto is Rabbit's own: RABBIT-KDF-1 (passphrase → key) + RABBIT-CIPHER-1.
"""

from __future__ import annotations

import base64
import json
import os
from typing import Any

_SENTINEL = "rabbitghost-vault-ok-v1"


def _vault_dir() -> str:
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    d = os.path.join(base, "RabbitGhost", "vault")
    os.makedirs(d, exist_ok=True)
    return d


def _sentinel_path() -> str:
    return os.path.join(_vault_dir(), "login.box")


def _mesh_path() -> str:
    return os.path.join(_vault_dir(), "mesh.box")


def _seal(obj: Any, passphrase: str) -> str:
    from rabbitghost.crypto import encrypt

    blob = encrypt(json.dumps(obj, ensure_ascii=False), passphrase)
    return base64.b64encode(blob.to_bytes()).decode()


def _unseal(token: str, passphrase: str) -> Any:
    from rabbitghost.crypto import EncryptedBlob, decrypt

    blob = EncryptedBlob.from_bytes(base64.b64decode(token))
    return json.loads(decrypt(blob, passphrase))


# ── app login ────────────────────────────────────────────────────────────────
def is_initialized() -> bool:
    return os.path.exists(_sentinel_path())


def initialize(passphrase: str) -> None:
    """Set the master password (once). Stores only an encrypted verifier."""
    if not passphrase or len(passphrase) < 12:
        raise ValueError(
            "passphrase too short (min 12 chars — it seals the whole mesh + mail vault)"
        )
    with open(_sentinel_path(), "w", encoding="ascii") as fh:
        fh.write(_seal(_SENTINEL, passphrase))


def login(passphrase: str) -> bool:
    """True iff the passphrase opens the verifier. Fail-closed on any error."""
    if not is_initialized():
        return False
    try:
        with open(_sentinel_path(), "r", encoding="ascii") as fh:
            return _unseal(fh.read(), passphrase) == _SENTINEL
    except Exception:
        return False


def change_password(old: str, new: str) -> bool:
    """Rotate the master password: verify old, re-seal the verifier AND the mesh."""
    if not login(old):
        return False
    if not new or len(new) < 12:
        raise ValueError("new passphrase too short (min 12 chars)")
    mesh = None
    if has_mesh():
        mesh = unseal_mesh(old)
    initialize(new)
    if mesh is not None:
        _write_mesh(mesh, new)  # 'new' was just set as the verifier; skip re-login KDF
    return True


# ── WireGuard vault ──────────────────────────────────────────────────────────
def has_mesh() -> bool:
    return os.path.exists(_mesh_path())


def _write_mesh(configs: dict, passphrase: str) -> None:
    """Seal + write the mesh vault (no login check — callers that already verified the
    passphrase use this to avoid a redundant RABBIT-KDF pass)."""
    with open(_mesh_path(), "w", encoding="ascii") as fh:
        fh.write(_seal(configs, passphrase))


def seal_mesh(configs: dict, passphrase: str) -> None:
    """Seal the per-device WireGuard configs at rest. Requires a valid login."""
    if not login(passphrase):
        raise PermissionError("vault locked: wrong or unset master password")
    _write_mesh(configs, passphrase)


def unseal_mesh(passphrase: str) -> dict:
    """Open the mesh vault (the only way to bring the tunnels up)."""
    if not login(passphrase):
        raise PermissionError("vault locked: wrong or unset master password")
    with open(_mesh_path(), "r", encoding="ascii") as fh:
        return _unseal(fh.read(), passphrase)


def build_and_seal_mesh(
    devices: list[tuple[str, str]], passphrase: str, hub: str = ""
) -> list[str]:
    """Generate a sovereign WireGuard PackMesh for *devices* [(name, endpoint), ...]
    and seal every config at rest behind the master password. Returns device names."""
    if not login(passphrase):
        raise PermissionError("vault locked: log in first")
    from rabbit.network.sovereign_wireguard import PackMesh

    mesh = PackMesh(hub=hub)
    for name, endpoint in devices:
        mesh.add_device(name, endpoint=endpoint)
    configs = mesh.generate()
    _write_mesh(configs, passphrase)  # already logged in above — skip the re-login KDF
    return list(configs.keys())
