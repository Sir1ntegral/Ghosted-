"""Ghosted's own WireGuard PackMesh — vendored pure-Python (X25519), zero deps.

Decoupled from rabbit.network.sovereign_wireguard. The mesh generator is carried
internally (_sovereign_wireguard) so Ghosted owns its tunnel fabric outright.

Contract preserved for vault.py:
    PackMesh(hub=...).add_device(name, endpoint=...).generate() -> {name: conf}
"""

from __future__ import annotations

from ._sovereign_wireguard import PackMesh

__all__ = ["PackMesh"]
