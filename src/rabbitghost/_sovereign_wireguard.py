"""Sovereign WireGuard config generator — Rabbit builds his OWN pack VPN.

A VPN Rabbit should own is the **pack mesh**: a private, encrypted overlay that
links Lucy's own devices (NUC, laptop, phone) into one network as if on a single
LAN — with *no third party* in the middle. WireGuard is the right tool for that
job; this organ lets Rabbit generate every piece of it himself.

WHY THIS IS SOVEREIGN
    * Keys are made HERE, in pure Python — Rabbit's own X25519 (RFC 7748
      Montgomery ladder), the same curve WireGuard uses, with the same clamping
      as ``wg genkey`` / ``wg pubkey``. No ``wg`` binary, no ``cryptography``
      native lib, no online service ever sees a private key. Consistent with
      Rabbit's pure-Python crypto stack (RABBIT-CIPHER-1 / RABBIT-KDF-1).
    * Configs are written by Rabbit and contain only his pack's material.
    * Optional per-link pre-shared keys add a symmetric layer on top of the
      Noise handshake (defence-in-depth, mildly post-quantum-resistant).

WHAT THIS IS *NOT* (honest boundary)
    This builds a device-to-device pack mesh — the thing a self-owned VPN is
    GOOD at. It is deliberately NOT an anonymity exit: a single self-run exit IP
    traces straight back to its renter and is a downgrade from the Tor stack for
    "don't track me". Anonymity stays on ghost/Tor; this stays on private comms.
    The two are separate tools for separate jobs and must not be conflated.

USAGE
    from rabbit.network.sovereign_wireguard import PackMesh
    mesh = PackMesh(subnet="10.44.0.0/24")
    mesh.add_device("nuc",    endpoint="nuc.example:51820", listen_port=51820)
    mesh.add_device("laptop")
    mesh.add_device("phone")
    files = mesh.generate()          # {name: wg0.conf text}
    paths = mesh.write()             # writes ~/.rabbit/network/wireguard/<name>.conf 0600

CLI
    python -m rabbit.network.sovereign_wireguard nuc=nuc.example:51820 laptop phone
"""

from __future__ import annotations

import base64
import ipaddress
import logging
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger("rabbit.network.wireguard")


def _atomic_write_all(items: list[tuple[Path, bytes]], *, mode: int = 0o600) -> None:
    """Write a whole batch of files all-or-nothing. Each config holds a private
    key — a half-written .conf (crash mid-write) is a corrupt, unusable key file,
    and a loop that fails partway leaves a half-updated mesh. So: PHASE 1 write
    every payload to a temp sibling (same dir → same filesystem → rename is
    atomic), fsync each; PHASE 2 atomically rename them all into place. If any
    temp write fails, NO target is touched and every temp is cleaned up — the
    existing mesh on disk is left exactly as it was."""
    staged: list[tuple[Path, Path]] = []  # (tmp, final)
    try:
        for path, data in items:
            tmp = path.with_name(path.name + ".tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
            try:
                os.write(fd, data)
                os.fsync(fd)
            finally:
                os.close(fd)
            staged.append((tmp, path))
        for tmp, path in staged:  # PHASE 2 — commit (atomic per file)
            os.replace(tmp, path)
            try:
                os.chmod(path, mode)
            except OSError:
                pass
    except Exception:
        for tmp, _ in staged:  # rollback — leave the prior mesh untouched
            try:
                tmp.unlink(missing_ok=True)
            except Exception:  # noqa: BLE001
                pass
        raise


__all__ = [
    "gen_private_key",
    "derive_public_key",
    "gen_preshared_key",
    "encode_key",
    "decode_key",
    "Device",
    "PackMesh",
]

# ---------------------------------------------------------------------------
# Pure-Python X25519 (RFC 7748) — Rabbit's own Curve25519 scalar multiplication.
# Matches WireGuard exactly: clamped 32-byte private key; public = X25519(k, 9).
# ---------------------------------------------------------------------------

_P = 2**255 - 19
_A24 = 121665
_BASE_U = 9


def _clamp(k: bytearray) -> bytearray:
    """The Curve25519 scalar clamping `wg genkey` applies to a fresh key."""
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return k


def _decode_u(u: bytes) -> int:
    a = bytearray(u[:32])
    a[31] &= 127  # mask the top bit, per RFC 7748
    return int.from_bytes(a, "little")


def _x25519(scalar: bytes, u_bytes: bytes) -> bytes:
    """Constant-shape Montgomery ladder. Returns the 32-byte u-coordinate."""
    k = int.from_bytes(_clamp(bytearray(scalar[:32])), "little")
    x1 = _decode_u(u_bytes)
    x2, z2 = 1, 0
    x3, z3 = x1, 1
    swap = 0
    for t in range(254, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        a = (x2 + z2) % _P
        aa = (a * a) % _P
        b = (x2 - z2) % _P
        bb = (b * b) % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = (d * a) % _P
        cb = (c * b) % _P
        x3 = pow((da + cb) % _P, 2, _P)
        z3 = (x1 * pow((da - cb) % _P, 2, _P)) % _P
        x2 = (aa * bb) % _P
        z2 = (e * ((aa + (_A24 * e)) % _P)) % _P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    res = (x2 * pow(z2, _P - 2, _P)) % _P
    return res.to_bytes(32, "little")


def gen_private_key() -> bytes:
    """A fresh, clamped 32-byte WireGuard private key (== `wg genkey`)."""
    return bytes(_clamp(bytearray(secrets.token_bytes(32))))


def derive_public_key(private_key: bytes) -> bytes:
    """Public key for a private key (== `wg pubkey`): X25519(priv, 9)."""
    base = _BASE_U.to_bytes(32, "little")
    return _x25519(private_key, base)


def gen_preshared_key() -> bytes:
    """A fresh 32-byte symmetric pre-shared key (== `wg genpsk`)."""
    return secrets.token_bytes(32)


def encode_key(raw: bytes) -> str:
    """WireGuard key wire form — base64 of the 32 raw bytes."""
    return base64.standard_b64encode(raw).decode("ascii")


def decode_key(b64: str) -> bytes:
    return base64.standard_b64decode(b64.encode("ascii"))


# Curve25519 small-order / blacklisted points (libsodium's set). A public key
# equal to any of these forces the shared secret to a known constant — a peer
# offering one is trying to break the handshake. Generated keys are clamped and
# never land here; this guards keys IMPORTED from elsewhere.
_LOW_ORDER_POINTS = frozenset(
    bytes.fromhex(h)
    for h in (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "0500000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "cdeb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "4c9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "dbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    )
)


def is_valid_public_key(pub: bytes) -> bool:
    """A WireGuard public key is usable iff it's 32 bytes and not a low-order
    point (which would degrade the handshake to a known shared secret)."""
    return len(pub) == 32 and bytes(pub) not in _LOW_ORDER_POINTS


# ---------------------------------------------------------------------------
# Pack mesh
# ---------------------------------------------------------------------------


@dataclass
class Device:
    """One peer in the pack (a device Lucy owns)."""

    name: str
    address: str = ""  # assigned from the subnet, e.g. 10.44.0.2
    endpoint: str = ""  # host:port — only devices reachable inbound
    listen_port: int = 0  # UDP port this device listens on (if any)
    dns: str = ""  # optional DNS for [Interface]
    private_key: bytes = field(default=b"", repr=False)
    public_key: bytes = b""

    def keygen(self) -> None:
        if not self.private_key:
            self.private_key = gen_private_key()
        self.public_key = derive_public_key(self.private_key)


def _link_psk_key(a: str, b: str) -> tuple[str, str]:
    return tuple(sorted((a, b)))  # symmetric link identity, order-independent


class PackMesh:
    """A full WireGuard mesh among Lucy's devices, generated entirely by Rabbit.

    Every device gets a /32 in the mesh subnet and a peer entry for every other
    device. Devices with an ``endpoint`` are dial-able; devices behind NAT (no
    endpoint) reach the others and stay connected via ``PersistentKeepalive``.
    A unique pre-shared key is minted per link for an extra symmetric layer.
    """

    def __init__(
        self,
        subnet: str = "10.44.0.0/24",
        *,
        keepalive: int = 25,
        use_psk: bool = True,
        hub: str = "",
    ) -> None:
        self._net = ipaddress.ip_network(subnet, strict=False)
        self._hosts = self._net.hosts()
        self._keepalive = int(keepalive)
        self._use_psk = bool(use_psk)
        self._hub = hub  # "" → full mesh; else hub-and-spoke through it
        self._devices: dict[str, Device] = {}
        self._psk: dict[tuple[str, str], bytes] = {}

    def add_device(
        self,
        name: str,
        *,
        endpoint: str = "",
        listen_port: int = 0,
        dns: str = "",
        private_key: bytes = b"",
    ) -> Device:
        if name in self._devices:
            raise ValueError(f"duplicate device: {name}")
        addr = str(next(self._hosts))
        dev = Device(
            name=name,
            address=addr,
            endpoint=endpoint,
            listen_port=listen_port,
            dns=dns,
            private_key=private_key,
        )
        dev.keygen()
        # defensive: a generated key is clamped and never low-order, but reject any
        # imported key that would degrade the handshake to a known shared secret.
        if not is_valid_public_key(dev.public_key):
            raise ValueError(f"device {name}: invalid/low-order public key")
        self._devices[name] = dev
        return dev

    def _psk_for(self, a: str, b: str) -> bytes:
        key = _link_psk_key(a, b)
        if key not in self._psk:
            self._psk[key] = gen_preshared_key()
        return self._psk[key]

    def _peers_for(self, name: str) -> list[str]:
        """Which devices this one peers with.

        Full mesh → everyone else. Hub-and-spoke → the hub peers with every
        spoke, but a spoke peers ONLY with the hub (and reaches the others
        *through* it). Hub-and-spoke is the answer when devices are behind NAT
        with no reachable endpoint of their own (phones, laptops on the move):
        they can't dial each other directly, so the one device with a public
        endpoint (the NUC/tower) relays between them."""
        if not self._hub:
            return [p for p in self._devices if p != name]
        if name == self._hub:
            return [p for p in self._devices if p != name]
        return [self._hub]  # a spoke talks only to the hub

    def render(self, name: str) -> str:
        """Render one device's wg0.conf (its [Interface] + its peers)."""
        me = self._devices[name]
        spoke = bool(self._hub) and name != self._hub
        lines: list[str] = []
        topo = "hub-and-spoke" if self._hub else "full mesh"
        lines.append(f"# Rabbit pack mesh ({topo}) — config for '{name}'")
        lines.append(f"# subnet {self._net} | generated by sovereign_wireguard")
        if self._hub and name == self._hub:
            lines.append(
                "# NOTE: this hub RELAYS between spokes — enable IP "
                "forwarding (net.ipv4.ip_forward=1)."
            )
        lines.append("[Interface]")
        lines.append(f"# {name}")
        lines.append(f"Address = {me.address}/{self._net.prefixlen}")
        lines.append(f"PrivateKey = {encode_key(me.private_key)}")
        if me.listen_port:
            lines.append(f"ListenPort = {me.listen_port}")
        if me.dns:
            lines.append(f"DNS = {me.dns}")
        for peer_name in self._peers_for(name):
            peer = self._devices[peer_name]
            lines.append("")
            lines.append("[Peer]")
            lines.append(f"# {peer_name}")
            lines.append(f"PublicKey = {encode_key(peer.public_key)}")
            if self._use_psk:
                lines.append(
                    f"PresharedKey = {encode_key(self._psk_for(name, peer_name))}"
                )
            # a spoke routes the WHOLE subnet to the hub (so it can reach siblings
            # via the relay); everyone else routes just the peer's own /32.
            if spoke and peer_name == self._hub:
                lines.append(f"AllowedIPs = {self._net}")
            else:
                lines.append(f"AllowedIPs = {peer.address}/32")
            if peer.endpoint:
                lines.append(f"Endpoint = {peer.endpoint}")
            # a NAT-bound peer (no inbound endpoint of its own) must keep the
            # tunnel warm so the others can always reach it.
            if not me.endpoint or not peer.endpoint:
                lines.append(f"PersistentKeepalive = {self._keepalive}")
        return "\n".join(lines) + "\n"

    def generate(self) -> dict[str, str]:
        """Every device's config text, keyed by device name."""
        if len(self._devices) < 2:
            raise ValueError("a mesh needs at least two devices")
        return {name: self.render(name) for name in self._devices}

    def write(self, out_dir: str | os.PathLike | None = None) -> dict[str, Path]:
        """Write each config to disk with private 0600 permissions.

        Default location: ~/.rabbit/network/wireguard/<name>.conf
        """
        base = (
            Path(out_dir)
            if out_dir
            else (Path.home() / ".rabbit" / "network" / "wireguard")
        )
        base.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(base, 0o700)
        except OSError:
            pass
        written: dict[str, Path] = {}
        items: list[tuple[Path, bytes]] = []
        for name, text in self.generate().items():
            path = base / f"{name}.conf"
            items.append((path, text.encode("utf-8")))
            written[name] = path
        # All-or-nothing + crash-safe: a private key on disk must never be a
        # half-written file, and the mesh must never be partially updated.
        _atomic_write_all(items, mode=0o600)
        for name, path in written.items():
            logger.info("wrote pack config: %s", path)
        return written

    def write_encrypted(
        self, passphrase: str, out_dir: str | os.PathLike | None = None
    ) -> dict[str, Path]:
        """Write each config SEALED at rest with RABBIT-CIPHER-1 (the same
        sovereign cipher as the rest of Rabbit) → ``<name>.conf.enc``.

        A wg0.conf holds a private key, so leaving it as plaintext on disk is the
        weak link. Encrypted-at-rest, the key is exposed only at bring-up time
        (decrypt → ``wg-quick`` → wipe). Pairs with ``decrypt_config``."""
        from rabbitghost import crypto

        base = (
            Path(out_dir)
            if out_dir
            else (Path.home() / ".rabbit" / "network" / "wireguard")
        )
        base.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(base, 0o700)
        except OSError:
            pass
        written: dict[str, Path] = {}
        items: list[tuple[Path, bytes]] = []
        for name, text in self.generate().items():
            blob = crypto.encrypt(text, passphrase).to_bytes()
            path = base / f"{name}.conf.enc"
            items.append((path, blob))
            written[name] = path
        _atomic_write_all(items, mode=0o600)
        for name, path in written.items():
            logger.info("wrote sealed pack config: %s", path)
        return written

    @staticmethod
    def decrypt_config(path: str | os.PathLike, passphrase: str) -> str:
        """Decrypt a ``*.conf.enc`` produced by ``write_encrypted`` back to the
        plaintext wg0.conf text (for piping into ``wg-quick`` at bring-up)."""
        from rabbitghost import crypto

        raw = Path(path).read_bytes()
        return crypto.decrypt(crypto.EncryptedBlob.from_bytes(raw), passphrase)

    def public_summary(self) -> dict[str, dict]:
        """Non-secret view (addresses + public keys) — safe to log/share."""
        return {
            name: {
                "address": d.address,
                "public_key": encode_key(d.public_key),
                "endpoint": d.endpoint or None,
            }
            for name, d in self._devices.items()
        }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_arg(token: str) -> tuple[str, str, int]:
    """`name`  or  `name=host:port` → (name, endpoint, listen_port)."""
    if "=" not in token:
        return token, "", 0
    name, ep = token.split("=", 1)
    port = 0
    if ":" in ep:
        try:
            port = int(ep.rsplit(":", 1)[1])
        except ValueError:
            port = 0
    return name, ep, port


def main(argv: list[str] | None = None) -> int:
    import sys

    args = list(argv if argv is not None else sys.argv[1:])
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        return 0 if args else 2
    no_psk = "--no-psk" in args
    args = [a for a in args if a != "--no-psk"]

    mesh = PackMesh(use_psk=not no_psk)
    for token in args:
        name, ep, port = _parse_arg(token)
        mesh.add_device(name, endpoint=ep, listen_port=port or (51820 if ep else 0))

    paths = mesh.write()
    print("Sovereign pack mesh generated (keys made in-process, never exported):")
    for name, info in mesh.public_summary().items():
        ep = f"  endpoint={info['endpoint']}" if info["endpoint"] else ""
        print(f"  {name:10s} {info['address']:14s} pub={info['public_key']}{ep}")
    print("\nConfig files (chmod 0600):")
    for name, p in paths.items():
        print(f"  {name:10s} {p}")
    print("\nBring up on each device:  wg-quick up ./<name>.conf")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
