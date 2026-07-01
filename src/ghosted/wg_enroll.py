"""
Ghosted — WireGuard enrollment (both directions), guarded by Gojo, sealed in the vault.

Enrollment is a ONCE-and-REMEMBERED act: the mesh state (device keys + PSK map) is
sealed at rest with the master password, so peers accrue incrementally without ever
regenerating everyone's keys, and the mesh is remembered across sessions.

Two directions:
  • add_peer(name, endpoint)      — THIS machine (the hub) provisions a new device: it
    mints the device's keys and returns a ready-to-import config (+ QR). Simplest.
  • enroll_peer_pubkey(name, pub) — register a device that generated its OWN keys and
    handed back only its public key (private key never leaves that device).
  • join_mesh(name, hub_pub, ...) — THIS machine joins someone else's mesh: it mints its
    own keys locally and returns its config + the public key/address to hand to the hub.

Every enrollment runs through ghosted.security.guard first (Gojo boundary + audit) and
is announced on the security event bus. State reconstruction preserves each device's
private key, address (assignment is append-only so addresses never shift), and the PSK
of every existing link; only new links to the new device mint fresh PSKs.
"""

from __future__ import annotations

import base64

from ghosted import event_bus, security, vault

__all__ = [
    "add_peer",
    "enroll_peer_pubkey",
    "join_mesh",
    "roster",
    "device_config",
]

_DEFAULT_SUBNET = "10.44.0.0/24"


# ── state <-> PackMesh reconstruction ──────────────────────────────────────────
def _serialize(mesh) -> dict:
    devices = [
        {
            "name": name,
            "address": dev.address,  # explicit so removal never shifts other devices
            "endpoint": dev.endpoint,
            "listen_port": dev.listen_port,
            "dns": dev.dns,
            "priv": base64.b64encode(dev.private_key).decode(),
            "external_pub": base64.b64encode(dev.public_key).decode()
            if not dev.private_key
            else "",
        }
        for name, dev in mesh._devices.items()
    ]
    psk = {
        "\x00".join(sorted((a, b))): base64.b64encode(v).decode()
        for (a, b), v in mesh._psk.items()
    }
    return {
        "subnet": str(mesh._net),
        "hub": mesh._hub,
        "use_psk": mesh._use_psk,
        "keepalive": mesh._keepalive,
        "devices": devices,
        "psk": psk,
    }


def _mesh_from_state(state: dict):
    from ghosted._sovereign_wireguard import derive_public_key
    from ghosted.wireguard import PackMesh

    mesh = PackMesh(
        subnet=state.get("subnet", _DEFAULT_SUBNET),
        keepalive=int(state.get("keepalive", 25)),
        use_psk=bool(state.get("use_psk", True)),
        hub=state.get("hub", ""),
    )
    for d in state.get("devices", []):
        priv_b64 = d.get("priv", "")
        if priv_b64:
            dev = mesh.add_device(
                d["name"],
                endpoint=d.get("endpoint", ""),
                listen_port=int(d.get("listen_port", 0)),
                dns=d.get("dns", ""),
                private_key=base64.b64decode(priv_b64),
            )
        else:
            # externally-keyed peer: we hold only its public key. Add a keyless slot
            # and stamp the known public key onto it.
            dev = mesh.add_device(d["name"], endpoint=d.get("endpoint", ""))
            dev.private_key = b""
            dev.public_key = base64.b64decode(d["external_pub"])
        if d.get("address"):  # restore the exact address so removals never shift peers
            dev.address = d["address"]
    for k, v in state.get("psk", {}).items():
        a, b = k.split("\x00")
        mesh._psk[tuple(sorted((a, b)))] = base64.b64decode(v)
    return mesh


def _load_or_new(passphrase: str, hub: str = ""):
    from ghosted.wireguard import PackMesh

    if vault.has_mesh_state():
        return _mesh_from_state(vault.read_mesh_state(passphrase))
    if not vault.login(passphrase):
        raise PermissionError("vault locked: log in first")
    return PackMesh(hub=hub)


def _persist(mesh, passphrase: str) -> dict:
    """Render every device (minting new-link PSKs), then seal state + configs."""
    configs = {name: mesh.render(name) for name in mesh._devices}
    vault.write_mesh_state(_serialize(mesh), passphrase)
    vault._write_mesh(configs, passphrase)  # already logged in by caller
    return configs


def _next_free_address(mesh) -> str:
    """Lowest /32 host in the subnet not already assigned — so a new device fills any
    gap left by a removal rather than shifting anyone."""
    used = {str(d.address) for d in mesh._devices.values() if d.address}
    for host in mesh._net.hosts():
        if str(host) not in used:
            return str(host)
    raise ValueError("mesh subnet is full")


# ── public API ─────────────────────────────────────────────────────────────────
def add_peer(name: str, endpoint: str = "", passphrase: str = "", *, hub: str = "",
             source_class: str = "internal") -> dict:
    """Hub provisions a new device: mint its keys, seal state, return its config.

    Guarded by Gojo (caller passes the REAL source_class so a remote request is denied
    at the boundary). The returned ``config`` is ready to import into WireGuard (or
    render as a QR). Idempotent-safe: a duplicate name is rejected, not silently reused.
    """
    v = security.guard(action="wireguard_enroll", source_class=source_class,
                       metadata={"device": name, "endpoint": endpoint})
    if v.get("decision") != "allow":
        return {"ok": False, "error": "blocked by boundary", "reason": v.get("reason")}
    mesh = _load_or_new(passphrase, hub=hub)
    if name in mesh._devices:
        return {"ok": False, "error": f"device already enrolled: {name}"}
    free = _next_free_address(mesh)
    dev = mesh.add_device(name, endpoint=endpoint)
    dev.address = free  # deterministic: fill the lowest free slot, never shift peers
    configs = _persist(mesh, passphrase)
    event_bus.announce({"component": "wireguard", "event_type": "enroll_peer",
                        "device": name, "count": len(mesh._devices)})
    return {"ok": True, "name": name, "config": configs[name],
            "devices": list(mesh._devices), "count": len(mesh._devices)}


def enroll_peer_pubkey(name: str, public_key: str, passphrase: str, *,
                       endpoint: str = "") -> dict:
    """Register a device that generated its OWN keys and handed back its public key.

    Ghosted never sees that device's private key — it only records the public key and
    an address so the hub can route to it. Returns the hub-side confirmation.
    """
    from ghosted._sovereign_wireguard import decode_key, is_valid_public_key

    v = security.guard(action="wireguard_enroll", metadata={"device": name})
    if v.get("decision") != "allow":
        return {"ok": False, "error": "blocked by boundary", "reason": v.get("reason")}
    try:
        raw = decode_key(public_key)
        if not is_valid_public_key(raw):
            return {"ok": False, "error": "invalid or low-order public key"}
    except Exception:
        return {"ok": False, "error": "unparseable public key"}
    mesh = _load_or_new(passphrase)
    if name in mesh._devices:
        return {"ok": False, "error": f"device already enrolled: {name}"}
    free = _next_free_address(mesh)
    dev = mesh.add_device(name, endpoint=endpoint)
    dev.address = free
    dev.private_key = b""  # we do NOT hold this device's private key
    dev.public_key = raw
    _persist(mesh, passphrase)
    event_bus.announce({"component": "wireguard", "event_type": "enroll_peer_pubkey",
                        "device": name})
    return {"ok": True, "name": name, "address": dev.address, "count": len(mesh._devices)}


def join_mesh(this_name: str, hub_public_key: str, hub_endpoint: str, passphrase: str, *,
              subnet: str = _DEFAULT_SUBNET, hub_address: str = "10.44.0.1",
              my_address: str = "10.44.0.9", source_class: str = "internal") -> dict:
    """THIS machine joins an existing mesh. Generates its OWN keys locally (private key
    never leaves this device), seals the resulting config, and returns this device's
    public key + address to hand back to the hub operator so they can add us."""
    import ipaddress

    from ghosted._sovereign_wireguard import (
        decode_key, derive_public_key, encode_key, gen_preshared_key,
        gen_private_key, is_valid_public_key,
    )

    v = security.guard(action="wireguard_join", source_class=source_class,
                       metadata={"device": this_name, "endpoint": hub_endpoint})
    if v.get("decision") != "allow":
        return {"ok": False, "error": "blocked by boundary", "reason": v.get("reason")}
    if not vault.login(passphrase):
        raise PermissionError("vault locked: log in first")
    try:
        if not is_valid_public_key(decode_key(hub_public_key)):
            return {"ok": False, "error": "invalid or low-order hub public key"}
    except Exception:
        return {"ok": False, "error": "unparseable hub public key"}

    priv = gen_private_key()
    pub = derive_public_key(priv)
    psk = gen_preshared_key()
    prefix = ipaddress.ip_network(subnet, strict=False).prefixlen
    conf = (
        f"# Ghosted — joined mesh, config for '{this_name}'\n"
        "[Interface]\n"
        f"# {this_name}\n"
        f"Address = {my_address}/{prefix}\n"
        f"PrivateKey = {encode_key(priv)}\n"
        "\n[Peer]\n"
        "# hub\n"
        f"PublicKey = {hub_public_key}\n"
        f"PresharedKey = {encode_key(psk)}\n"
        f"AllowedIPs = {subnet}\n"
        f"Endpoint = {hub_endpoint}\n"
        "PersistentKeepalive = 25\n"
    )
    # Seal this device's config into the mesh vault under its name.
    existing = vault.unseal_mesh(passphrase) if vault.has_mesh() else {}
    existing[this_name] = conf
    vault._write_mesh(existing, passphrase)
    event_bus.announce({"component": "wireguard", "event_type": "join_mesh",
                        "device": this_name, "hub_endpoint": hub_endpoint})
    return {
        "ok": True, "name": this_name, "config": conf,
        "public_key": encode_key(pub), "preshared_key": encode_key(psk),
        "address": my_address,
        "hand_back": "give the hub operator your public_key + preshared_key + address "
                     "so they can add you (enroll_peer_pubkey).",
    }


def remove_device(name: str, passphrase: str, *, source_class: str = "internal") -> dict:
    """Remove an enrolled device from the mesh. Remaining devices keep their keys AND
    addresses (addresses are stored explicitly, so removal never shifts anyone); PSK
    links involving the removed device are pruned. Guarded by Gojo."""
    v = security.guard(action="wireguard_remove", source_class=source_class,
                       metadata={"device": name})
    if v.get("decision") != "allow":
        return {"ok": False, "error": "blocked by boundary", "reason": v.get("reason")}
    if not vault.has_mesh_state():
        return {"ok": False, "error": "no mesh enrolled yet"}
    state = vault.read_mesh_state(passphrase)
    kept = [d for d in state.get("devices", []) if d["name"] != name]
    if len(kept) == len(state.get("devices", [])):
        return {"ok": False, "error": f"no such device: {name}"}
    state["devices"] = kept
    state["psk"] = {
        k: val for k, val in state.get("psk", {}).items()
        if name not in k.split("\x00")
    }
    mesh = _mesh_from_state(state)
    _persist(mesh, passphrase)
    event_bus.announce({"component": "wireguard", "event_type": "remove_peer",
                        "device": name, "count": len(mesh._devices)})
    return {"ok": True, "removed": name, "count": len(mesh._devices)}


def roster(passphrase: str) -> list[dict]:
    """Non-secret view of the enrolled devices: name, address, endpoint (no keys)."""
    if not vault.has_mesh_state():
        return []
    mesh = _mesh_from_state(vault.read_mesh_state(passphrase))
    return [
        {"name": n, "address": d.address, "endpoint": d.endpoint or "(NAT / no inbound)"}
        for n, d in mesh._devices.items()
    ]


def device_config(name: str, passphrase: str) -> str | None:
    """The sealed config text for one enrolled device (to re-export / QR), or None."""
    if not vault.has_mesh():
        return None
    return vault.unseal_mesh(passphrase).get(name)
