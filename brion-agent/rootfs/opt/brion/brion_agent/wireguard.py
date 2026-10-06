"""WireGuard key generation and tunnel control (WireGuard runs on the HAOS host kernel;
the add-on has host_network + NET_ADMIN).

* The private key is generated in-process (X25519 via `cryptography`) or by `wg genkey`
  over a pipe - never via command-line arguments - and written with mode 0600 to
  /data/brion/wg/private.key (excluded from backups). `wg set` reads it from that file.
* Nothing in this module returns or logs the private key.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import logging
import os
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence

LOG = logging.getLogger("brion.wireguard")
_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$")
_IFACE_RE = re.compile(r"^[a-z][a-z0-9]{1,14}$")
_ENDPOINT_RE = re.compile(r"^(\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]{1,253}):([0-9]{1,5})$")
HANDSHAKE_MAX_AGE = 300


class WireGuardError(Exception):
    pass


Runner = Callable[[Sequence[str], Optional[bytes]], subprocess.CompletedProcess]


def default_runner(argv: Sequence[str], stdin: Optional[bytes] = None) -> subprocess.CompletedProcess:
    return subprocess.run(list(argv), input=stdin, capture_output=True, timeout=15, check=False)


def valid_key(k: str) -> bool:
    return bool(_KEY_RE.match(k or ""))


def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def generate_keypair(key_file: Path, runner: Runner = default_runner) -> str:
    """Create the device keypair. Returns ONLY the public key (base64)."""
    if key_file.exists() and key_file.stat().st_size > 0:
        raise WireGuardError("a WireGuard private key already exists - refusing to overwrite")
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        priv = X25519PrivateKey.generate()
        raw = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                 serialization.NoEncryption())
        pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        _write_private(key_file, base64.b64encode(raw) + b"\n")
        del raw, priv
        return base64.b64encode(pub).decode()
    except ImportError:
        pass
    gen = runner(["wg", "genkey"], None)
    if gen.returncode != 0 or not gen.stdout:
        raise WireGuardError("wg genkey failed")
    _write_private(key_file, gen.stdout.strip() + b"\n")
    pub = runner(["wg", "pubkey"], gen.stdout)
    if pub.returncode != 0:
        raise WireGuardError("wg pubkey failed")
    return pub.stdout.decode().strip()


def public_key_of(key_file: Path, runner: Runner = default_runner) -> str:
    data = key_file.read_bytes().strip()
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        priv = X25519PrivateKey.from_private_bytes(base64.b64decode(data))
        return base64.b64encode(priv.public_key().public_bytes(serialization.Encoding.Raw,
                                                               serialization.PublicFormat.Raw)).decode()
    except ImportError:
        out = runner(["wg", "pubkey"], data)
        return out.stdout.decode().strip()


@dataclass
class PeerConfig:
    address: str                 # tunnel address of this device, e.g. 10.88.0.42/32
    server_public_key: str
    endpoint: str                # host:port
    allowed_ips: List[str]       # private ranges only (no default route)
    persistent_keepalive: int = 25
    has_psk: bool = False

    @classmethod
    def from_activation(cls, d: Dict) -> "PeerConfig":
        try:
            addr = ipaddress.ip_interface(str(d["address"]))
            allowed = [str(ipaddress.ip_network(str(n), strict=False)) for n in d["allowed_ips"]]
            endpoint = str(d["endpoint"])
            keepalive = int(d.get("persistent_keepalive", 25))
        except (KeyError, ValueError, TypeError) as exc:
            raise WireGuardError(f"invalid peer configuration: {type(exc).__name__}") from None
        if not addr.network.is_private:
            raise WireGuardError("tunnel address must be private")
        for n in allowed:
            net = ipaddress.ip_network(n)
            if net.prefixlen < 8 or not net.is_private:
                raise WireGuardError(f"allowed_ips {n} not permitted (no default/public routes)")
        if not valid_key(str(d.get("server_public_key", ""))):
            raise WireGuardError("invalid server public key")
        m = _ENDPOINT_RE.match(endpoint)
        if not m or not 0 < int(m.group(2)) < 65536:
            raise WireGuardError("invalid endpoint")
        if not 0 <= keepalive <= 3600:
            raise WireGuardError("invalid keepalive")
        return cls(str(addr), d["server_public_key"], endpoint, allowed, keepalive)

    def to_dict(self) -> Dict:
        return {"address": self.address, "server_public_key": self.server_public_key, "endpoint": self.endpoint,
                "allowed_ips": self.allowed_ips, "persistent_keepalive": self.persistent_keepalive,
                "has_psk": self.has_psk}


class WireGuard:
    def __init__(self, interface: str, key_file: Path, psk_file: Path, peer_file: Path, sys_net: Path,
                 runner: Runner = default_runner) -> None:
        if not _IFACE_RE.match(interface):
            raise WireGuardError("invalid interface name")
        self.iface, self.key_file, self.psk_file, self.peer_file = interface, key_file, psk_file, peer_file
        self.sys_net, self.run = sys_net, runner

    def _ok(self, argv: Sequence[str]) -> None:
        r = self.run(argv, None)
        if r.returncode != 0:
            raise WireGuardError(f"{argv[0]} {argv[1] if len(argv) > 1 else ''} failed: "
                                 f"{(r.stderr or b'').decode(errors='replace')[:160]}")

    def save_peer(self, peer: PeerConfig, psk: Optional[str]) -> None:
        if psk:
            if not valid_key(psk):
                raise WireGuardError("invalid preshared key")
            _write_private(self.psk_file, psk.encode() + b"\n")
            peer.has_psk = True
        _write_private(self.peer_file, json.dumps(peer.to_dict()).encode())

    def load_peer(self) -> Optional[PeerConfig]:
        try:
            d = json.loads(self.peer_file.read_text())
        except (OSError, ValueError):
            return None
        p = PeerConfig.from_activation(d)
        p.has_psk = bool(d.get("has_psk"))
        return p

    def interface_up(self) -> bool:
        try:
            return "DEVTYPE=wireguard" in (self.sys_net / self.iface / "uevent").read_text()
        except OSError:
            return False

    def up(self) -> None:
        peer = self.load_peer()
        if peer is None or not self.key_file.exists():
            raise WireGuardError("no provisioned WireGuard configuration")
        if self.interface_up():
            self.down()
        self._ok(["ip", "link", "add", "dev", self.iface, "type", "wireguard"])
        try:
            cmd = ["wg", "set", self.iface, "private-key", str(self.key_file), "peer", peer.server_public_key]
            if peer.has_psk:
                cmd += ["preshared-key", str(self.psk_file)]
            cmd += ["endpoint", peer.endpoint, "allowed-ips", ",".join(peer.allowed_ips),
                    "persistent-keepalive", str(peer.persistent_keepalive)]
            self._ok(cmd)
            self._ok(["ip", "address", "add", peer.address, "dev", self.iface])
            self._ok(["ip", "link", "set", "up", "dev", self.iface])
            for net in peer.allowed_ips:
                self._ok(["ip", "route", "replace", net, "dev", self.iface])
        except WireGuardError:
            self.down()
            raise

    def down(self) -> bool:
        if not self.interface_up():
            return False
        r = self.run(["ip", "link", "del", "dev", self.iface], None)
        return r.returncode == 0

    def last_handshake_age(self) -> Optional[float]:
        r = self.run(["wg", "show", self.iface, "latest-handshakes"], None)
        if r.returncode != 0:
            return None
        ts = [int(line.split()[1]) for line in r.stdout.decode().splitlines() if len(line.split()) == 2]
        latest = max(ts or [0])
        return None if latest == 0 else max(0.0, time.time() - latest)

    def healthy(self) -> Dict[str, object]:
        up = self.interface_up()
        age = self.last_handshake_age() if up else None
        return {"interface": up, "handshake_age_s": None if age is None else round(age),
                "ok": up and age is not None and age < HANDSHAKE_MAX_AGE}
