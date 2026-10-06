"""Detect the local network (subnet, gateway, DNS) – via Supervisor, fallback /proc."""
from __future__ import annotations

import ipaddress
import json
import logging
import subprocess
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

LOG = logging.getLogger("brion.security.net")


class NetworkError(Exception):
    pass


@dataclass
class NetworkInfo:
    interface: str
    address: str
    prefix: int
    network: str               # CIDR that will be scanned
    gateway: Optional[str]
    dns: List[str] = field(default_factory=list)
    source: str = "supervisor"
    note: Optional[str] = None

    def to_dict(self) -> Dict:
        return asdict(self)


def _validate(address: str, prefix: int, gateway: Optional[str], dns: List[str], iface: str, source: str,
              min_prefix: int) -> NetworkInfo:
    try:
        iface_net = ipaddress.ip_interface(f"{address}/{prefix}")
    except ValueError as exc:
        raise NetworkError(f"invalid interface address: {exc}") from None
    if iface_net.version != 4:
        raise NetworkError("only IPv4 networks are scanned")
    net = iface_net.network
    if not net.is_private or net.is_loopback or net.is_link_local:
        raise NetworkError(f"{net} is not a private LAN – refusing to scan")
    note = None
    if prefix < min_prefix:
        net = ipaddress.ip_interface(f"{address}/24").network
        note = f"Netz /{prefix} zu groß – Prüfung auf {net} begrenzt"
    if gateway:
        try:
            if ipaddress.ip_address(gateway) not in iface_net.network:
                LOG.warning("gateway outside interface network")
        except ValueError:
            gateway = None
    clean_dns = []
    for d in dns:
        try:
            a = ipaddress.ip_address(d)
        except ValueError:
            continue
        if not a.is_loopback and not str(a).startswith("172.30.32."):  # skip HA-internal DNS
            clean_dns.append(str(a))
    return NetworkInfo(iface, str(iface_net.ip), prefix, str(net), gateway, clean_dns, source, note)


def from_supervisor(url: str, token: str, min_prefix: int = 22, timeout: float = 5.0) -> NetworkInfo:
    req = urllib.request.Request(f"{url}/network/info", headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read()).get("data", {})
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise NetworkError(f"supervisor network info unavailable: {type(exc).__name__}") from None
    candidates = [i for i in data.get("interfaces", []) if i.get("connected") and (i.get("ipv4") or {}).get("address")]
    candidates.sort(key=lambda i: (not i.get("primary"), i.get("type") != "ethernet"))
    if not candidates:
        raise NetworkError("no connected IPv4 interface")
    i = candidates[0]
    ipv4 = i["ipv4"]
    addr, _, pre = ipv4["address"][0].partition("/")
    return _validate(addr, int(pre or 24), ipv4.get("gateway"), list(ipv4.get("nameservers") or []),
                     i.get("interface", "?"), "supervisor", min_prefix)


def from_proc(proc_root: Path, resolv_conf: Path, min_prefix: int = 22) -> NetworkInfo:
    iface, gateway = None, None
    try:
        for line in (proc_root / "net" / "route").read_text().splitlines()[1:]:
            parts = line.split()
            if len(parts) > 2 and parts[1] == "00000000":
                iface = parts[0]
                gateway = str(ipaddress.ip_address(bytes.fromhex(parts[2])[::-1]))
                break
    except (OSError, ValueError):
        pass
    if not iface:
        raise NetworkError("no default route")
    try:
        out = subprocess.run(["ip", "-o", "-4", "addr", "show", "dev", iface], capture_output=True, text=True,
                             timeout=5, check=True).stdout
        cidr = out.split(" inet ")[1].split()[0]
    except (OSError, subprocess.SubprocessError, IndexError):
        raise NetworkError(f"cannot read IPv4 address of {iface}") from None
    addr, _, pre = cidr.partition("/")
    dns = []
    try:
        dns = [ln.split()[1] for ln in resolv_conf.read_text().splitlines() if ln.startswith("nameserver")]
    except OSError:
        pass
    return _validate(addr, int(pre), gateway, dns, iface, "proc", min_prefix)


def detect(supervisor_url: str, token: str, proc_root: Path, resolv_conf: Path, min_prefix: int = 22) -> NetworkInfo:
    try:
        return from_supervisor(supervisor_url, token, min_prefix)
    except NetworkError as exc:
        LOG.info("falling back to /proc network detection: %s", exc)
        return from_proc(proc_root, resolv_conf, min_prefix)
