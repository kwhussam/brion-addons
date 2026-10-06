"""Local-only nmap wrapper: host discovery (-sn) and targeted port checks.

Guarantees: targets are restricted to the detected private LAN, never more than
max_hosts addresses, only the ports from the rule file (no full 65535 scans),
argv without shell, timeouts on every call.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from typing import Dict, Iterable, List, Optional

LOG = logging.getLogger("brion.security.nmap")
MAX_PORTS = 64
MAX_XML = 20 * 1024 * 1024


class ScanError(Exception):
    pass


@dataclass
class Host:
    ip: str
    mac: Optional[str] = None
    vendor: Optional[str] = None
    hostname: Optional[str] = None
    open_ports: List[int] = field(default_factory=list)
    known_to_router: Optional[bool] = None
    is_gateway: bool = False
    is_self: bool = False

    def to_dict(self) -> Dict:
        return asdict(self)


def _nmap_bin() -> str:
    return os.environ.get("BRION_NMAP_BIN", "nmap")


def _run(args: List[str], timeout: int) -> str:
    argv = [_nmap_bin(), *args]
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
    except FileNotFoundError:
        raise ScanError("nmap is not installed") from None
    except subprocess.TimeoutExpired:
        raise ScanError(f"nmap timed out after {timeout}s") from None
    if proc.returncode != 0:
        raise ScanError(f"nmap exited with {proc.returncode}: {proc.stderr.decode(errors='replace')[:200]}")
    if len(proc.stdout) > MAX_XML:
        raise ScanError("nmap output too large")
    return proc.stdout.decode("utf-8", errors="replace")


def _check_network(network: str, max_hosts: int) -> ipaddress.IPv4Network:
    net = ipaddress.ip_network(network, strict=False)
    if net.version != 4 or not net.is_private or net.is_loopback:
        raise ScanError("only private IPv4 LANs may be scanned")
    if net.num_addresses - 2 > max_hosts:
        raise ScanError(f"{net} has more than {max_hosts} hosts")
    return net


def parse_hosts(xml_text: str) -> List[Host]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ScanError(f"unparseable nmap output: {exc}") from None
    hosts = []
    for h in root.findall("host"):
        status = h.find("status")
        if status is not None and status.get("state") != "up":
            continue
        host = Host(ip="")
        for a in h.findall("address"):
            if a.get("addrtype") == "ipv4":
                host.ip = a.get("addr", "")
            elif a.get("addrtype") == "mac":
                host.mac = (a.get("addr") or "").lower() or None
                host.vendor = a.get("vendor") or None
        hn = h.find("hostnames/hostname")
        if hn is not None:
            host.hostname = hn.get("name")
        for p in h.findall("ports/port"):
            st = p.find("state")
            if st is not None and st.get("state") == "open" and p.get("protocol") == "tcp":
                host.open_ports.append(int(p.get("portid")))
        if host.ip:
            hosts.append(host)
    return hosts


def discover(network: str, max_hosts: int = 512, timeout: int = 300) -> List[Host]:
    net = _check_network(network, max_hosts)
    xml_text = _run(["-sn", "-oX", "-", "--max-retries", "2", "--host-timeout", "20s", "-T4", str(net)], timeout)
    return [h for h in parse_hosts(xml_text) if ipaddress.ip_address(h.ip) in net]


def port_scan(ips: Iterable[str], ports: Iterable[int], network: str, max_hosts: int = 512,
              timeout: int = 900) -> Dict[str, List[int]]:
    net = _check_network(network, max_hosts)
    targets = sorted({ip for ip in ips if ipaddress.ip_address(ip) in net}, key=ipaddress.ip_address)
    port_list = sorted({int(p) for p in ports if 0 < int(p) < 65536})
    if not targets or not port_list:
        return {}
    if len(port_list) > MAX_PORTS:
        raise ScanError(f"at most {MAX_PORTS} ports may be checked")
    scan_type = "-sS" if hasattr(os, "geteuid") and os.geteuid() == 0 else "-sT"
    xml_text = _run([scan_type, "-Pn", "-n", "--open", "-p", "T:" + ",".join(map(str, port_list)),
                     "--max-retries", "1", "--host-timeout", "60s", "-T4", "-oX", "-", *targets], timeout)
    return {h.ip: sorted(h.open_ports) for h in parse_hosts(xml_text) if h.ip in targets}
