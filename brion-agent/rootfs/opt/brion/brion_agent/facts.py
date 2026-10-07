"""Observe the real device: keys, tunnels, credentials, master switch, config hygiene."""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from brion_core import SecurityFacts
from brion_core.golden import FORBIDDEN_INTEGRATIONS

from .ha import HAClient, HAUnavailable
from .settings import Settings

LOG = logging.getLogger("brion.facts")
MASTER = "input_boolean.brion_master_enable"
_SECRET_KEY_LINE = re.compile(r"^[^#\s][^:]*:", re.M)


def _nonempty_files(directory: Path, pattern: str = "*") -> int:
    if not directory.is_dir():
        return 0
    return sum(1 for p in directory.glob(pattern) if p.is_file() and p.stat().st_size > 0)


def wireguard_interfaces(sys_net: Path) -> list:
    found = []
    if sys_net.is_dir():
        for uevent in sys_net.glob("*/uevent"):
            try:
                if "DEVTYPE=wireguard" in uevent.read_text():
                    found.append(uevent.parent.name)
            except OSError:
                continue
    return sorted(found)


def master_enable_on(ha: HAClient) -> Optional[bool]:
    """True/False, or None if HA is unreachable (callers treat None as ON: fail closed)."""
    try:
        st = ha.get_state(MASTER)
    except HAUnavailable as exc:
        LOG.warning("master switch state unknown: %s", exc)
        return None
    if st is None:  # entity not defined (yet): nothing can be enabled through it
        return False
    return st.get("state") != "off"


def inspect_config(ha_config_dir: Path) -> Dict[str, Any]:
    """Names/counts only - never values."""
    out: Dict[str, Any] = {"secrets_yaml_keys": 0, "forbidden_integrations": [], "wireguard_config_files": 0}
    sec = ha_config_dir / "secrets.yaml"
    if sec.is_file():
        out["secrets_yaml_keys"] = len(_SECRET_KEY_LINE.findall(sec.read_text(errors="replace")))
    entries = ha_config_dir / ".storage" / "core.config_entries"
    if entries.is_file():
        try:
            data = json.loads(entries.read_text())
            domains = {e.get("domain") for e in data.get("data", {}).get("entries", [])}
            out["forbidden_integrations"] = sorted(d for d in domains if d in FORBIDDEN_INTEGRATIONS)
        except (OSError, ValueError):
            out["forbidden_integrations"] = ["<unreadable core.config_entries>"]
    count = 0
    if ha_config_dir.is_dir():
        for p in ha_config_dir.rglob("*.conf"):
            if ".storage" in p.parts:
                continue
            try:
                if "[Interface]" in p.read_text(errors="replace"):
                    count += 1
            except OSError:
                continue
    out["wireguard_config_files"] = count
    return out


def collect(settings: Settings, ha: HAClient) -> Tuple[SecurityFacts, Dict[str, Any]]:
    master = master_enable_on(ha)
    wg_ifaces = wireguard_interfaces(settings.sys_net)
    facts = SecurityFacts(
        wg_private_key_present=_nonempty_files(settings.wg_dir) > 0,
        tunnel_active=bool(wg_ifaces),
        backup_credentials_present=_nonempty_files(settings.secrets_dir, "backup*") > 0,
        cloud_credentials_present=_nonempty_files(settings.secrets_dir, "cloud*") > 0,
        master_enable_on=True if master is None else master,
    )
    inspection = inspect_config(settings.ha_config_dir)
    inspection["wireguard_interfaces"] = wg_ifaces
    inspection["ha_reachable"] = master is not None
    return facts, inspection


_SERIAL_RE = re.compile(r"^[0-9a-f]{8,32}$")
_CPUINFO_SERIAL_RE = re.compile(r"^Serial\s*:\s*([0-9A-Fa-f]+)\s*$", re.M)


def _valid_serial(raw: str) -> Optional[str]:
    raw = raw.strip("\x00\n ").lower()
    return raw if _SERIAL_RE.match(raw) and raw.strip("0") else None


def hardware_serial(settings: Settings) -> Optional[str]:
    """Raspberry-Pi serial number.

    1. Device tree (/proc/device-tree/serial-number) - in HAOS add-on containers usually
       not visible, because Docker masks /sys/firmware.
    2. /proc/cpuinfo "Serial : 10000000xxxxxxxx" - readable inside the container on a Pi.
    """
    try:
        serial = _valid_serial(settings.device_serial_file.read_bytes().decode(errors="replace"))
        if serial:
            return serial
    except OSError:
        pass
    try:
        m = _CPUINFO_SERIAL_RE.search(settings.cpuinfo_file.read_text(errors="replace"))
    except OSError:
        return None
    return _valid_serial(m.group(1)) if m else None
