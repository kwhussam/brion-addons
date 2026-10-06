"""Runtime paths and add-on options. Paths are overridable for tests via environment."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    options_file: Path
    ha_config_dir: Path
    ha_api: str
    supervisor_token: str
    api_host: str
    api_port: int
    device_serial_file: Path
    sys_net: Path
    publish_interval: float
    supervisor_url: str = "http://supervisor"
    ingress_host: str = "172.30.32.1"
    ingress_port: int = 8098
    ingress_peers: frozenset = frozenset({"172.30.32.2"})
    security_url: str = "http://172.30.32.1:8100"
    wg_interface: str = "brionwg0"
    health_interval: float = 300.0

    @property
    def wg_key_file(self) -> Path:
        return self.wg_dir / "private.key"

    @property
    def wg_psk_file(self) -> Path:
        return self.wg_dir / "psk.key"

    @property
    def wg_peer_file(self) -> Path:
        return self.wg_dir / "peer.json"

    @property
    def backup_file(self) -> Path:
        return self.secrets_dir / "backup.json"     # matches facts pattern "backup*"

    @property
    def activation_file(self) -> Path:
        return self.brion_dir / "activation.json"   # non-secret: activation id, heartbeat target

    @property
    def brion_dir(self) -> Path:
        return self.data_dir / "brion"

    @property
    def db_path(self) -> Path:
        return self.brion_dir / "brion.db"

    @property
    def secrets_dir(self) -> Path:
        return self.brion_dir / "secrets"

    @property
    def wg_dir(self) -> Path:
        return self.brion_dir / "wg"

    def options(self) -> Dict[str, Any]:
        """Re-read on every call: option changes apply without code reload."""
        try:
            with open(self.options_file, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return {}


def load() -> Settings:
    env = os.environ
    data_dir = Path(env.get("BRION_DATA_DIR", "/data"))
    return Settings(
        data_dir=data_dir,
        options_file=Path(env.get("BRION_OPTIONS_FILE", str(data_dir / "options.json"))),
        ha_config_dir=Path(env.get("BRION_HA_CONFIG_DIR", "/homeassistant")),
        ha_api=env.get("BRION_HA_API", "http://supervisor/core/api").rstrip("/"),
        supervisor_token=env.get("SUPERVISOR_TOKEN", ""),
        api_host=env.get("BRION_API_HOST", "0.0.0.0"),
        api_port=int(env.get("BRION_API_PORT", "8099")),
        device_serial_file=Path(env.get("BRION_DEVICE_SERIAL_FILE", "/proc/device-tree/serial-number")),
        sys_net=Path(env.get("BRION_SYS_NET", "/sys/class/net")),
        publish_interval=float(env.get("BRION_PUBLISH_INTERVAL", "30")),
        supervisor_url=env.get("BRION_SUPERVISOR_URL", "http://supervisor"),
        ingress_host=env.get("BRION_INGRESS_HOST", "172.30.32.1"),
        ingress_port=int(env.get("BRION_INGRESS_PORT", "8098")),
        ingress_peers=frozenset(p for p in env.get("BRION_INGRESS_PEERS", "172.30.32.2").split(",") if p),
        security_url=env.get("BRION_SECURITY_URL", "http://172.30.32.1:8100").rstrip("/"),
        wg_interface=env.get("BRION_WG_INTERFACE", "brionwg0"),
        health_interval=float(env.get("BRION_HEALTH_INTERVAL", "300")),
    )
