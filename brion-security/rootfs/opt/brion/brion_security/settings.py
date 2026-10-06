"""Runtime configuration. Add-on options from /data/options.json, paths overridable for tests."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, FrozenSet


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    rules_file: Path
    agent_url: str
    supervisor_url: str
    supervisor_token: str
    bind_host: str
    port: int
    allowed_peers: FrozenSet[str]
    router_host: str
    retain_reports: int
    log_level: str
    device_model_file: Path
    proc_root: Path
    resolv_conf: Path

    @property
    def security_dir(self) -> Path:
        return self.data_dir / "security"   # backup_exclude: security/*

    @property
    def db_path(self) -> Path:
        return self.security_dir / "security.db"

    @property
    def reports_dir(self) -> Path:
        return self.security_dir / "reports"


def _options(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


def load() -> Settings:
    env = os.environ
    data_dir = Path(env.get("BRION_SEC_DATA_DIR", "/data"))
    opts = _options(Path(env.get("BRION_SEC_OPTIONS_FILE", str(data_dir / "options.json"))))
    return Settings(
        data_dir=data_dir,
        rules_file=Path(env.get("BRION_SEC_RULES", "/opt/brion/config/security_rules.yaml")),
        agent_url=env.get("BRION_AGENT_URL", opts.get("agent_url", "http://127.0.0.1:8099")).rstrip("/"),
        supervisor_url=env.get("BRION_SUPERVISOR_URL", "http://supervisor").rstrip("/"),
        supervisor_token=env.get("SUPERVISOR_TOKEN", ""),
        bind_host=env.get("BRION_SEC_BIND", opts.get("bind_host", "172.30.32.1")),
        port=int(env.get("BRION_SEC_PORT", "8100")),
        allowed_peers=frozenset(p for p in env.get("BRION_INGRESS_PEERS", "172.30.32.2").split(",") if p),
        router_host=str(opts.get("router_host") or ""),
        retain_reports=int(opts.get("retain_reports", 5)),
        log_level=str(opts.get("log_level", "info")),
        device_model_file=Path(env.get("BRION_DEVICE_MODEL_FILE", "/proc/device-tree/model")),
        proc_root=Path(env.get("BRION_PROC_ROOT", "/proc")),
        resolv_conf=Path(env.get("BRION_RESOLV_CONF", "/etc/resolv.conf")),
    )
