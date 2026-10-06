"""Everything that leaves the Raspberry Pi goes through this module.

* Activation API: installation_id, one-time activation token, WireGuard PUBLIC key,
  security status + timestamp, agent version. Never the private key.
* Heartbeat: installation_id, status, timestamp - nothing else.
* Security add-on (local): only status + timestamp are taken over.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from . import __version__
from .wireguard import PeerConfig, WireGuardError, valid_key

LOG = logging.getLogger("brion.outbound")
MAX_RESPONSE = 64 * 1024
ACTIVATION_FIELDS = ("installation_id", "activation_token", "wireguard_public_key", "security", "agent_version")
HEARTBEAT_FIELDS = ("installation_id", "status", "timestamp")
SECURITY_STATUSES = ("PASSED", "CONDITIONAL", "FAILED")


class OutboundError(Exception):
    def __init__(self, code: str, message: str = "", status: int = 0) -> None:
        super().__init__(f"{code}: {message}")
        self.code, self.message, self.status = code, message, status


def _https_only(url: str, allow_http_private: bool = False) -> None:
    p = urllib.parse.urlparse(url)
    if p.scheme == "https" and p.hostname:
        return
    if allow_http_private and p.scheme == "http" and p.hostname:
        try:
            if ipaddress.ip_address(p.hostname).is_private:
                return
        except ValueError:
            pass
    raise OutboundError("insecure_url", f"{p.scheme}://{p.hostname} not allowed")


def _post_json(url: str, body: Dict[str, Any], ca_file: Optional[str], timeout: float,
               token: Optional[str] = None) -> Dict[str, Any]:
    ctx = ssl.create_default_context(cafile=ca_file or None) if url.startswith("https") else None
    headers = {"Content-Type": "application/json", "User-Agent": f"BrionAgent/{__version__}"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            raw = r.read(MAX_RESPONSE + 1)
    except urllib.error.HTTPError as exc:
        code = {400: "bad_request", 401: "token_rejected", 403: "token_rejected", 404: "unknown_installation",
                409: "conflict", 410: "token_used"}.get(exc.code, "server_error")
        raise OutboundError(code, f"HTTP {exc.code}", exc.code) from None
    except (urllib.error.URLError, OSError, ssl.SSLError) as exc:
        raise OutboundError("unreachable", type(exc).__name__) from None
    if len(raw) > MAX_RESPONSE:
        raise OutboundError("response_too_large")
    try:
        data = json.loads(raw or b"{}")
    except ValueError:
        raise OutboundError("invalid_response", "no JSON") from None
    if not isinstance(data, dict):
        raise OutboundError("invalid_response", "not an object")
    return data


def activation_request(installation_id: str, token: str, public_key: str, security_status: str,
                       security_timestamp: str) -> Dict[str, Any]:
    if not valid_key(public_key):
        raise OutboundError("invalid_public_key")
    body = {"installation_id": installation_id, "activation_token": token, "wireguard_public_key": public_key,
            "security": {"status": security_status, "timestamp": security_timestamp},
            "agent_version": __version__}
    assert tuple(body) == ACTIVATION_FIELDS
    return body


def parse_activation_response(data: Dict[str, Any]) -> Dict[str, Any]:
    """Strict validation. Returns {peer: PeerConfig, psk, backup, heartbeat, activation_id}."""
    try:
        wg = data["wireguard"]
        peer = PeerConfig.from_activation(wg)
    except (KeyError, TypeError, WireGuardError) as exc:
        raise OutboundError("invalid_response", f"wireguard: {exc}") from None
    psk = wg.get("preshared_key")
    if psk is not None and not valid_key(str(psk)):
        raise OutboundError("invalid_response", "preshared_key")
    backup = data.get("backup") or {}
    if not isinstance(backup, dict) or backup.get("type") not in ("webdav", "nextcloud"):
        raise OutboundError("invalid_response", "backup.type")
    for k in ("url", "username", "password"):
        if not isinstance(backup.get(k), str) or not backup.get(k):
            raise OutboundError("invalid_response", f"backup.{k}")
    _https_only(backup["url"])
    hb = data.get("heartbeat") or {}
    try:
        hb_url, hb_interval = str(hb["url"]), int(hb.get("interval", 300))
    except (KeyError, ValueError, TypeError):
        raise OutboundError("invalid_response", "heartbeat") from None
    _https_only(hb_url, allow_http_private=True)   # heartbeat may target the hub over the tunnel
    if not 60 <= hb_interval <= 3600:
        raise OutboundError("invalid_response", "heartbeat.interval")
    act_id = str(data.get("activation_id", ""))
    if not re.match(r"^[A-Za-z0-9._-]{1,64}$", act_id):
        raise OutboundError("invalid_response", "activation_id")
    return {"peer": peer, "psk": psk, "activation_id": act_id,
            "backup": {k: backup[k] for k in ("type", "url", "username", "password")},
            "heartbeat": {"url": hb_url, "interval": hb_interval}}


def activate(url: str, body: Dict[str, Any], ca_file: Optional[str], timeout: float = 30.0) -> Dict[str, Any]:
    _https_only(url)
    if tuple(body) != ACTIVATION_FIELDS or set(body["security"]) != {"status", "timestamp"}:
        raise OutboundError("invalid_request")
    return parse_activation_response(_post_json(url, body, ca_file, timeout))


def heartbeat_payload(installation_id: str, status: str, when: Optional[datetime] = None) -> Dict[str, str]:
    when = when or datetime.now(timezone.utc)
    payload = {"installation_id": installation_id, "status": status,
               "timestamp": when.isoformat(timespec="seconds")}
    assert tuple(payload) == HEARTBEAT_FIELDS
    return payload


def send_heartbeat(url: str, payload: Dict[str, str], ca_file: Optional[str], timeout: float = 10.0) -> None:
    if tuple(payload) != HEARTBEAT_FIELDS:
        raise OutboundError("invalid_request")
    _https_only(url, allow_http_private=True)
    _post_json(url, payload, ca_file, timeout)


def security_summary(security_url: str, token: str, timeout: float = 5.0) -> Dict[str, Optional[str]]:
    """Status + timestamp from the local Brion Security add-on. Detailed scan data is never taken over."""
    req = urllib.request.Request(f"{security_url}/internal/v1/summary", headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read(4096) or b"{}")
    except urllib.error.HTTPError as exc:
        raise OutboundError("security_refused", f"HTTP {exc.code}", exc.code) from None
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise OutboundError("security_unreachable", type(exc).__name__) from None
    status, ts = data.get("status"), data.get("timestamp")
    if status is not None and status not in SECURITY_STATUSES:
        raise OutboundError("invalid_response", "status")
    if ts is not None:
        try:
            datetime.fromisoformat(str(ts))
        except ValueError:
            raise OutboundError("invalid_response", "timestamp") from None
    return {"status": status, "timestamp": ts}
