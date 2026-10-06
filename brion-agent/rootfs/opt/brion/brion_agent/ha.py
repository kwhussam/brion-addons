"""Minimal Home Assistant Core API client (via Supervisor proxy, SUPERVISOR_TOKEN)."""
from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

LOG = logging.getLogger("brion.ha")


class HAUnavailable(Exception):
    pass


class HAClient:
    def __init__(self, base_url: str, token: str, timeout: float = 10.0) -> None:
        self.base = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _req(self, method: str, path: str, body: Optional[Dict[str, Any]] = None) -> Any:
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method, headers={
            "Authorization": f"Bearer {self.token}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise HAUnavailable(f"HA API {method} {path}: HTTP {exc.code}") from None
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise HAUnavailable(f"HA API {method} {path}: {exc}") from None

    def get_state(self, entity_id: str) -> Optional[Dict[str, Any]]:
        return self._req("GET", f"/states/{entity_id}")

    def set_state(self, entity_id: str, state: str, attributes: Dict[str, Any]) -> None:
        self._req("POST", f"/states/{entity_id}", {"state": state, "attributes": attributes})

    def call_service(self, domain: str, service: str, data: Dict[str, Any]) -> None:
        self._req("POST", f"/services/{domain}/{service}", data)
