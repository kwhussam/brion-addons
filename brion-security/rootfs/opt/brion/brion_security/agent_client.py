"""Client for the Brion Agent internal API (authenticated with this add-on's SUPERVISOR_TOKEN)."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Dict, Optional


class AgentError(Exception):
    def __init__(self, status: int, code: str, message: str = "") -> None:
        super().__init__(f"{status} {code}: {message}")
        self.status, self.code, self.message = status, code, message


class AgentClient:
    def __init__(self, base_url: str, token: str, timeout: float = 10.0) -> None:
        self.base, self.token, self.timeout = base_url.rstrip("/"), token, timeout

    def _call(self, method: str, path: str, body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method, headers={
            "Authorization": f"Bearer {self.token}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as exc:
            try:
                err = json.loads(exc.read() or b"{}")
            except ValueError:
                err = {}
            raise AgentError(exc.code, str(err.get("error", "error")), str(err.get("message", ""))[:300]) from None
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise AgentError(503, "agent_unreachable", type(exc).__name__) from None

    def status(self) -> Dict[str, Any]:
        return self._call("GET", "/v1/internal/status")

    def scan_start(self) -> Dict[str, Any]:
        return self._call("POST", "/v1/internal/scan/start", {})

    def scan_result(self, **payload: Any) -> Dict[str, Any]:
        return self._call("POST", "/v1/internal/scan/result", payload)

    def scan_abort(self, scan_id: str, reason: str) -> Dict[str, Any]:
        return self._call("POST", "/v1/internal/scan/abort", {"scan_id": scan_id, "reason": reason})

    def rescan(self, user: str, reason: str) -> Dict[str, Any]:
        return self._call("POST", "/v1/internal/rescan", {"user": user, "reason": reason})
