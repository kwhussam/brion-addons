"""Verify that a local caller is the Brion Agent add-on (token checked by the Supervisor)."""
from __future__ import annotations

import hashlib
import json
import threading
import time
import urllib.error
import urllib.request
from typing import Dict, Optional, Tuple

ALLOWED_SUFFIX = "_brion_agent"


class AgentVerifier:
    def __init__(self, supervisor_url: str, timeout: float = 5.0) -> None:
        self.url, self.timeout = supervisor_url.rstrip("/"), timeout
        self._cache: Dict[str, Tuple[float, bool]] = {}
        self._lock = threading.Lock()

    def is_agent(self, token: str) -> bool:
        if not token or len(token) > 512:
            return False
        key, now = hashlib.sha256(token.encode()).hexdigest(), time.monotonic()
        with self._lock:
            hit = self._cache.get(key)
            if hit and hit[0] > now:
                return hit[1]
        ok = self._ask(token)
        with self._lock:
            self._cache[key] = (now + (300.0 if ok else 10.0), ok)
        return ok

    def _ask(self, token: str) -> bool:
        req = urllib.request.Request(f"{self.url}/addons/self/info", headers={"Authorization": f"Bearer {token}"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                slug = str((json.loads(r.read() or b"{}").get("data") or {}).get("slug", ""))
        except (urllib.error.URLError, OSError, ValueError):
            return False
        return slug.endswith(ALLOWED_SUFFIX)
