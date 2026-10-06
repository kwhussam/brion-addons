"""Internal API for other Brion add-ons (currently only the Security add-on).

Caller authentication without a shared secret: the caller presents its own
SUPERVISOR_TOKEN; the agent asks the Supervisor who that token belongs to
(GET /addons/self/info with the caller's token) and only accepts add-ons whose slug
ends with an allowed suffix. Results are cached briefly (by token hash only).
"""
from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
import urllib.error
import urllib.request
from typing import Dict, Optional, Tuple

LOG = logging.getLogger("brion.internal")
ALLOWED_CALLERS = {"_brion_security": "system:brion-security"}
CACHE_TTL = 300.0


class CallerVerifier:
    def __init__(self, supervisor_url: str, timeout: float = 5.0) -> None:
        self.url = supervisor_url.rstrip("/")
        self.timeout = timeout
        self._cache: Dict[str, Tuple[float, Optional[str]]] = {}
        self._lock = threading.Lock()

    def actor_for(self, token: str) -> Optional[str]:
        """Return the Brion actor for a valid caller token, else None."""
        if not token or len(token) > 512:
            return None
        key = hashlib.sha256(token.encode()).hexdigest()
        now = time.monotonic()
        with self._lock:
            hit = self._cache.get(key)
            if hit and hit[0] > now:
                return hit[1]
        actor = self._ask_supervisor(token)
        with self._lock:
            # negative results are cached shorter so a restarted add-on is not locked out
            self._cache[key] = (now + (CACHE_TTL if actor else 10.0), actor)
            if len(self._cache) > 256:
                self._cache = {k: v for k, v in self._cache.items() if v[0] > now}
        return actor

    def _ask_supervisor(self, token: str) -> Optional[str]:
        req = urllib.request.Request(f"{self.url}/addons/self/info",
                                     headers={"Authorization": f"Bearer {token}"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read() or b"{}")
        except (urllib.error.URLError, OSError, ValueError) as exc:
            LOG.warning("caller verification failed: %s", type(exc).__name__)
            return None
        slug = str((data.get("data") or {}).get("slug", ""))
        for suffix, actor in ALLOWED_CALLERS.items():
            if slug.endswith(suffix):
                return actor
        LOG.warning("internal API call from non-allowed add-on %s", slug or "<unknown>")
        return None
