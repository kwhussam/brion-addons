"""Heuristic secret detection for anything that gets persisted or reported.

This is a last line of defence, not the primary control: callers must never pass
secrets in the first place. A hit is treated as a hard error (fail closed).
"""
from __future__ import annotations

import re
from typing import Any, List

_PATTERNS = {
    "wireguard_key": re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]="),
    "jwt_or_llat": re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    "pem_block": re.compile(r"-----BEGIN [A-Z ]*(PRIVATE KEY|CERTIFICATE)-----"),
    "age_secret_key": re.compile(r"AGE-SECRET-KEY-1[0-9A-Z]{20,}"),
}
_SENSITIVE_KEY = re.compile(r"(password|passwd|secret|token|private_?key|psk|api_?key|credential)", re.I)


def find_secrets(obj: Any, path: str = "$") -> List[str]:
    """Return JSON paths that look like they contain secret material."""
    hits: List[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{path}.{k}"
            if _SENSITIVE_KEY.search(str(k)) and v not in (None, "", False, [], {}):
                if not isinstance(v, bool):
                    hits.append(p)
                    continue
            hits.extend(find_secrets(v, p))
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            hits.extend(find_secrets(v, f"{path}[{i}]"))
    elif isinstance(obj, str):
        for name, rx in _PATTERNS.items():
            if rx.search(obj):
                hits.append(f"{path} ({name})")
    return hits
