"""Logging setup with a redaction filter as a safety net (the code never logs secrets)."""
from __future__ import annotations

import logging
import re
import sys

_PATTERNS = (
    (re.compile(r'("?(?:router_)?password"?\s*[:=]\s*)("[^"]*"|\S+)', re.I), r"\1***"),
    (re.compile(r"(Authorization:\s*\w+\s+)\S+", re.I), r"\1***"),
    (re.compile(r'(response=")[0-9a-f]{32}(")', re.I), r"\1***\2"),
    (re.compile(r"(Bearer\s+)[A-Za-z0-9._\-]{8,}"), r"\1***"),
)


def redact(text: str) -> str:
    for rx, repl in _PATTERNS:
        text = rx.sub(repl, text)
    return text


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:  # noqa: BLE001
            return True
        record.msg, record.args = redact(msg), ()
        return True


def setup(level: str = "info") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    handler.addFilter(RedactingFilter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        lg = logging.getLogger(name)
        lg.handlers[:] = []
        lg.propagate = True
    logging.getLogger("uvicorn.access").disabled = True  # no URLs/headers in logs
