"""Small JSON stores in /data/brion (activation token, golden deployment record)."""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


def fingerprint(installation_id: str, token_sha256: str) -> str:
    """Public, non-secret pairing code (shown on QR label and in the Security UI)."""
    return hashlib.sha256(f"{installation_id}:{token_sha256}".encode()).hexdigest()[:8]


def _write_private(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh, sort_keys=True)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def _read(path: Path) -> Optional[Dict[str, Any]]:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


class ActivationTokenStore:
    def __init__(self, secrets_dir: Path) -> None:
        self.path = secrets_dir / "activation_token.json"

    def save(self, installation_id: str, token: str, expires_at: datetime) -> Dict[str, Any]:
        sha = hashlib.sha256(token.encode()).hexdigest()
        _write_private(self.path, {"installation_id": installation_id, "token": token,
                                   "token_sha256": sha, "expires_at": expires_at.isoformat()})
        return self.public()

    def token(self) -> str:
        """Plaintext token - only for the activation request, never logged or returned by the API."""
        d = _read(self.path)
        if not d or not d.get("token"):
            raise ValueError("no activation token")
        return d["token"]

    def consume(self) -> None:
        """One-time token: removed after a successful activation."""
        if self.path.exists():
            size = self.path.stat().st_size
            with open(self.path, "r+b") as fh:
                fh.write(b"\0" * size)
            self.path.unlink()

    def token_sha256(self) -> Optional[str]:
        d = _read(self.path)
        return d.get("token_sha256") if d else None

    def public(self) -> Dict[str, Any]:
        d = _read(self.path)
        if not d:
            return {"present": False, "fingerprint": None, "expires_at": None, "expired": None}
        exp = datetime.fromisoformat(d["expires_at"])
        return {"present": True, "fingerprint": fingerprint(d["installation_id"], d["token_sha256"]),
                "expires_at": d["expires_at"], "expired": exp <= datetime.now(timezone.utc)}


class GoldenRecord:
    def __init__(self, brion_dir: Path) -> None:
        self.path = brion_dir / "golden.json"

    def get(self) -> Optional[Dict[str, Any]]:
        return _read(self.path)

    def set(self, data: Dict[str, Any]) -> None:
        _write_private(self.path, data)
