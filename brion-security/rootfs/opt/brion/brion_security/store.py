"""Local scan store (SQLite in /data/security, excluded from HA backups)."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id              TEXT PRIMARY KEY,
    agent_scan_id   TEXT,
    operator        TEXT,
    started_at      TEXT NOT NULL,
    finished_at     TEXT,
    state           TEXT NOT NULL CHECK (state IN ('running','completed','error','interrupted')),
    phase           TEXT,
    progress        INTEGER NOT NULL DEFAULT 0,
    overall         TEXT CHECK (overall IS NULL OR overall IN ('PASSED','CONDITIONAL','FAILED')),
    counts_json     TEXT,
    findings_json   TEXT,
    data_json       TEXT,
    report_dir      TEXT,
    report_sha256   TEXT,
    agent_state     TEXT,
    error           TEXT,
    rules_version   INTEGER,
    scanner_version TEXT
);
CREATE INDEX IF NOT EXISTS scans_started ON scans (started_at);
"""
_FIELDS = {"agent_scan_id", "finished_at", "state", "phase", "progress", "overall", "counts_json",
           "findings_json", "data_json", "report_dir", "report_sha256", "agent_state", "error",
           "rules_version", "scanner_version"}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(path.parent, 0o700)
        old = os.umask(0o077)
        try:
            self._conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        finally:
            os.umask(old)
        os.chmod(path, 0o600)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("PRAGMA secure_delete=ON")
        self._conn.executescript(SCHEMA)

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            self._conn.execute("COMMIT")

    def create(self, scan_id: str, operator: Optional[str], scanner_version: str) -> None:
        with self._tx() as c:
            c.execute("INSERT INTO scans (id, operator, started_at, state, phase, progress, scanner_version)"
                      " VALUES (?,?,?,?,?,?,?)", (scan_id, operator, now_iso(), "running", "start", 0, scanner_version))

    def update(self, scan_id: str, **fields: Any) -> None:
        unknown = set(fields) - _FIELDS
        if unknown:
            raise ValueError(f"unknown fields {unknown}")
        for k in ("counts_json", "findings_json", "data_json"):
            if k in fields and not isinstance(fields[k], str):
                fields[k] = json.dumps(fields[k], sort_keys=True)
        cols = ", ".join(f"{k} = ?" for k in fields)
        with self._tx() as c:
            c.execute(f"UPDATE scans SET {cols} WHERE id = ?", (*fields.values(), scan_id))

    def _row(self, row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
        if row is None:
            return None
        d = dict(row)
        for k in ("counts_json", "findings_json", "data_json"):
            d[k[:-5]] = json.loads(d.pop(k)) if d.get(k) else None
        return d

    def get(self, scan_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._row(self._conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone())

    def latest(self, state: Optional[str] = None) -> Optional[Dict[str, Any]]:
        sql = "SELECT * FROM scans" + (" WHERE state = ?" if state else "") + " ORDER BY started_at DESC, rowid DESC LIMIT 1"
        with self._lock:
            return self._row(self._conn.execute(sql, (state,) if state else ()).fetchone())

    def mark_interrupted(self) -> List[Dict[str, Any]]:
        """Called at start-up: scans that were running when the add-on stopped."""
        with self._lock:
            rows = [dict(r) for r in self._conn.execute("SELECT id, agent_scan_id FROM scans WHERE state = 'running'")]
        for r in rows:
            self.update(r["id"], state="interrupted", finished_at=now_iso(), error="add-on restarted during scan")
        return rows

    def prune(self, keep: int) -> List[str]:
        with self._lock:
            old = [r["report_dir"] for r in self._conn.execute(
                "SELECT report_dir FROM scans WHERE report_dir IS NOT NULL ORDER BY started_at DESC, rowid DESC LIMIT -1 OFFSET ?",
                (keep,))]
            self._conn.execute(
                "DELETE FROM scans WHERE id IN (SELECT id FROM scans ORDER BY started_at DESC, rowid DESC LIMIT -1 OFFSET ?)",
                (keep,))
        return [d for d in old if d]
