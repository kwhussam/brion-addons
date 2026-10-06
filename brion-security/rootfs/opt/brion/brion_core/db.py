"""SQLite persistence: connection setup, transactions, versioned migrations.

Durability choices for power loss on a customer site:
* WAL journal + synchronous=FULL: a committed transition survives a power cut.
* BEGIN IMMEDIATE for every write: one writer at a time, no lost updates.
* CHECK constraints and triggers duplicate the Python invariants (defence in depth).
"""
from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, List

from .errors import IntegrityError

_STATES = "'FACTORY','QUARANTINE','SCANNING','FAILED','CONDITIONAL','PASSED','PROVISIONING','ACTIVE','MAINTENANCE','DISABLED'"

MIGRATIONS = {
    1: f"""
CREATE TABLE installation (
    id                     INTEGER PRIMARY KEY CHECK (id = 1),
    installation_id        TEXT UNIQUE CHECK (installation_id IS NULL OR
                               installation_id GLOB 'BR-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9]'),
    serial_number          TEXT CHECK (serial_number IS NULL OR
                               serial_number GLOB 'PI-[0-9][0-9][0-9][0-9][0-9]' OR
                               (length(serial_number) BETWEEN 8 AND 16 AND serial_number NOT GLOB '*[^0-9a-f]*')),
    state                  TEXT NOT NULL CHECK (state IN ({_STATES})),
    security_status        TEXT NOT NULL DEFAULT 'UNKNOWN'
                               CHECK (security_status IN ('UNKNOWN','PASS','CONDITIONAL','CONDITIONAL_ACCEPTED','FAIL')),
    activated              INTEGER NOT NULL DEFAULT 0 CHECK (activated IN (0, 1)),
    vpn_provisioned        INTEGER NOT NULL DEFAULT 0 CHECK (vpn_provisioned IN (0, 1)),
    last_security_check    TEXT,
    backup_status          TEXT NOT NULL DEFAULT 'NOT_CONFIGURED'
                               CHECK (backup_status IN ('NOT_CONFIGURED','CONFIGURED','OK','FAILED')),
    configuration_version  TEXT,
    master_enable_expected INTEGER NOT NULL DEFAULT 0,
    row_version            INTEGER NOT NULL DEFAULT 1,
    created_at             TEXT NOT NULL,
    updated_at             TEXT NOT NULL,
    CHECK (master_enable_expected = (state = 'ACTIVE')),
    CHECK (activated = 0 OR state IN ('PROVISIONING','ACTIVE','MAINTENANCE','DISABLED')),
    CHECK (vpn_provisioned = 0 OR state IN ('PROVISIONING','ACTIVE','MAINTENANCE')),
    CHECK (backup_status = 'NOT_CONFIGURED' OR state IN ('PROVISIONING','ACTIVE','MAINTENANCE')),
    CHECK (state = 'FACTORY' OR (installation_id IS NOT NULL AND serial_number IS NOT NULL))
);

CREATE TRIGGER installation_identity_immutable
BEFORE UPDATE OF installation_id, serial_number ON installation
WHEN (OLD.installation_id IS NOT NULL AND NEW.installation_id IS NOT OLD.installation_id)
  OR (OLD.serial_number  IS NOT NULL AND NEW.serial_number  IS NOT OLD.serial_number)
BEGIN
    SELECT RAISE(ABORT, 'installation identity is immutable');
END;

CREATE TRIGGER installation_no_delete
BEFORE DELETE ON installation
BEGIN
    SELECT RAISE(ABORT, 'installation row cannot be deleted');
END;

CREATE TABLE state_transitions (
    seq             INTEGER PRIMARY KEY AUTOINCREMENT,
    installation_id TEXT,
    from_state      TEXT,
    to_state        TEXT NOT NULL CHECK (to_state IN ({_STATES})),
    trigger         TEXT NOT NULL,
    actor           TEXT NOT NULL,
    reason          TEXT,
    facts_json      TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    prev_hash       TEXT NOT NULL CHECK (length(prev_hash) = 64),
    hash            TEXT NOT NULL UNIQUE CHECK (length(hash) = 64)
);

CREATE TRIGGER state_transitions_append_only_u
BEFORE UPDATE ON state_transitions
BEGIN
    SELECT RAISE(ABORT, 'state_transitions is append-only');
END;

CREATE TRIGGER state_transitions_append_only_d
BEFORE DELETE ON state_transitions
BEGIN
    SELECT RAISE(ABORT, 'state_transitions is append-only');
END;

CREATE TABLE security_scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at      TEXT NOT NULL,
    finished_at     TEXT NOT NULL,
    result          TEXT NOT NULL CHECK (result IN ('PASS','CONDITIONAL','FAIL')),
    scanner_version TEXT NOT NULL,
    report_sha256   TEXT NOT NULL CHECK (length(report_sha256) = 64 AND report_sha256 NOT GLOB '*[^0-9a-f]*'),
    summary_json    TEXT NOT NULL
);

CREATE TRIGGER security_scans_append_only_u
BEFORE UPDATE ON security_scans
BEGIN
    SELECT RAISE(ABORT, 'security_scans is append-only');
END;

CREATE INDEX security_scans_finished ON security_scans (finished_at);
""",
}

MIGRATIONS[2] = """
-- BRION-SEC-005: scan results must belong to a scan run that was started by an
-- allowed scanner actor (no replay of old/foreign reports).
CREATE TABLE scan_sessions (
    scan_id        TEXT PRIMARY KEY CHECK (length(scan_id) = 32 AND scan_id NOT GLOB '*[^0-9a-f]*'),
    actor          TEXT NOT NULL,
    state_at_start TEXT NOT NULL,
    started_at     TEXT NOT NULL,
    closed_at      TEXT,
    outcome        TEXT CHECK (outcome IS NULL OR outcome IN ('PASS','CONDITIONAL','FAIL','ABORTED'))
);

CREATE TRIGGER scan_sessions_no_delete
BEFORE DELETE ON scan_sessions
BEGIN
    SELECT RAISE(ABORT, 'scan_sessions is append-only');
END;

CREATE TRIGGER scan_sessions_close_once
BEFORE UPDATE ON scan_sessions
WHEN OLD.closed_at IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'scan session already closed');
END;

ALTER TABLE security_scans ADD COLUMN scan_id TEXT REFERENCES scan_sessions(scan_id);
CREATE UNIQUE INDEX security_scans_scan_id ON security_scans (scan_id);

-- BRION-DB-003
CREATE TRIGGER security_scans_append_only_d
BEFORE DELETE ON security_scans
BEGIN
    SELECT RAISE(ABORT, 'security_scans is append-only');
END;
"""

MIGRATIONS[3] = """
-- Operational audit log of the Brion Agent (no secrets, hash-chained, append-only)
CREATE TABLE audit_events (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    at           TEXT NOT NULL,
    actor        TEXT NOT NULL,
    action       TEXT NOT NULL,
    outcome      TEXT NOT NULL CHECK (outcome IN ('ok','denied','failed','info')),
    state        TEXT,
    details_json TEXT NOT NULL,
    prev_hash    TEXT NOT NULL CHECK (length(prev_hash) = 64),
    hash         TEXT NOT NULL UNIQUE CHECK (length(hash) = 64)
);

CREATE TRIGGER audit_events_append_only_u
BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;

CREATE TRIGGER audit_events_append_only_d
BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;
"""

SCHEMA_VERSION = max(MIGRATIONS)


def _split_statements(script: str) -> List[str]:
    """Split a script into complete statements (trigger bodies contain ';')."""
    statements, buf = [], ""
    for line in script.splitlines(keepends=True):
        buf += line
        if sqlite3.complete_statement(buf):
            if buf.strip():
                statements.append(buf.strip())
            buf = ""
    if buf.strip():
        raise IntegrityError("incomplete SQL statement in migration")
    return statements


def connect(path: "os.PathLike[str] | str") -> sqlite3.Connection:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    old_umask = os.umask(0o077)  # db, -wal and -shm files are owner-only
    try:
        conn = sqlite3.connect(str(p), timeout=5.0, isolation_level=None)
    finally:
        os.umask(old_umask)
    conn.row_factory = sqlite3.Row
    try:
        return _prepare(conn)
    except sqlite3.DatabaseError as exc:          # corrupt/foreign file -> controlled, fail-closed error
        conn.close()
        raise IntegrityError(f"database unusable: {exc}") from None


def _prepare(conn: sqlite3.Connection) -> sqlite3.Connection:
    mode = conn.execute("PRAGMA journal_mode=WAL").fetchone()[0]
    if str(mode).lower() != "wal":
        conn.close()
        raise IntegrityError(f"could not enable WAL journal (got {mode})")
    conn.execute("PRAGMA synchronous=FULL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA secure_delete=ON")
    migrate(conn)
    return conn


@contextmanager
def immediate(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


def schema_version(conn: sqlite3.Connection) -> int:
    return int(conn.execute("PRAGMA user_version").fetchone()[0])


def migrate(conn: sqlite3.Connection) -> int:
    current = schema_version(conn)
    if current > SCHEMA_VERSION:
        raise IntegrityError(
            f"database schema v{current} is newer than this code (v{SCHEMA_VERSION}); refusing to run")
    for version in range(current + 1, SCHEMA_VERSION + 1):
        with immediate(conn):
            for stmt in _split_statements(MIGRATIONS[version]):
                conn.execute(stmt)
            conn.execute(f"PRAGMA user_version = {int(version)}")
    ok = conn.execute("PRAGMA quick_check").fetchone()[0]
    if ok != "ok":
        raise IntegrityError(f"sqlite quick_check failed: {ok}")
    return schema_version(conn)
