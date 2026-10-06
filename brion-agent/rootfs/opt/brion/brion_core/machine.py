"""Persistent lifecycle state machine backed by SQLite.

Single writer: the Brion Agent add-on owns ``/data/brion/brion.db``. Other
components (Security add-on, Ansible) change state only through the agent's API,
which wraps this class (phase 7).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from dataclasses import dataclass, fields, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

from . import db
from .errors import (
    ConcurrencyError,
    GuardViolationError,
    IntegrityError,
    InvalidTransitionError,
    NotInitializedError,
    ValidationError,
)
from .ids import normalize_serial, validate_installation_id
from .policy import LOCKED, POLICIES, ReconcilePlan, SecurityFacts, build_plan, policy_violations
from .redaction import find_secrets
from .states import CREDENTIALED_STATES, BackupStatus, SecurityStatus, State
from .transitions import GuardInput, Rule, find_rule, rules_from

DEFAULT_DB_PATH = "/data/brion/brion.db"
DEFAULT_SCAN_MAX_AGE = timedelta(hours=24)
DEFAULT_CLOCK_SKEW = timedelta(minutes=5)
GENESIS_HASH = "0" * 64

_ACTOR_RE = re.compile(r"^(system|user|ansible):[A-Za-z0-9._@-]{1,64}$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9._+-]{1,64}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_REASON_LEN = 500
DEFAULT_SCANNER_ACTORS = frozenset({"system:brion-security"})
DEFAULT_SCAN_TIMEOUT = timedelta(hours=1)
SCAN_START_STATES = (State.QUARANTINE, State.ACTIVE, State.MAINTENANCE)
MAX_SUMMARY_BYTES = 64 * 1024


def default_db_path() -> str:
    return os.environ.get("BRION_DB", DEFAULT_DB_PATH)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _ts(dt: Optional[datetime]) -> Optional[str]:
    return None if dt is None else dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def _parse_ts(value: Optional[str]) -> Optional[datetime]:
    return None if value is None else datetime.fromisoformat(value)


def _validate_actor(actor: str) -> str:
    if not isinstance(actor, str) or not _ACTOR_RE.match(actor):
        raise ValidationError("actor must look like 'system:<name>', 'user:<name>' or 'ansible:<name>'")
    return actor


def _validate_reason(reason: Optional[str]) -> Optional[str]:
    if reason is None:
        return None
    reason = reason.strip()
    if not reason:
        return None
    if len(reason) > MAX_REASON_LEN:
        raise ValidationError(f"reason longer than {MAX_REASON_LEN} characters")
    if find_secrets(reason):
        raise ValidationError("reason looks like it contains secret material")
    return reason


@dataclass(frozen=True)
class InstallationRecord:
    installation_id: Optional[str]
    serial_number: Optional[str]
    state: State
    security_status: SecurityStatus
    activated: bool
    vpn_provisioned: bool
    last_security_check: Optional[datetime]
    backup_status: BackupStatus
    configuration_version: Optional[str]
    master_enable_expected: bool
    row_version: int
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "InstallationRecord":
        return cls(
            installation_id=row["installation_id"],
            serial_number=row["serial_number"],
            state=State(row["state"]),
            security_status=SecurityStatus(row["security_status"]),
            activated=bool(row["activated"]),
            vpn_provisioned=bool(row["vpn_provisioned"]),
            last_security_check=_parse_ts(row["last_security_check"]),
            backup_status=BackupStatus(row["backup_status"]),
            configuration_version=row["configuration_version"],
            master_enable_expected=bool(row["master_enable_expected"]),
            row_version=int(row["row_version"]),
            created_at=_parse_ts(row["created_at"]),
            updated_at=_parse_ts(row["updated_at"]),
        )

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for f in fields(self):
            v = getattr(self, f.name)
            if isinstance(v, datetime):
                v = _ts(v)
            elif hasattr(v, "value"):
                v = v.value
            out[f.name] = v
        return out


def check_invariants(rec: InstallationRecord) -> None:
    """Python mirror of the SQL CHECK constraints (fail before touching the DB)."""
    problems: List[str] = []
    if rec.master_enable_expected != (rec.state is State.ACTIVE):
        problems.append("master_enable_expected must be true exactly in ACTIVE")
    if rec.activated and rec.state not in CREDENTIALED_STATES | {State.DISABLED}:
        problems.append(f"activated not allowed in {rec.state.value}")
    if rec.vpn_provisioned and rec.state not in CREDENTIALED_STATES:
        problems.append(f"vpn_provisioned not allowed in {rec.state.value}")
    if rec.backup_status is not BackupStatus.NOT_CONFIGURED and rec.state not in CREDENTIALED_STATES:
        problems.append(f"backup configuration not allowed in {rec.state.value}")
    if rec.state is not State.FACTORY and not (rec.installation_id and rec.serial_number):
        problems.append("identity required outside FACTORY")
    if problems:
        raise IntegrityError("; ".join(problems))


def _chain_hash(prev_hash: str, payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256((prev_hash + "\n" + canonical).encode("utf-8")).hexdigest()


class StateMachine:
    def __init__(
        self,
        conn: sqlite3.Connection,
        *,
        clock: Optional[Callable[[], datetime]] = None,
        scan_max_age: timedelta = DEFAULT_SCAN_MAX_AGE,
        clock_skew: timedelta = DEFAULT_CLOCK_SKEW,
        scanner_actors: frozenset = DEFAULT_SCANNER_ACTORS,
        scan_timeout: timedelta = DEFAULT_SCAN_TIMEOUT,
    ) -> None:
        self._conn = conn
        self._clock = clock or _utcnow
        self.scan_max_age = scan_max_age
        self.clock_skew = clock_skew
        self.scanner_actors = frozenset(scanner_actors)
        self.scan_timeout = scan_timeout

    # ------------------------------------------------------------------ lifecycle
    @classmethod
    def open(cls, path: "os.PathLike[str] | str | None" = None, **kwargs: Any) -> "StateMachine":
        return cls(db.connect(Path(path or default_db_path())), **kwargs)

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "StateMachine":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None:
            raise ValidationError("clock must return timezone-aware datetimes")
        return now.astimezone(timezone.utc).replace(microsecond=0)

    # ----------------------------------------------------------------- reading
    def _load(self) -> Optional[InstallationRecord]:
        row = self._conn.execute("SELECT * FROM installation WHERE id = 1").fetchone()
        return InstallationRecord.from_row(row) if row else None

    def get(self) -> InstallationRecord:
        rec = self._load()
        if rec is None:
            raise NotInitializedError("installation not initialised (run 'init' first)")
        return rec

    def allowed_triggers(self) -> List[str]:
        return [r.trigger for r in rules_from(self.get().state)]

    def history(self, limit: int = 100) -> List[Dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM state_transitions ORDER BY seq DESC LIMIT ?", (int(limit),)).fetchall()
        out = []
        for r in reversed(rows):
            d = dict(r)
            d["facts"] = json.loads(d.pop("facts_json"))
            out.append(d)
        return out

    def scans(self, limit: int = 20) -> List[Dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM security_scans ORDER BY id DESC LIMIT ?", (int(limit),)).fetchall()
        return [{**dict(r), "summary": json.loads(r["summary_json"])} for r in rows]

    # ------------------------------------------------------------- write helpers
    def _check_version(self, rec: InstallationRecord, expected_version: Optional[int]) -> None:
        if expected_version is not None and rec.row_version != expected_version:
            raise ConcurrencyError(
                f"record changed (expected version {expected_version}, found {rec.row_version})")

    def _append_audit(self, *, installation_id: Optional[str], from_state: Optional[State],
                      to_state: State, trigger: str, actor: str, reason: Optional[str],
                      facts: SecurityFacts, now: datetime) -> None:
        prev = self._conn.execute("SELECT hash FROM state_transitions ORDER BY seq DESC LIMIT 1").fetchone()
        prev_hash = prev[0] if prev else GENESIS_HASH
        payload = {
            "installation_id": installation_id,
            "from_state": from_state.value if from_state else None,
            "to_state": to_state.value,
            "trigger": trigger,
            "actor": actor,
            "reason": reason,
            "facts": facts.to_dict(),
            "created_at": _ts(now),
        }
        self._conn.execute(
            "INSERT INTO state_transitions (installation_id, from_state, to_state, trigger, actor, reason,"
            " facts_json, created_at, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (installation_id, payload["from_state"], payload["to_state"], trigger, actor, reason,
             json.dumps(payload["facts"], sort_keys=True), payload["created_at"], prev_hash,
             _chain_hash(prev_hash, payload)),
        )

    def _commit(self, old: InstallationRecord, new: InstallationRecord, *, trigger: str, actor: str,
                reason: Optional[str], facts: SecurityFacts, now: datetime) -> None:
        new = replace(new, master_enable_expected=(new.state is State.ACTIVE),
                      row_version=old.row_version + 1, updated_at=now)
        check_invariants(new)
        try:
            cur = self._conn.execute(
                "UPDATE installation SET installation_id=?, serial_number=?, state=?, security_status=?,"
                " activated=?, vpn_provisioned=?, last_security_check=?, backup_status=?,"
                " configuration_version=?, master_enable_expected=?, row_version=?, updated_at=?"
                " WHERE id = 1 AND row_version = ?",
                (new.installation_id, new.serial_number, new.state.value, new.security_status.value,
                 int(new.activated), int(new.vpn_provisioned), _ts(new.last_security_check),
                 new.backup_status.value, new.configuration_version, int(new.master_enable_expected),
                 new.row_version, _ts(now), old.row_version),
            )
        except sqlite3.IntegrityError as exc:
            raise IntegrityError(f"database rejected update: {exc}") from exc
        if cur.rowcount != 1:
            raise ConcurrencyError("record was modified concurrently")
        self._append_audit(installation_id=new.installation_id, from_state=old.state, to_state=new.state,
                           trigger=trigger, actor=actor, reason=reason, facts=facts, now=now)

    def _apply_rule(self, rec: InstallationRecord, rule: Rule, *, actor: str, facts: SecurityFacts,
                    reason: Optional[str], context: Mapping[str, Any], now: datetime) -> InstallationRecord:
        if rule.requires_reason and not reason:
            raise ValidationError(f"trigger {rule.trigger!r} requires a reason")
        problems: List[str] = []
        if rule.human_only and not actor.startswith("user:"):
            problems.append("requires a human actor (user:<name>)")
        source_policy, target_policy = POLICIES[rec.state], POLICIES[rule.target]
        if not source_policy.includes(target_policy):  # escalation: entry must be clean
            problems += [f"{v} not allowed in {rec.state.value}" for v in policy_violations(source_policy, facts)]
        gi = GuardInput(record=rec, facts=facts, context=context, actor=actor, reason=reason, now=now,
                        scan_max_age=self.scan_max_age, clock_skew=self.clock_skew)
        for guard in rule.guards:
            msg = guard(gi)
            if msg:
                problems.append(msg)
        if problems:
            raise GuardViolationError(rule.trigger, dict.fromkeys(problems))
        return replace(rec, state=rule.target, **dict(rule.effects))

    # -------------------------------------------------------------- operations
    def initialize(self, *, actor: str, facts: SecurityFacts,
                   configuration_version: Optional[str] = None) -> InstallationRecord:
        """Create the FACTORY record. Idempotent: returns the existing record."""
        _validate_actor(actor)
        if configuration_version is not None and not _VERSION_RE.match(configuration_version):
            raise ValidationError("invalid configuration_version")
        violations = policy_violations(LOCKED, facts)
        if violations:
            raise GuardViolationError("initialized", [f"golden image not clean: {v}" for v in violations])
        now = self._now()
        with db.immediate(self._conn):
            existing = self._load()
            if existing is not None:
                return existing
            self._conn.execute(
                "INSERT INTO installation (id, state, configuration_version, created_at, updated_at)"
                " VALUES (1, 'FACTORY', ?, ?, ?)", (configuration_version, _ts(now), _ts(now)))
            self._append_audit(installation_id=None, from_state=None, to_state=State.FACTORY,
                               trigger="initialized", actor=actor, reason=None, facts=facts, now=now)
        return self.get()

    def set_identity(self, *, installation_id: str, serial_number: str, actor: str,
                     facts: SecurityFacts) -> InstallationRecord:
        iid = validate_installation_id(installation_id)
        sn = normalize_serial(serial_number)
        _validate_actor(actor)
        now = self._now()
        with db.immediate(self._conn):
            rec = self.get()
            if rec.installation_id == iid and rec.serial_number == sn:
                return rec
            if rec.state is not State.FACTORY:
                raise InvalidTransitionError("identity can only be assigned in FACTORY")
            if rec.installation_id not in (None, iid) or rec.serial_number not in (None, sn):
                raise ValidationError("identity already assigned and is immutable")
            self._commit(rec, replace(rec, installation_id=iid, serial_number=sn), trigger="identity_assigned",
                         actor=actor, reason=None, facts=facts, now=now)
        return self.get()

    def fire(self, trigger: str, *, actor: str, facts: SecurityFacts, reason: Optional[str] = None,
             context: Optional[Mapping[str, Any]] = None,
             expected_version: Optional[int] = None) -> InstallationRecord:
        _validate_actor(actor)
        if trigger == "scan_started":
            raise InvalidTransitionError("scan_started is only available via start_scan() (scan session)")
        reason = _validate_reason(reason)
        context = dict(context or {})
        if find_secrets(context):
            raise ValidationError("context looks like it contains secret material")
        now = self._now()
        with db.immediate(self._conn):
            rec = self.get()
            self._check_version(rec, expected_version)
            rule = find_rule(rec.state, trigger)
            new = self._apply_rule(rec, rule, actor=actor, facts=facts, reason=reason, context=context, now=now)
            if trigger == "scan_aborted":
                self._close_open_sessions("ABORTED", now)
            self._commit(rec, new, trigger=trigger, actor=actor, reason=reason, facts=facts, now=now)
        return self.get()

    def update_fields(self, *, actor: str, facts: SecurityFacts, activated: Optional[bool] = None,
                      vpn_provisioned: Optional[bool] = None, backup_status: Optional[str] = None,
                      configuration_version: Optional[str] = None,
                      expected_version: Optional[int] = None) -> InstallationRecord:
        """Update non-state fields. Escalating values are gated by state and facts."""
        _validate_actor(actor)
        now = self._now()
        with db.immediate(self._conn):
            rec = self.get()
            self._check_version(rec, expected_version)
            changes: Dict[str, Any] = {}
            escalating = False
            problems: List[str] = []
            if activated is not None:
                if activated and not rec.activated:
                    escalating = True
                    if rec.state is not State.PROVISIONING:
                        raise InvalidTransitionError("activated can only be set in PROVISIONING")
                changes["activated"] = bool(activated)
            if vpn_provisioned is not None:
                if vpn_provisioned and not rec.vpn_provisioned:
                    escalating = True
                    if rec.state not in (State.PROVISIONING, State.MAINTENANCE):
                        raise InvalidTransitionError("vpn_provisioned can only be set in PROVISIONING/MAINTENANCE")
                    if not (facts.wg_private_key_present and facts.tunnel_active):
                        problems.append("wireguard key/tunnel not observed on device")
                changes["vpn_provisioned"] = bool(vpn_provisioned)
            if backup_status is not None:
                try:
                    bs = BackupStatus(backup_status)
                except ValueError:
                    raise ValidationError(f"invalid backup_status {backup_status!r}") from None
                if bs is not BackupStatus.NOT_CONFIGURED:
                    if rec.state not in CREDENTIALED_STATES:
                        raise InvalidTransitionError(f"backup cannot be configured in {rec.state.value}")
                    if bs in (BackupStatus.CONFIGURED, BackupStatus.OK):
                        escalating = escalating or rec.backup_status is BackupStatus.NOT_CONFIGURED
                        if not facts.backup_credentials_present:
                            problems.append("backup credentials not observed on device")
                changes["backup_status"] = bs
            if configuration_version is not None:
                if not _VERSION_RE.match(configuration_version):
                    raise ValidationError("invalid configuration_version")
                changes["configuration_version"] = configuration_version
            if not changes:
                raise ValidationError("nothing to update")
            if escalating:
                problems += [f"{v} not allowed in {rec.state.value}"
                             for v in policy_violations(POLICIES[rec.state], facts)]
            if problems:
                raise GuardViolationError("fields_updated", problems)
            new = replace(rec, **changes)
            if all(getattr(new, k) == getattr(rec, k) for k in changes):
                return rec  # idempotent no-op, nothing logged
            self._commit(rec, new, trigger="fields_updated:" + ",".join(sorted(changes)), actor=actor,
                         reason=None, facts=facts, now=now)
        return self.get()

    # ------------------------------------------------------------ scan sessions
    def _open_sessions(self) -> List[sqlite3.Row]:
        return self._conn.execute("SELECT * FROM scan_sessions WHERE closed_at IS NULL").fetchall()

    def _close_open_sessions(self, outcome: str, now: datetime) -> int:
        cur = self._conn.execute("UPDATE scan_sessions SET closed_at = ?, outcome = ? WHERE closed_at IS NULL",
                                 (_ts(now), outcome))
        return cur.rowcount

    def _require_scanner(self, actor: str) -> None:
        _validate_actor(actor)
        if actor not in self.scanner_actors:
            raise GuardViolationError("scan", [f"actor {actor} is not an allowed scanner"])

    def start_scan(self, *, actor: str, facts: SecurityFacts) -> Tuple[InstallationRecord, str]:
        """Open a scan session. QUARANTINE -> SCANNING; in ACTIVE/MAINTENANCE no state change.

        Returns (record, scan_id). Only one open session at a time; a session older than
        scan_timeout is closed as ABORTED first (crashed scanner).
        """
        self._require_scanner(actor)
        now = self._now()
        scan_id = os.urandom(16).hex()
        with db.immediate(self._conn):
            rec = self.get()
            if rec.state not in SCAN_START_STATES:
                raise InvalidTransitionError(f"a security scan cannot start in {rec.state.value}")
            for s in self._open_sessions():
                if now - _parse_ts(s["started_at"]) < self.scan_timeout:
                    raise InvalidTransitionError("a security scan is already running")
            self._close_open_sessions("ABORTED", now)
            self._conn.execute(
                "INSERT INTO scan_sessions (scan_id, actor, state_at_start, started_at) VALUES (?,?,?,?)",
                (scan_id, actor, rec.state.value, _ts(now)))
            if rec.state is State.QUARANTINE:
                rule = find_rule(rec.state, "scan_started")
                new = self._apply_rule(rec, rule, actor=actor, facts=facts, reason=None, context={}, now=now)
                self._commit(rec, new, trigger="scan_started", actor=actor, reason=None, facts=facts, now=now)
        return self.get(), scan_id

    def abort_scan(self, *, scan_id: str, actor: str, facts: SecurityFacts, reason: str) -> InstallationRecord:
        """Scanner gave up (error, cancelled). SCANNING -> QUARANTINE."""
        self._require_scanner(actor)
        reason = _validate_reason(reason) or "scan aborted"
        now = self._now()
        with db.immediate(self._conn):
            rec = self.get()
            row = self._conn.execute("SELECT * FROM scan_sessions WHERE scan_id = ?", (scan_id,)).fetchone()
            if row is None or row["closed_at"] is not None or row["actor"] != actor:
                raise InvalidTransitionError("no open scan session with this scan_id for this actor")
            self._conn.execute("UPDATE scan_sessions SET closed_at = ?, outcome = 'ABORTED' WHERE scan_id = ?",
                               (_ts(now), scan_id))
            if rec.state is State.SCANNING:
                new = self._apply_rule(rec, find_rule(rec.state, "scan_aborted"), actor=actor, facts=facts,
                                       reason=reason, context={}, now=now)
                self._commit(rec, new, trigger="scan_aborted", actor=actor, reason=reason, facts=facts, now=now)
        return self.get()

    def record_scan(self, *, scan_id: str, result: str, scanner_version: str, report_sha256: str,
                    summary: Mapping[str, Any], started_at: datetime, actor: str,
                    facts: SecurityFacts) -> InstallationRecord:
        """Persist a scan result for an open scan session and apply its consequence atomically.

        SCANNING -> PASSED/CONDITIONAL/FAILED; ACTIVE + FAIL/CONDITIONAL -> MAINTENANCE;
        otherwise only security_status/last_security_check are updated.
        """
        self._require_scanner(actor)
        try:
            res = SecurityStatus(result)
        except ValueError:
            raise ValidationError(f"invalid scan result {result!r}") from None
        if res not in (SecurityStatus.PASS, SecurityStatus.CONDITIONAL, SecurityStatus.FAIL):
            raise ValidationError("scan result must be PASS, CONDITIONAL or FAIL")
        if not _VERSION_RE.match(scanner_version or ""):
            raise ValidationError("invalid scanner_version")
        if not _SHA256_RE.match(report_sha256 or ""):
            raise ValidationError("report_sha256 must be 64 lower-case hex characters")
        hits = find_secrets(summary)
        if hits:
            raise ValidationError(f"scan summary contains secret-like data at {hits}")
        summary_json = json.dumps(summary, sort_keys=True)
        if len(summary_json.encode()) > MAX_SUMMARY_BYTES:
            raise ValidationError("scan summary too large")
        now = self._now()
        if started_at.tzinfo is None or started_at > now + self.clock_skew or now - started_at > timedelta(days=1):
            raise ValidationError("started_at must be timezone-aware and within the last 24h")

        with db.immediate(self._conn):
            rec = self.get()
            session = self._conn.execute("SELECT * FROM scan_sessions WHERE scan_id = ?",
                                         (scan_id or "",)).fetchone()
            if session is None or session["closed_at"] is not None:
                raise InvalidTransitionError("unknown or already closed scan session (replay?)")
            if session["actor"] != actor:
                raise GuardViolationError("scan", ["result actor differs from the actor that started the scan"])
            opened = _parse_ts(session["started_at"])
            if started_at < opened - self.clock_skew:
                raise ValidationError("started_at lies before the scan session was opened")
            if now - opened > self.scan_timeout:
                raise ValidationError("scan session timed out")
            expected_state = State.SCANNING if session["state_at_start"] == State.QUARANTINE.value \
                else State(session["state_at_start"])
            if rec.state is not expected_state:
                raise InvalidTransitionError(
                    f"state changed during the scan ({session['state_at_start']} -> {rec.state.value})")
            if self._conn.execute("SELECT 1 FROM security_scans WHERE report_sha256 = ?",
                                  (report_sha256,)).fetchone():
                raise ValidationError("report already recorded (replay)")
            self._conn.execute("UPDATE scan_sessions SET closed_at = ?, outcome = ? WHERE scan_id = ?",
                               (_ts(now), res.value, scan_id))
            self._conn.execute(
                "INSERT INTO security_scans (started_at, finished_at, result, scanner_version, report_sha256,"
                " summary_json, scan_id) VALUES (?,?,?,?,?,?,?)",
                (_ts(started_at), _ts(now), res.value, scanner_version, report_sha256, summary_json, scan_id))
            interim = replace(rec, security_status=res, last_security_check=now)
            trigger, reason = "scan_recorded", None
            new = interim
            if rec.state is State.SCANNING:
                trigger = {SecurityStatus.PASS: "scan_passed", SecurityStatus.CONDITIONAL: "scan_conditional",
                           SecurityStatus.FAIL: "scan_failed"}[res]
            elif rec.state is State.ACTIVE and res in (SecurityStatus.FAIL, SecurityStatus.CONDITIONAL):
                # BRION-SEC-002: a CONDITIONAL result must not leave the master switch on
                trigger, reason = "security_degraded", f"periodic security scan {res.value}"
            if trigger != "scan_recorded":
                new = self._apply_rule(interim, find_rule(rec.state, trigger), actor=actor, facts=facts,
                                       reason=reason, context={}, now=now)
            self._commit(rec, new, trigger=trigger, actor=actor, reason=reason, facts=facts, now=now)
        return self.get()

    # ------------------------------------------------------------ reconciliation
    def reconcile(self, facts: SecurityFacts) -> ReconcilePlan:
        return build_plan(self.get().state, facts)

    def recover_on_boot(self, facts: SecurityFacts,
                        actor: str = "system:brion-agent") -> Tuple[InstallationRecord, ReconcilePlan]:
        """Called by the agent at every start before anything else."""
        rec = self.get()
        if rec.state is State.SCANNING:
            rec = self.fire("scan_aborted", actor=actor, facts=facts, reason="scan interrupted by restart")
        else:
            with db.immediate(self._conn):
                self._close_open_sessions("ABORTED", self._now())
        return rec, build_plan(rec.state, facts)

    # ------------------------------------------------------------------- audit
    # ------------------------------------------------------------ audit events
    def audit_event(self, *, actor: str, action: str, outcome: str = "ok",
                    details: Optional[Mapping[str, Any]] = None) -> None:
        """Append an operational audit event (API calls, activation steps, wipes ...).

        Never stores secrets: secret-looking details are replaced by their key names.
        """
        _validate_actor(actor)
        if not re.match(r"^[a-z][a-z0-9_.]{1,63}$", action):
            raise ValidationError("invalid audit action")
        if outcome not in ("ok", "denied", "failed", "info"):
            raise ValidationError("invalid audit outcome")
        details = dict(details or {})
        if find_secrets(details):
            details = {"redacted": True, "keys": sorted(map(str, details))}
        blob = json.dumps(details, sort_keys=True, default=str)
        if len(blob) > 4096:
            details, blob = {"truncated": True}, '{"truncated": true}'
        now = self._now()
        with db.immediate(self._conn):
            rec = self._load()
            prev = self._conn.execute("SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1").fetchone()
            prev_hash = prev[0] if prev else GENESIS_HASH
            payload = {"at": _ts(now), "actor": actor, "action": action, "outcome": outcome,
                       "state": rec.state.value if rec else None, "details": json.loads(blob)}
            self._conn.execute(
                "INSERT INTO audit_events (at, actor, action, outcome, state, details_json, prev_hash, hash)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (payload["at"], actor, action, outcome, payload["state"], blob, prev_hash,
                 _chain_hash(prev_hash, payload)))

    def audit_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        rows = self._conn.execute("SELECT * FROM audit_events ORDER BY seq DESC LIMIT ?", (int(limit),)).fetchall()
        out = []
        for r in reversed(rows):
            d = dict(r)
            d["details"] = json.loads(d.pop("details_json"))
            out.append(d)
        return out

    def _verify_events(self) -> List[str]:
        problems, prev_hash = [], GENESIS_HASH
        for row in self._conn.execute("SELECT * FROM audit_events ORDER BY seq"):
            payload = {"at": row["at"], "actor": row["actor"], "action": row["action"], "outcome": row["outcome"],
                       "state": row["state"], "details": json.loads(row["details_json"])}
            if row["prev_hash"] != prev_hash:
                problems.append(f"audit event {row['seq']}: chain broken")
            if _chain_hash(row["prev_hash"], payload) != row["hash"]:
                problems.append(f"audit event {row['seq']}: content hash mismatch")
            prev_hash = row["hash"]
        return problems

    def verify_audit(self) -> List[str]:
        """Recompute the hash chains. Returns a list of problems (empty = intact)."""
        problems: List[str] = self._verify_events()
        prev_hash = GENESIS_HASH
        last_state: Optional[str] = None
        for row in self._conn.execute("SELECT * FROM state_transitions ORDER BY seq"):
            payload = {
                "installation_id": row["installation_id"], "from_state": row["from_state"],
                "to_state": row["to_state"], "trigger": row["trigger"], "actor": row["actor"],
                "reason": row["reason"], "facts": json.loads(row["facts_json"]),
                "created_at": row["created_at"],
            }
            if row["prev_hash"] != prev_hash:
                problems.append(f"seq {row['seq']}: chain broken (prev_hash mismatch)")
            if _chain_hash(row["prev_hash"], payload) != row["hash"]:
                problems.append(f"seq {row['seq']}: content hash mismatch")
            if last_state is not None and row["from_state"] != last_state:
                problems.append(f"seq {row['seq']}: from_state {row['from_state']} != previous {last_state}")
            prev_hash, last_state = row["hash"], row["to_state"]
        rec = self._load()
        if rec is not None and last_state != rec.state.value:
            problems.append(f"current state {rec.state.value} not backed by audit log ({last_state})")
        return problems
