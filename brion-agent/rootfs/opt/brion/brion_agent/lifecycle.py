"""Lifecycle orchestration of the customer Raspberry Pi.

Boot (every start):  open SQLite -> installation id -> state -> security status -> start only
                     the functions the state allows.
Locked states        (FACTORY, QUARANTINE, SCANNING, FAILED, CONDITIONAL, PASSED, DISABLED):
                     no WireGuard, no remote access, no backup/cloud credentials, master OFF.
PROVISIONING         only reachable via activate(); an interrupted provisioning fails closed.
ACTIVE               VPN + backup checked, heartbeat running, master switch ON.
MAINTENANCE          VPN for remote maintenance, master OFF.

The agent never scans the network - it only takes over status + timestamp from Brion Security.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from brion_core import (BackupStatus, BrionError, GuardViolationError, InvalidTransitionError, SecurityStatus,
                        State, StateMachine)
from brion_core.transitions import rules_from

from . import __version__, facts as facts_mod, outbound
from .outbound import OutboundError
from .wireguard import WireGuard, WireGuardError, generate_keypair

LOG = logging.getLogger("brion.lifecycle")
SYSTEM = "system:brion-agent"

# Triggers that may be fired through POST /api/transition. Everything else is internal:
# scans only via the Security add-on session, provisioning only via /api/activate.
API_TRIGGERS = ("rescan_requested", "conditional_accepted", "maintenance_started", "maintenance_finished",
                "disabled", "reenabled")
QUARANTINE_MSG = "Das System bleibt im Quarantäne-Modus."
MESSAGES = {
    "FACTORY": "Werkstatt-Vorkonfiguration – das Gerät ist noch nicht ausgeliefert.",
    "QUARANTINE": "Das System befindet sich im Quarantäne-Modus. Bitte die Sicherheitsprüfung in „Brion Security“ durchführen.",
    "SCANNING": "Die Sicherheitsprüfung läuft.",
    "FAILED": QUARANTINE_MSG + " Die Sicherheitsprüfung wurde nicht bestanden – Befunde beheben und erneut prüfen.",
    "CONDITIONAL": QUARANTINE_MSG + " Die Prüfung ergab Auflagen – Befunde beheben oder durch einen Techniker akzeptieren.",
    "PASSED": "Sicherheitsprüfung bestanden. Das System kann jetzt aktiviert werden.",
    "PROVISIONING": "Aktivierung läuft (VPN und Backup werden eingerichtet).",
    "ACTIVE": "Brion ist aktiv.",
    "MAINTENANCE": "Wartungsmodus – Brion-Automationen sind pausiert.",
    "DISABLED": "Brion ist deaktiviert.",
}


class LifecycleError(Exception):
    def __init__(self, status: int, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.status, self.code, self.message = status, code, message or code


def _ts(dt: Optional[datetime]) -> Optional[str]:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds") if dt else None


def _write_private_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(data, fh, sort_keys=True)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


class Lifecycle:
    def __init__(self, agent, wg: Optional[WireGuard] = None) -> None:
        self.agent = agent
        s = agent.settings
        self.s = s
        self.wg = wg or WireGuard(s.wg_interface, s.wg_key_file, s.wg_psk_file, s.wg_peer_file, s.sys_net)
        self.job: Dict[str, Any] = {"running": False}
        self.health: Dict[str, Any] = {}
        self.heartbeat: Dict[str, Any] = {"last_ok": None, "last_error": None, "sent": 0}
        self.boot_report: Dict[str, Any] = {}
        self._job_thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ utils
    def opts(self) -> Dict[str, Any]:
        return self.s.options()

    def audit(self, action: str, outcome: str = "ok", actor: str = SYSTEM, **details: Any) -> None:
        try:
            with self.agent.machine() as m:
                m.audit_event(actor=actor, action=action, outcome=outcome, details=details)
        except BrionError as exc:   # auditing must never break the lifecycle
            LOG.error("audit event %s not stored: %s", action, exc)

    def facts(self):
        return self.agent.collect()[0]

    def set_master(self, on: bool, actor: str = SYSTEM) -> bool:
        try:
            self.agent.ha.call_service("input_boolean", "turn_on" if on else "turn_off",
                                       {"entity_id": facts_mod.MASTER})
            self.audit("master.on" if on else "master.off", actor=actor)
            return True
        except Exception as exc:  # noqa: BLE001
            self.audit("master.on" if on else "master.off", "failed", actor=actor, error=type(exc).__name__)
            return False

    def security_addon(self) -> Dict[str, Any]:
        try:
            return {"reachable": True, **outbound.security_summary(self.s.security_url, self.s.supervisor_token)}
        except OutboundError as exc:
            return {"reachable": False, "status": None, "timestamp": None, "error": exc.code}

    def wipe_credentials(self, reason: str) -> List[str]:
        removed = []
        if self.wg.down():
            removed.append("tunnel")
        for d, pattern in ((self.s.wg_dir, "*"), (self.s.secrets_dir, "backup*"), (self.s.secrets_dir, "cloud*")):
            for p in d.glob(pattern):
                if p.is_file():
                    size = p.stat().st_size
                    with open(p, "r+b") as fh:
                        fh.write(b"\0" * size)
                    p.unlink()
                    removed.append(p.name)
        if self.s.activation_file.exists():
            self.s.activation_file.unlink()
            removed.append(self.s.activation_file.name)
        if removed:
            self.audit("credentials.wiped", reason=reason, items=removed)
        return removed

    # ------------------------------------------------------------------- boot
    def boot(self) -> Dict[str, Any]:
        """Steps 1-5 of the boot sequence. Always fail closed."""
        report: Dict[str, Any] = {"at": _ts(datetime.now(timezone.utc)), "agent_version": __version__}
        # 1. SQLite öffnen (Migration + quick_check)
        try:
            with self.agent.machine() as m:
                rec = self.agent.record()
                audit_problems = m.verify_audit()
        except BrionError as exc:
            report.update(db="error", error=str(exc)[:200])
            self.wipe_credentials("database unusable")
            self.set_master(False)
            self.boot_report = report
            LOG.critical("brion.db unusable - running fail closed: %s", exc)
            return report
        report["db"] = "ok"
        report["audit_ok"] = not audit_problems
        # 2./3. Installation-ID und Zustand
        report["installation_id"] = rec.installation_id if rec else None
        report["state_at_boot"] = rec.state.value if rec else None
        # recovery of interrupted operations (scans, provisioning)
        with self.agent.lock:
            facts = self.facts()
            with self.agent.machine() as m:
                if rec is not None:
                    rec, _ = m.recover_on_boot(facts)                      # SCANNING -> QUARANTINE
                    if rec.state is State.PROVISIONING:                     # BRION-SM-005: fail closed
                        rec = m.fire("provisioning_failed", actor=SYSTEM, facts=facts,
                                     reason="restart during provisioning")
                        report["recovered"] = "provisioning_failed"
        # 4. Security-Status prüfen
        addon = self.security_addon()
        report["security"] = {
            "status": rec.security_status.value if rec else None,
            "last_check": _ts(rec.last_security_check) if rec else None,
            "addon_status": addon.get("status"), "addon_timestamp": addon.get("timestamp"),
            "addon_reachable": addon.get("reachable"),
        }
        # 5. zulässige Funktionen starten
        report["functions"] = self.apply_state(boot=True)
        report["state"] = self.agent.state().value if self.agent.state() else None
        self.boot_report = report
        self.audit("agent.boot", state_after_boot=report["state"], db=report["db"], audit_ok=report["audit_ok"],
                   functions=report["functions"], recovered=report.get("recovered"))
        LOG.info("boot complete: state=%s functions=%s", report["state"], report["functions"])
        return report

    def apply_state(self, boot: bool = False) -> List[str]:
        """Start/stop functions according to the current state. Returns what is running."""
        state = self.agent.state()
        if state is State.ACTIVE:
            return self.ensure_active(boot=boot)
        if state is State.MAINTENANCE:
            if boot:
                self.set_master(False)
            running = ["vpn"] if self.ensure_vpn() else []
            return running + ["heartbeat"]
        # every other state is locked down
        self.wipe_credentials(f"state {state.value if state else 'UNINITIALIZED'}")
        if boot:
            self.set_master(False)
        return []

    # ----------------------------------------------------------- ACTIVE checks
    def ensure_vpn(self) -> bool:
        if not self.wg.interface_up():
            try:
                self.wg.up()
                self.audit("vpn.up")
            except WireGuardError as exc:
                self.audit("vpn.up", "failed", error=str(exc)[:120])
                return False
        return True

    def check_backup(self) -> str:
        try:
            cfg = json.loads(self.s.backup_file.read_text())
            ok = all(cfg.get(k) for k in ("type", "url", "username", "password"))
        except (OSError, ValueError):
            ok = False
        return "OK" if ok else "FAILED"

    def ensure_active(self, boot: bool = False, actor: str = SYSTEM) -> List[str]:
        with self.agent.machine() as m:
            rec = m.get()
        facts = self.facts()
        # BRION-SM-003: ACTIVE must stay backed by activation, VPN and backup
        if not (rec.activated and rec.vpn_provisioned):
            with self.agent.machine() as m:
                m.fire("security_degraded", actor=SYSTEM, facts=facts, reason="ACTIVE without activation/VPN")
            self.set_master(False)
            self.audit("active.invariant_violated", "failed")
            return ["vpn"] if self.ensure_vpn() else []
        vpn_ok = self.ensure_vpn()
        vpn = self.wg.healthy()
        backup = self.check_backup()
        if backup != rec.backup_status.value:
            with self.agent.machine() as m:
                m.update_fields(actor=SYSTEM, facts=self.facts(), backup_status=backup)
        self.health = {"checked_at": _ts(datetime.now(timezone.utc)), "vpn": vpn, "backup": backup,
                       "ok": bool(vpn_ok and vpn["interface"] and backup == "OK")}
        if boot:
            self.agent.publish()          # guard automation must see ACTIVE before the switch goes on
            self.set_master(True, actor=actor)
        return ["vpn"] * bool(vpn_ok) + ["backup"] * (backup == "OK") + ["heartbeat", "master_switch"]

    def validations(self) -> Dict[str, bool]:
        """Context for activation_completed / maintenance_finished - computed here, never trusted from callers."""
        try:
            golden = self.agent.ha.get_state("sensor.brion_golden_version")
            master = self.agent.ha.get_state(facts_mod.MASTER)
            states = self.agent.ha._req("GET", "/states") or []
        except Exception:  # noqa: BLE001
            return {"integrations_validated": False, "automations_validated": False}
        expected = (self.agent.golden.get() or {}).get("version")
        autos = [s for s in states if str(s.get("entity_id", "")).startswith("automation.")
                 and str((s.get("attributes") or {}).get("id", "")).startswith("brion_")]
        guards = [a for a in autos if a["attributes"]["id"].startswith("brion_guard_")]
        return {
            "integrations_validated": bool(golden) and master is not None
                                      and (expected is None or golden.get("state") == expected),
            "automations_validated": bool(autos) and bool(guards) and all(g.get("state") == "on" for g in guards),
        }

    # -------------------------------------------------------------- activation
    def activation_preconditions(self) -> Dict[str, Any]:
        with self.agent.machine() as m:
            rec = m.get()
        if self.job.get("running"):
            raise LifecycleError(409, "activation_running", "Aktivierung läuft bereits.")
        if rec.state is not State.PASSED:
            raise LifecycleError(409, "not_passed", f"Aktivierung nur im Zustand PASSED (aktuell {rec.state.value}).")
        allowed = {SecurityStatus.PASS}
        if self.opts().get("activate_after_conditional_acceptance"):
            allowed.add(SecurityStatus.CONDITIONAL_ACCEPTED)
        if rec.security_status not in allowed:
            raise LifecycleError(409, "security_not_passed",
                                 f"Sicherheitsstatus {rec.security_status.value} erlaubt keine Aktivierung.")
        addon = self.security_addon()
        if not addon["reachable"]:
            raise LifecycleError(503, "security_unreachable", "Brion Security nicht erreichbar.")
        expected_addon = {"PASSED"} | ({"CONDITIONAL"} if rec.security_status is SecurityStatus.CONDITIONAL_ACCEPTED else set())
        if addon["status"] not in expected_addon:
            raise LifecycleError(409, "security_mismatch", "Brion Security meldet kein bestandenes Ergebnis.")
        try:
            addon_ts = datetime.fromisoformat(addon["timestamp"])
        except (TypeError, ValueError):
            raise LifecycleError(409, "security_mismatch", "Zeitpunkt der Prüfung fehlt.") from None
        if rec.last_security_check is None or abs(addon_ts - rec.last_security_check) > timedelta(minutes=5):
            raise LifecycleError(409, "security_mismatch", "Prüfergebnis des Agent und von Brion Security weichen ab.")
        tok = self.agent.tokens.public()
        if not tok["present"] or tok["expired"]:
            raise LifecycleError(409, "activation_token_missing", "Activation Token fehlt oder ist abgelaufen.")
        if not self.opts().get("activation_url"):
            raise LifecycleError(409, "activation_url_missing", "Keine Activation-API konfiguriert.")
        return {"record": rec, "addon": addon}

    def activate(self, actor: str, wait: bool = False) -> Dict[str, Any]:
        with self._lock:
            pre = self.activation_preconditions()
            self.job = {"running": True, "step": "start", "started_at": _ts(datetime.now(timezone.utc)),
                        "actor": actor, "error": None}
            self._job_thread = threading.Thread(target=self._provision, args=(actor, pre), daemon=True,
                                                name="brion-activation")
            self._job_thread.start()
        if wait:
            self._job_thread.join(300)
        return dict(self.job)

    def _step(self, name: str) -> None:
        self.job["step"] = name
        LOG.info("activation step: %s", name)

    def _provision(self, actor: str, pre: Dict[str, Any]) -> None:
        rec = pre["record"]
        try:
            self._step("provisioning_started")
            with self.agent.lock, self.agent.machine() as m:
                rec = m.fire("provisioning_started", actor=actor, facts=self.facts())
            self.audit("activation.started", actor=actor)
            self.agent.publish()

            self._step("keypair")
            public_key = generate_keypair(self.s.wg_key_file)
            self.audit("wireguard.keypair_generated",
                       public_key_fingerprint=hashlib.sha256(public_key.encode()).hexdigest()[:16])

            self._step("activation_api")
            token = self.agent.tokens.token()
            body = outbound.activation_request(rec.installation_id, token, public_key,
                                               pre["addon"]["status"], pre["addon"]["timestamp"])
            del token
            result = outbound.activate(self.opts()["activation_url"], body,
                                       self.opts().get("activation_ca_file") or None)
            body = None
            self.agent.tokens.consume()                       # one-time token
            self.audit("activation.api", activation_id=result["activation_id"])

            self._step("store_configuration")
            self.wg.save_peer(result["peer"], result.get("psk"))
            _write_private_json(self.s.backup_file, result["backup"])
            _write_private_json(self.s.activation_file, {"activation_id": result["activation_id"],
                                                         "heartbeat": result["heartbeat"],
                                                         "activated_at": _ts(datetime.now(timezone.utc))})
            result = None
            with self.agent.lock, self.agent.machine() as m:
                m.update_fields(actor=SYSTEM, facts=self.facts(), activated=True)

            self._step("vpn")
            self.wg.up()
            deadline = time.monotonic() + float(self.opts().get("handshake_timeout", 60))
            while not self.wg.healthy()["ok"]:
                if time.monotonic() > deadline:
                    raise WireGuardError("no WireGuard handshake with the Brion hub")
                time.sleep(1)
            with self.agent.lock, self.agent.machine() as m:
                m.update_fields(actor=SYSTEM, facts=self.facts(), vpn_provisioned=True)
                m.update_fields(actor=SYSTEM, facts=self.facts(), backup_status="CONFIGURED")
            self.audit("vpn.up")

            self._step("validation")
            ctx = self.validations()
            with self.agent.lock, self.agent.machine() as m:
                m.fire("activation_completed", actor=SYSTEM, facts=self.facts(), context=ctx)
            self._step("master_switch")
            self.ensure_active(boot=True, actor=SYSTEM)
            self.audit("activation.completed", actor=actor)
            self.job.update(running=False, step="done", finished_at=_ts(datetime.now(timezone.utc)))
        except Exception as exc:  # noqa: BLE001 - every failure ends in FAILED, fail closed
            code = exc.code if isinstance(exc, OutboundError) else type(exc).__name__
            LOG.error("activation failed in step %s: %s", self.job.get("step"), code)
            self.job.update(running=False, error=code, finished_at=_ts(datetime.now(timezone.utc)))
            self.audit("activation.failed", "failed", actor=actor, step=self.job.get("step"), error=code)
            try:
                with self.agent.lock, self.agent.machine() as m:
                    if m.get().state is State.PROVISIONING:
                        m.fire("provisioning_failed", actor=SYSTEM, facts=self.facts(),
                               reason=f"activation failed: {code}"[:200])
            except BrionError as e2:
                LOG.critical("could not leave PROVISIONING: %s", e2)
            self.wipe_credentials("activation failed")
            self.set_master(False)
        finally:
            self.agent.wakeup.set()

    # -------------------------------------------------------------- transitions
    def transition(self, trigger: str, actor: str, reason: Optional[str]) -> Dict[str, Any]:
        if trigger not in API_TRIGGERS:
            raise LifecycleError(403, "trigger_not_allowed",
                                 f"Übergang {trigger!r} ist über die API nicht erlaubt.")
        context: Dict[str, Any] = {}
        if trigger == "maintenance_finished":
            context = self.validations()
            self.set_master(False)     # entering ACTIVE requires the switch to be off (policy)
        with self.agent.lock:
            try:
                with self.agent.machine() as m:
                    rec = m.fire(trigger, actor=actor, facts=self.facts(), reason=reason, context=context)
            except (InvalidTransitionError, GuardViolationError) as exc:
                self.audit("api.transition", "denied", actor=actor, trigger=trigger, error=str(exc)[:200])
                raise
        self.audit("api.transition", actor=actor, trigger=trigger, to_state=rec.state.value)
        if rec.state is State.ACTIVE:
            self.ensure_active(boot=True, actor=actor)
        else:
            self.agent.reconcile()           # immediate lock-down when leaving ACTIVE
            if rec.state is State.MAINTENANCE:
                self.ensure_vpn()
            elif rec.state is State.DISABLED:
                self.wipe_credentials("disabled")
        self.agent.wakeup.set()
        return rec.to_dict()

    # -------------------------------------------------------------- heartbeat
    def heartbeat_due(self) -> Optional[Dict[str, Any]]:
        if self.agent.state() not in (State.ACTIVE, State.MAINTENANCE):
            return None
        try:
            act = json.loads(self.s.activation_file.read_text())
        except (OSError, ValueError):
            return None
        last = self.heartbeat.get("last_attempt_mono") or 0
        if time.monotonic() - last < int(act["heartbeat"]["interval"]):
            return None
        return act["heartbeat"]

    def send_heartbeat(self) -> bool:
        target = self.heartbeat_due()
        if not target:
            return False
        rec = self.agent.record()
        self.heartbeat["last_attempt_mono"] = time.monotonic()
        try:
            outbound.send_heartbeat(target["url"], outbound.heartbeat_payload(rec.installation_id, rec.state.value),
                                    self.opts().get("activation_ca_file") or None)
            self.heartbeat.update(last_ok=_ts(datetime.now(timezone.utc)), last_error=None,
                                  sent=self.heartbeat["sent"] + 1)
            return True
        except OutboundError as exc:
            self.heartbeat["last_error"] = exc.code
            return False

    def periodic(self) -> None:
        """Called by the background loop: ACTIVE health checks and heartbeat."""
        state = self.agent.state()
        if state is State.ACTIVE:
            last = self.health.get("_mono", 0)
            if time.monotonic() - last >= self.s.health_interval:
                self.ensure_active(boot=False)
                self.health["_mono"] = time.monotonic()
        if state in (State.ACTIVE, State.MAINTENANCE):
            self.send_heartbeat()

    def health_status(self) -> Dict[str, Any]:
        if self.boot_report.get("db") == "error":
            return {"status": "error", "reason": "database"}
        state = self.agent.state()
        status = "ok"
        if state is State.ACTIVE and self.health and not self.health.get("ok"):
            status = "degraded"
        return {"status": status, "agent_version": __version__, "state": state.value if state else None,
                "checks": {k: v for k, v in self.health.items() if not k.startswith("_")},
                "heartbeat": {k: self.heartbeat.get(k) for k in ("last_ok", "last_error")}}

    # ------------------------------------------------------------------ views
    def allowed_actions(self, state: Optional[State]) -> List[str]:
        if state is None:
            return []
        acts = [r.trigger for r in rules_from(state) if r.trigger in API_TRIGGERS]
        if state is State.PASSED and not self.job.get("running"):
            acts.append("activate")
        return acts

    def view(self, detailed: bool = True) -> Dict[str, Any]:
        rec = self.agent.record()
        state = rec.state if rec else None
        facts = self.facts()
        out: Dict[str, Any] = {
            "agent_version": __version__,
            "installation_id": rec.installation_id if rec else None,
            "state": state.value if state else None,
            "message": MESSAGES.get(state.value if state else "", "Nicht initialisiert."),
            "quarantine": state in (State.FACTORY, State.QUARANTINE, State.SCANNING, State.FAILED,
                                    State.CONDITIONAL, State.PASSED, None),
            "allowed_actions": self.allowed_actions(state),
        }
        if not detailed:
            return out
        addon = self.security_addon()
        out.update({
            "security": {"status": rec.security_status.value if rec else None,
                         "last_check": _ts(rec.last_security_check) if rec else None,
                         "addon": {k: addon.get(k) for k in ("reachable", "status", "timestamp")}},
            "master_enable": {"expected": bool(rec and rec.master_enable_expected), "actual": facts.master_enable_on},
            "remote_maintenance": {"vpn_provisioned": bool(rec and rec.vpn_provisioned),
                                   "tunnel": self.wg.healthy() if facts.tunnel_active else {"interface": False}},
            "backup": {"status": rec.backup_status.value if rec else None},
            "heartbeat": {k: self.heartbeat.get(k) for k in ("last_ok", "last_error", "sent")},
            "activation": {k: self.job.get(k) for k in ("running", "step", "error", "started_at", "finished_at")},
            "health": {k: v for k, v in self.health.items() if not k.startswith("_")},
            "security_ui": self.security_ui_path(),
        })
        return out

    def security_ui_path(self) -> Optional[str]:
        host = os.environ.get("HOSTNAME", "")            # Supervisor: "<repo>-brion-agent"
        if host.endswith("-brion-agent"):
            return f"/hassio/ingress/{host[:-len('-brion-agent')].replace('-', '_')}_brion_security"
        return None
