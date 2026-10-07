"""Agent core: boot recovery, reconcile (fail closed) and HA status publishing."""
from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import brion_core
from brion_core import NotInitializedError, StateMachine, State, build_plan

from . import __version__, facts as facts_mod
from .ha import HAClient, HAUnavailable
from .settings import Settings
from .store import ActivationTokenStore, GoldenRecord

LOG = logging.getLogger("brion.agent")
SENSOR = "sensor.brion_lifecycle"
WORKSHOP_STATES = (None, State.FACTORY, State.QUARANTINE)


class Agent:
    def __init__(self, settings: Settings, ha: Optional[HAClient] = None) -> None:
        self.settings = settings
        self.ha = ha or HAClient(settings.ha_api, settings.supervisor_token)
        self.tokens = ActivationTokenStore(settings.secrets_dir)
        self.golden = GoldenRecord(settings.brion_dir)
        self.lock = threading.RLock()  # serialises workshop writes + reconcile
        self.lifecycle = None          # set by Lifecycle owner (__main__ / tests)
        self.wakeup = threading.Event()
        self._stop = threading.Event()
        for d in (settings.brion_dir, settings.secrets_dir, settings.wg_dir):
            d.mkdir(parents=True, exist_ok=True, mode=0o700)

    # ------------------------------------------------------------- helpers
    def machine(self) -> StateMachine:
        return StateMachine.open(self.settings.db_path)

    def record(self) -> Optional[brion_core.InstallationRecord]:
        with self.machine() as m:
            try:
                return m.get()
            except NotInitializedError:
                return None

    def state(self) -> Optional[State]:
        rec = self.record()
        return rec.state if rec else None

    def workshop_open(self) -> bool:
        opts = self.settings.options()
        return bool(opts.get("workshop_mode")) and bool(opts.get("workshop_token_sha256")) \
            and self.state() in WORKSHOP_STATES

    def collect(self):
        return facts_mod.collect(self.settings, self.ha)

    # ----------------------------------------------------------- reconcile
    def reconcile(self, boot: bool = False) -> Dict[str, Any]:
        """boot=True only once at agent start: a scan that was running before the restart
        is aborted (SCANNING -> QUARANTINE). Periodic calls never touch running scans."""
        with self.lock:
            facts, _ = self.collect()
            state = self.state()
            if state is None:
                plan = build_plan(State.FACTORY, facts)
            else:
                with self.machine() as m:
                    if boot:
                        _, plan = m.recover_on_boot(facts)
                    else:
                        plan = m.reconcile(facts)
            done = []
            for action in plan.actions:
                try:
                    if action == "set_master_enable_off":
                        self.ha.call_service("input_boolean", "turn_off",
                                             {"entity_id": facts_mod.MASTER})
                    elif action == "wipe_wg_private_key":
                        self._wipe(self.settings.wg_dir, "*")
                    elif action == "wipe_backup_credentials":
                        self._wipe(self.settings.secrets_dir, "backup*")
                    elif action == "wipe_cloud_credentials":
                        self._wipe(self.settings.secrets_dir, "cloud*")
                    elif action == "stop_tunnel":
                        if self.lifecycle is None or not self.lifecycle.wg.down():
                            LOG.error("wireguard interface up in state %s and could not be removed",
                                      plan.state.value)
                            continue
                    elif action == "set_master_enable_on":
                        # switched on by the lifecycle at boot/activation/maintenance end only;
                        # a manual OFF in ACTIVE is respected (Brion paused by the customer)
                        continue
                    done.append(action)
                except HAUnavailable as exc:
                    LOG.warning("reconcile action %s failed: %s", action, exc)
            if done:
                LOG.warning("reconcile enforced %s in state %s", done, plan.state.value)
            return {"plan": plan.to_dict(), "executed": done}

    @staticmethod
    def _wipe(directory, pattern: str) -> None:
        for p in directory.glob(pattern):
            if p.is_file():
                size = p.stat().st_size
                with open(p, "r+b") as fh:  # best-effort overwrite before unlink
                    fh.write(b"\0" * size)
                    fh.flush()
                p.unlink()

    # ------------------------------------------------------------- status
    def status(self) -> Dict[str, Any]:
        facts, inspection = self.collect()
        rec = self.record()
        audit_ok = None
        if rec is not None:
            with self.machine() as m:
                audit_ok = not m.verify_audit()
        golden = self.golden.get() or {}
        token = self.tokens.public()
        return {
            "agent_version": __version__,
            "core_version": brion_core.__version__,
            "hardware_serial": facts_mod.hardware_serial(self.settings),
            "record": rec.to_dict() if rec else None,
            "facts": facts.to_dict(),
            "inspection": inspection,
            "activation": token,
            "golden": {k: golden.get(k) for k in ("version", "sha256", "content_id", "deployed_at")} if golden else None,
            "workshop_mode": bool(self.settings.options().get("workshop_mode")),
            "audit_ok": audit_ok,
        }

    def publish(self) -> None:
        st = self.status()
        rec = st["record"] or {}
        attrs = {
            "friendly_name": "Brion Lebenszyklus",
            "icon": "mdi:shield-home-outline",
            "installation_id": rec.get("installation_id"),
            "serial_number": rec.get("serial_number"),
            "hardware_serial": facts_mod.hardware_serial(self.settings),
            "security_status": rec.get("security_status"),
            "master_enable_expected": rec.get("master_enable_expected", False),
            "vpn_provisioned": rec.get("vpn_provisioned", False),
            "activated": rec.get("activated", False),
            "configuration_version": rec.get("configuration_version"),
            "agent_version": st["agent_version"],
            "golden_version": (st["golden"] or {}).get("version"),
            "activation_token_present": st["activation"]["present"],
            "activation_token_expired": st["activation"]["expired"],
            "activation_fingerprint": st["activation"]["fingerprint"],
            "workshop_mode": st["workshop_mode"],
            "audit_ok": st["audit_ok"],
            "facts": st["facts"],
            "inspection": {k: v for k, v in st["inspection"].items() if k != "ha_reachable"},
            "published_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        self.ha.set_state(SENSOR, rec.get("state", "UNINITIALIZED"), attrs)

    # --------------------------------------------------------------- loop
    def run_background(self) -> threading.Thread:
        def loop() -> None:
            while not self._stop.is_set():
                steps = [self.reconcile, self.publish]
                if self.lifecycle is not None:
                    steps.append(self.lifecycle.periodic)
                for step in steps:
                    try:
                        step()
                    except Exception:  # keep the loop alive, never crash the agent
                        LOG.exception("background step %s failed", step.__name__)
                self.wakeup.wait(self.settings.publish_interval)
                self.wakeup.clear()
        t = threading.Thread(target=loop, name="brion-background", daemon=True)
        t.start()
        return t

    def stop(self) -> None:
        self._stop.set()
        self.wakeup.set()
