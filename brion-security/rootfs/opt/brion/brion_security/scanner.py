"""Scan orchestration: lifecycle gate -> agent scan session -> network -> nmap -> TR-064
-> rules -> local report -> result to agent. One scan at a time, password wiped in all cases."""
from __future__ import annotations

import logging
import shutil
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from jinja2 import Environment

from . import __version__, netinfo, nmap_scan, privacy, report, rules, tr064
from .agent_client import AgentClient, AgentError
from .sensitive import Secret
from .settings import Settings
from .store import Store, now_iso

LOG = logging.getLogger("brion.security.scan")
AGENT_RESULT = {"PASSED": "PASS", "CONDITIONAL": "CONDITIONAL", "FAILED": "FAIL"}
PHASES = {"start": (0, "Prüfung wird vorbereitet"), "network": (10, "Netzwerk wird erkannt"),
          "discovery": (25, "Geräte im Netz werden gesucht"), "ports": (50, "Ausgewählte Ports werden geprüft"),
          "router": (70, "Router wird über TR-064 abgefragt"), "rules": (85, "Ergebnisse werden bewertet"),
          "report": (92, "Bericht wird erstellt"), "submit": (97, "Ergebnis wird übermittelt"),
          "done": (100, "Abgeschlossen")}


class ScanRejected(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


class Scanner:
    def __init__(self, settings: Settings, store: Store, agent: AgentClient, env: Environment,
                 collectors: Optional[Dict[str, Callable[..., Any]]] = None) -> None:
        self.settings, self.store, self.agent, self.env = settings, store, agent, env
        self.ruleset = rules.load(settings.rules_file)
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        # injectable for tests
        self.collectors = {
            "network": lambda: netinfo.detect(settings.supervisor_url, settings.supervisor_token,
                                              settings.proc_root, settings.resolv_conf, self.ruleset.min_prefix),
            "discover": nmap_scan.discover, "ports": nmap_scan.port_scan, "router": tr064.collect,
            **(collectors or {}),
        }

    # --------------------------------------------------------------- control
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self, router_user: str, router_password: Secret, operator: Optional[str]) -> str:
        """Validate lifecycle, open agent scan session, run in background. Returns local scan id."""
        try:
            with self._lock:
                if self.running():
                    raise ScanRejected(409, "scan_running", "Eine Prüfung läuft bereits.")
                try:
                    st = self.agent.status()
                except AgentError as exc:
                    raise ScanRejected(503, "agent_unavailable", "Brion Agent nicht erreichbar.") from exc
                if st.get("state") != "QUARANTINE":
                    raise ScanRejected(409, "not_in_quarantine",
                                       f"Prüfung nur im Zustand QUARANTINE möglich (aktuell {st.get('state')}).")
                try:
                    session = self.agent.scan_start()
                except AgentError as exc:
                    raise ScanRejected(409 if exc.status < 500 else 503, "agent_refused",
                                       f"Agent hat den Start abgelehnt: {exc.code}") from exc
                scan_id = uuid.uuid4().hex
                self.store.create(scan_id, operator, __version__)
                self.store.update(scan_id, agent_scan_id=session["scan_id"])
                t = threading.Thread(target=self._run, name=f"scan-{scan_id[:8]}", daemon=True,
                                     args=(scan_id, session["scan_id"], st.get("installation_id"),
                                           router_user, router_password))
                self._thread = t
                t.start()
                return scan_id
        except BaseException:
            router_password.wipe()   # never keep the password if the scan does not start
            raise

    def retry(self, router_user: str, router_password: Secret, operator: Optional[str]) -> str:
        try:
            st = self.agent.status()
        except AgentError as exc:
            router_password.wipe()
            raise ScanRejected(503, "agent_unavailable", "Brion Agent nicht erreichbar.") from exc
        state = st.get("state")
        if state in ("FAILED", "CONDITIONAL"):
            if not operator:
                router_password.wipe()
                raise ScanRejected(403, "user_required", "Wiederholung nur durch angemeldeten Benutzer.")
            try:
                self.agent.rescan(operator, "Erneute Sicherheitsprüfung über Brion Security")
            except AgentError as exc:
                router_password.wipe()
                raise ScanRejected(409, "agent_refused", f"Agent hat die Wiederholung abgelehnt: {exc.code}") from exc
        elif state != "QUARANTINE":
            router_password.wipe()
            raise ScanRejected(409, "retry_not_possible", f"Wiederholung im Zustand {state} nicht möglich.")
        return self.start(router_user, router_password, operator)

    def recover(self) -> None:
        """At start-up: abort agent sessions of scans interrupted by a restart."""
        for row in self.store.mark_interrupted():
            if row.get("agent_scan_id"):
                try:
                    self.agent.scan_abort(row["agent_scan_id"], "security add-on restarted")
                except AgentError as exc:
                    LOG.info("abort of interrupted scan not accepted by agent: %s", exc.code)

    # ------------------------------------------------------------------ run
    def _phase(self, scan_id: str, phase: str) -> None:
        self.store.update(scan_id, phase=phase, progress=PHASES[phase][0])

    def _run(self, scan_id: str, agent_scan_id: str, installation_id: Optional[str],
             router_user: str, router_password: Secret) -> None:
        started = datetime.now(timezone.utc)
        try:
            self._phase(scan_id, "network")
            net = self.collectors["network"]()
            self._phase(scan_id, "discovery")
            hosts = self.collectors["discover"](net.network, self.ruleset.max_hosts)
            for h in hosts:
                h.is_self = h.ip == net.address
                h.is_gateway = h.ip == net.gateway
            self._phase(scan_id, "ports")
            open_ports = self.collectors["ports"]([h.ip for h in hosts], self.ruleset.ports, net.network,
                                                  self.ruleset.max_hosts)
            for h in hosts:
                h.open_ports = open_ports.get(h.ip, [])
            self._phase(scan_id, "router")
            router_host = self.settings.router_host or net.gateway
            router = (self.collectors["router"](router_host, router_user, router_password)
                      if router_host else tr064.RouterInfo(errors=["no gateway"]))
            router_password.wipe()
            known = {h.get("mac") for h in router.hosts or [] if h.get("mac")}
            for h in hosts:
                h.known_to_router = None if router.hosts is None else (h.mac in known if h.mac else None)
            self._phase(scan_id, "rules")
            data = rules.ScanData(net.to_dict(), [h.to_dict() for h in hosts], router.to_dict())
            ev = rules.evaluate(self.ruleset, data).to_dict()
            finished = datetime.now(timezone.utc)
            result = {"scan_id": scan_id, "installation_id": installation_id,
                      "started_at": started.isoformat(timespec="seconds"),
                      "finished_at": finished.isoformat(timespec="seconds"), "scanner_version": __version__,
                      "network": data.network, "devices": data.devices, "router": data.router, **ev}
            self._phase(scan_id, "report")
            rep = report.write_reports(self.env, result, self.settings.reports_dir / scan_id)
            self.store.update(scan_id, overall=ev["overall"], counts_json=ev["counts"], findings_json=ev["findings"],
                              data_json=result, report_dir=rep["dir"], report_sha256=rep["pdf_sha256"],
                              rules_version=ev["rules_version"])
            self._phase(scan_id, "submit")
            resp = self.agent.scan_result(scan_id=agent_scan_id, result=AGENT_RESULT[ev["overall"]],
                                          scanner_version=__version__, report_sha256=rep["pdf_sha256"],
                                          summary=privacy.agent_summary(ev), started_at=started.isoformat())
            self.store.update(scan_id, state="completed", finished_at=now_iso(), agent_state=resp.get("state"),
                              phase="done", progress=100)
            LOG.info("security check finished: %s (%s GREEN / %s YELLOW / %s RED)", ev["overall"],
                     ev["counts"]["GREEN"], ev["counts"]["YELLOW"], ev["counts"]["RED"])
            self._prune()
        except Exception as exc:  # noqa: BLE001
            reason = f"{type(exc).__name__}: {str(exc)[:200]}" if not isinstance(exc, AgentError) else f"agent: {exc.code}"
            LOG.error("security check failed: %s", reason)
            self.store.update(scan_id, state="error", finished_at=now_iso(), error=reason)
            try:
                self.agent.scan_abort(agent_scan_id, "scan failed")
            except AgentError:
                pass
        finally:
            router_password.wipe()

    def _prune(self) -> None:
        for d in self.store.prune(self.settings.retain_reports):
            p = Path(d)
            if p.is_dir() and self.settings.reports_dir in p.parents:
                shutil.rmtree(p, ignore_errors=True)

    # --------------------------------------------------------------- views
    def job(self) -> Optional[Dict[str, Any]]:
        j = self.store.latest()
        if not j:
            return None
        return {"id": j["id"], "state": j["state"], "phase": j["phase"], "progress": j["progress"],
                "phase_label": PHASES.get(j["phase"] or "start", (0, ""))[1], "started_at": j["started_at"],
                "finished_at": j["finished_at"], "overall": j["overall"], "error": j["error"]}

    def last_result(self) -> Optional[Dict[str, Any]]:
        j = self.store.latest("completed")
        return j["data"] if j else None
