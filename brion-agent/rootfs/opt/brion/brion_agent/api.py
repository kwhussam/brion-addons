"""HTTP API: /v1/health (always) and /v1/workshop/* (workshop mode + FACTORY/QUARANTINE only)."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import threading
import time
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Tuple

from brion_core import BrionError, GuardViolationError, State, validate_installation_id
from brion_core import golden as golden_mod

from . import __version__
from .internal import CallerVerifier
from .lifecycle import API_TRIGGERS, Lifecycle, LifecycleError
from .service import Agent

LOG = logging.getLogger("brion.api")
MAX_JSON = 64 * 1024
MAX_BUNDLE = golden_mod.MAX_TOTAL_BYTES + 1024 * 1024
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{43,128}$")
ACTOR = "ansible:workshop"
UI_FILES = {"automations.yaml": "[]\n", "scripts.yaml": "{}\n", "scenes.yaml": "[]\n"}


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str = "", extra: Optional[Dict] = None):
        super().__init__(message or code)
        self.status, self.code, self.message, self.extra = status, code, message or code, extra or {}


class _RateLimiter:
    def __init__(self, limit: int = 10, window: float = 60.0) -> None:
        self.limit, self.window, self.fails, self.lock = limit, window, [], threading.Lock()

    def blocked(self) -> bool:
        with self.lock:
            now = time.monotonic()
            self.fails = [t for t in self.fails if now - t < self.window]
            return len(self.fails) >= self.limit

    def fail(self) -> None:
        with self.lock:
            self.fails.append(time.monotonic())


WEB_FILES = {"/": ("ui.html", "text/html; charset=utf-8"), "/ui.css": ("ui.css", "text/css; charset=utf-8"),
            "/ui.js": ("ui.js", "application/javascript; charset=utf-8")}
UI_DIR = __import__("pathlib").Path(__file__).resolve().parent
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "frame-ancestors 'self'; base-uri 'none'; form-action 'self'; object-src 'none'")
_USER_RE = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")


def make_handler(agent: Agent, lifecycle: Optional[Lifecycle] = None, channel: str = "lan"):
    limiter = _RateLimiter()
    internal_limiter = _RateLimiter(limit=20)
    api_limiter = _RateLimiter(limit=10)
    verifier = CallerVerifier(agent.settings.supervisor_url)

    class Handler(BaseHTTPRequestHandler):
        server_version = f"BrionAgent/{__version__}"
        sys_version = ""

        def log_message(self, fmt: str, *args: Any) -> None:  # never log headers/bodies
            LOG.info("%s %s -> %s", self.command, self.path.split("?")[0], args[1] if len(args) > 1 else "")

        # -------------------------------------------------------- plumbing
        def _send(self, status: int, body: Dict[str, Any]) -> None:
            raw = json.dumps(body, sort_keys=True, default=str).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)

        def _body(self, limit: int) -> bytes:
            length = int(self.headers.get("Content-Length") or 0)
            if length > limit:
                raise ApiError(413, "payload_too_large")
            return self.rfile.read(length) if length else b""

        def _json(self) -> Dict[str, Any]:
            try:
                data = json.loads(self._body(MAX_JSON) or b"{}")
            except ValueError:
                raise ApiError(400, "invalid_json") from None
            if not isinstance(data, dict):
                raise ApiError(400, "invalid_json")
            return data

        def _auth(self) -> None:
            if limiter.blocked():
                raise ApiError(429, "too_many_failed_attempts")
            opts = agent.settings.options()
            expected = opts.get("workshop_token_sha256") or ""
            if not opts.get("workshop_mode") or not expected:
                raise ApiError(403, "workshop_closed")
            if agent.state() not in (None, State.FACTORY, State.QUARANTINE):
                raise ApiError(403, "workshop_closed", "device left the workshop states")
            header = self.headers.get("Authorization", "")
            token = header[7:] if header.startswith("Bearer ") else ""
            given = hashlib.sha256(token.encode()).hexdigest()
            if not token or not hmac.compare_digest(given, expected):
                limiter.fail()
                raise ApiError(401, "unauthorized")

        def _auth_internal(self) -> str:
            if internal_limiter.blocked():
                raise ApiError(429, "too_many_failed_attempts")
            header = self.headers.get("Authorization", "")
            actor = verifier.actor_for(header[7:] if header.startswith("Bearer ") else "")
            if actor is None:
                internal_limiter.fail()
                raise ApiError(401, "unauthorized")
            return actor

        def _require_factory(self) -> None:
            if agent.state() not in (None, State.FACTORY):
                raise ApiError(409, "not_in_factory", "only allowed before workshop finalisation")

        # --------------------------------------------------------- /api (lifecycle)
        def _api_actor(self) -> str:
            """Ingress: HA-authenticated user. LAN/VPN: bearer token (sha256 in add-on options)."""
            if channel == "ingress":
                name = self.headers.get("X-Remote-User-Name") or ""
                if not _USER_RE.match(name):
                    raise ApiError(401, "unauthorized", "Home-Assistant-Anmeldung erforderlich.")
                return f"user:{name}"
            if api_limiter.blocked():
                raise ApiError(429, "too_many_failed_attempts")
            expected = agent.settings.options().get("api_token_sha256") or ""
            header = self.headers.get("Authorization", "")
            token = header[7:] if header.startswith("Bearer ") else ""
            if not expected or not token or not hmac.compare_digest(hashlib.sha256(token.encode()).hexdigest(), expected):
                api_limiter.fail()
                lifecycle.audit("api.auth", "denied", actor="system:unknown", path=self.path.split("?")[0][:64],
                                peer=self.client_address[0])
                raise ApiError(401, "unauthorized")
            return "system:brion-central"

        def _api(self, method: str, path: str) -> Tuple[int, Dict]:
            if lifecycle is None:
                raise ApiError(503, "lifecycle_unavailable")
            if method == "GET" and path == "/api/health":
                health = lifecycle.health_status()
                if channel == "lan" and not self.headers.get("Authorization"):
                    return (200 if health["status"] != "error" else 503), {
                        "status": health["status"], "agent_version": __version__}
            actor = self._api_actor()
            if method == "GET" and path == "/api/health":
                return (200 if health["status"] != "error" else 503), health
            if method == "GET" and path == "/api/state":
                return 200, lifecycle.view(detailed=True)
            if method not in ("POST",):
                raise ApiError(405, "method_not_allowed")
            body = self._json()
            operator = body.get("operator")
            if actor == "system:brion-central" and operator:
                if not _USER_RE.match(str(operator)):
                    raise ApiError(400, "invalid_operator")
                actor = f"user:{operator}"
            reason = body.get("reason")
            if reason is not None and not isinstance(reason, str):
                raise ApiError(400, "invalid_reason")
            if path == "/api/transition":
                trigger = str(body.get("trigger", ""))
                return 200, {"record": lifecycle.transition(trigger, actor, reason)}
            if path == "/api/maintenance":
                action = body.get("action")
                if action not in ("start", "finish"):
                    raise ApiError(400, "invalid_action", "action muss 'start' oder 'finish' sein.")
                trigger = "maintenance_started" if action == "start" else "maintenance_finished"
                return 200, {"record": lifecycle.transition(trigger, actor, reason or (
                    "Wartung gestartet" if action == "start" else None))}
            if path == "/api/activate":
                job = lifecycle.activate(actor)
                lifecycle.audit("api.activate", actor=actor)
                return 202, {"activation": {k: job.get(k) for k in ("running", "step", "started_at")}}
            raise ApiError(404, "not_found")

        def _send_ui(self, path: str) -> None:
            name, ctype = WEB_FILES[path]
            raw = (UI_DIR / name).read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)

        def _dispatch(self, method: str) -> None:
            path = self.path.split("?")[0].rstrip("/") or "/"
            try:
                if channel == "ingress":
                    if self.client_address[0] not in agent.settings.ingress_peers:
                        raise ApiError(403, "forbidden", "Zugriff nur über Home Assistant (Ingress).")
                    if method == "GET" and path in WEB_FILES:
                        return self._send_ui(path)
                    if not path.startswith("/api/"):
                        raise ApiError(404, "not_found")
                    status, body = self._api(method, path)
                    return self._send(status, body)
                if path.startswith("/api/"):
                    status, body = self._api(method, path)
                    return self._send(status, body)
                if method == "GET" and path == "/v1/health":
                    # installation_id/state are public (printed on the QR label) and let the
                    # workshop detect a wrong device before touching anything.
                    rec = agent.record()
                    return self._send(200, {"status": "ok", "agent_version": __version__,
                                            "installation_id": rec.installation_id if rec else None,
                                            "state": rec.state.value if rec else None})
                internal = INTERNAL_ROUTES.get((method, path))
                if internal is not None:
                    status, body = internal(self, self._auth_internal())
                    return self._send(status, body)
                route = ROUTES.get((method, path))
                if route is None:
                    raise ApiError(404, "not_found")
                self._auth()
                status, body = route(self)
                self._send(status, body)
            except ApiError as exc:
                self._send(exc.status, {"error": exc.code, "message": exc.message, **exc.extra})
            except LifecycleError as exc:
                self._send(exc.status, {"error": exc.code, "message": exc.message})
            except GuardViolationError as exc:
                self._send(409, {"error": "guard_violation", "message": str(exc),
                                 "violations": list(exc.violations)})
            except BrionError as exc:
                self._send(409 if exc.exit_code in (3, 6) else 400,
                           {"error": type(exc).__name__, "message": str(exc)})
            except Exception:  # pragma: no cover - defensive
                LOG.exception("unhandled error")
                self._send(500, {"error": "internal_error"})

        def do_GET(self) -> None:  # noqa: N802
            self._dispatch("GET")

        def do_POST(self) -> None:  # noqa: N802
            self._dispatch("POST")

        def do_PUT(self) -> None:  # noqa: N802
            self._dispatch("PUT")

        # ---------------------------------------------------------- routes
        def info(self) -> Tuple[int, Dict]:
            return 200, agent.status()

        def identity(self) -> Tuple[int, Dict]:
            body = self._json()
            iid = validate_installation_id(str(body.get("installation_id", "")))
            serial = str(body.get("serial_number", ""))
            cfg = body.get("configuration_version")
            with agent.lock:
                rec = agent.record()
                if rec and rec.installation_id and (rec.installation_id != iid):
                    raise ApiError(409, "identity_mismatch",
                                   f"device already belongs to {rec.installation_id}")
                if rec and rec.state is not State.FACTORY:
                    if rec.installation_id == iid:
                        return 200, {"changed": False, "record": rec.to_dict()}
                    raise ApiError(409, "not_in_factory")
                facts, _ = agent.collect()
                before = rec.row_version if rec else 0
                with agent.machine() as m:
                    m.initialize(actor=ACTOR, facts=facts, configuration_version=cfg)
                    new = m.set_identity(installation_id=iid, serial_number=serial, actor=ACTOR, facts=facts)
            agent.wakeup.set()
            return 200, {"changed": new.row_version != before, "record": new.to_dict()}

        def golden(self) -> Tuple[int, Dict]:
            expected_sha = (self.headers.get("X-Brion-Bundle-Sha256") or "").lower()
            blob = self._body(MAX_BUNDLE)
            sha = hashlib.sha256(blob).hexdigest()
            if not hmac.compare_digest(sha, expected_sha):
                raise ApiError(400, "checksum_mismatch")
            try:
                manifest, files = golden_mod.read_bundle(blob)
            except BrionError as exc:
                raise ApiError(422, "golden_rejected", str(exc)) from None
            cfg_dir = agent.settings.ha_config_dir
            with agent.lock:
                current = agent.golden.get() or {}
                on_disk_ok = all((cfg_dir / p).is_file() and hashlib.sha256((cfg_dir / p).read_bytes())
                                 .hexdigest() == h for p, h in manifest["files"].items())
                changed = not (current.get("sha256") == sha and on_disk_ok)
                if agent.state() not in (None, State.FACTORY):
                    if changed:  # after finalisation only an identical, intact deployment is accepted
                        raise ApiError(409, "not_in_factory", "golden can only change before finalisation")
                    return 200, {"changed": False, "version": manifest["version"], "sha256": sha,
                                 "written": 0, "removed": []}
                result = {"written": [], "removed": []}
                if changed:
                    result = golden_mod.install_bundle(files, str(cfg_dir))
                    agent.golden.set({"version": manifest["version"], "sha256": sha,
                                      "content_id": manifest.get("content_id"),
                                      "deployed_at": datetime.now(timezone.utc).isoformat(timespec="seconds")})
                for name, default in UI_FILES.items():
                    if not (cfg_dir / name).exists():
                        (cfg_dir / name).write_text(default)
                        changed = True
                rec = agent.record()
                if rec is not None and rec.configuration_version != f"golden-{manifest['version']}":
                    facts, _ = agent.collect()
                    with agent.machine() as m:
                        m.update_fields(actor=ACTOR, facts=facts,
                                        configuration_version=f"golden-{manifest['version']}")
                    changed = True
            agent.wakeup.set()
            return 200, {"changed": changed, "version": manifest["version"], "sha256": sha,
                         "written": len(result["written"]), "removed": result["removed"]}

        def activation_token(self) -> Tuple[int, Dict]:
            self._require_factory()
            body = self._json()
            token = str(body.get("token", ""))
            if not TOKEN_RE.match(token):
                raise ApiError(400, "invalid_token_format")
            try:
                expires = datetime.fromisoformat(str(body.get("expires_at", "")))
            except ValueError:
                raise ApiError(400, "invalid_expires_at") from None
            if expires.tzinfo is None or expires <= datetime.now(timezone.utc):
                raise ApiError(400, "invalid_expires_at", "must be timezone-aware and in the future")
            with agent.lock:
                rec = agent.record()
                if rec is None or not rec.installation_id:
                    raise ApiError(409, "identity_missing")
                sha = hashlib.sha256(token.encode()).hexdigest()
                cur = agent.tokens.public()
                changed = not (agent.tokens.token_sha256() == sha and cur.get("expires_at") == expires.isoformat())
                pub = agent.tokens.save(rec.installation_id, token, expires) if changed else cur
            agent.wakeup.set()
            return 200, {"changed": changed, "fingerprint": pub["fingerprint"], "expires_at": pub["expires_at"]}

        def finalize(self) -> Tuple[int, Dict]:
            with agent.lock:
                rec = agent.record()
                if rec is None:
                    raise ApiError(409, "identity_missing")
                if rec.state is State.QUARANTINE:
                    return 200, {"changed": False, "record": rec.to_dict()}
                facts, inspection = agent.collect()
                problems = []
                if not agent.golden.get():
                    problems.append("golden configuration not deployed")
                tok = agent.tokens.public()
                if not tok["present"] or tok["expired"]:
                    problems.append("activation token missing or expired")
                if inspection["secrets_yaml_keys"]:
                    problems.append("secrets.yaml is not empty")
                if inspection["forbidden_integrations"]:
                    problems.append(f"customer integrations present: {inspection['forbidden_integrations']}")
                if inspection["wireguard_config_files"] or inspection["wireguard_interfaces"]:
                    problems.append("wireguard configuration present")
                if not inspection["ha_reachable"]:
                    problems.append("home assistant not reachable (master switch state unknown)")
                if problems:
                    raise ApiError(409, "finalize_blocked", "; ".join(problems), {"violations": problems})
                with agent.machine() as m:
                    new = m.fire("workshop_finalized", actor=ACTOR, facts=facts)
            agent.wakeup.set()
            return 200, {"changed": True, "record": new.to_dict()}

        # ------------------------------------------------- internal (Security add-on)
        def internal_status(self, actor: str) -> Tuple[int, Dict]:
            rec = agent.record()
            facts, _ = agent.collect()
            return 200, {
                "installation_id": rec.installation_id if rec else None,
                "state": rec.state.value if rec else None,
                "security_status": rec.security_status.value if rec else None,
                "last_security_check": rec.to_dict()["last_security_check"] if rec else None,
                "vpn_provisioned": rec.vpn_provisioned if rec else False,
                "remote_access_active": facts.tunnel_active,
                "automations_enabled": facts.master_enable_on,
            }

        def internal_scan_start(self, actor: str) -> Tuple[int, Dict]:
            facts, _ = agent.collect()
            with agent.lock, agent.machine() as m:
                rec, scan_id = m.start_scan(actor=actor, facts=facts)
            agent.wakeup.set()
            return 200, {"scan_id": scan_id, "state": rec.state.value}

        def internal_scan_result(self, actor: str) -> Tuple[int, Dict]:
            body = self._json()
            try:
                started = datetime.fromisoformat(str(body.get("started_at", "")))
            except ValueError:
                raise ApiError(400, "invalid_started_at") from None
            summary = body.get("summary") or {}
            if not isinstance(summary, dict):
                raise ApiError(400, "invalid_summary")
            facts, _ = agent.collect()
            with agent.lock, agent.machine() as m:
                rec = m.record_scan(scan_id=str(body.get("scan_id", "")), result=str(body.get("result", "")),
                                    scanner_version=str(body.get("scanner_version", "")),
                                    report_sha256=str(body.get("report_sha256", "")), summary=summary,
                                    started_at=started, actor=actor, facts=facts)
            agent.wakeup.set()
            return 200, {"state": rec.state.value, "security_status": rec.security_status.value}

        def internal_scan_abort(self, actor: str) -> Tuple[int, Dict]:
            body = self._json()
            facts, _ = agent.collect()
            with agent.lock, agent.machine() as m:
                rec = m.abort_scan(scan_id=str(body.get("scan_id", "")), actor=actor, facts=facts,
                                   reason=str(body.get("reason") or "scan aborted")[:200])
            agent.wakeup.set()
            return 200, {"state": rec.state.value}

        def internal_rescan(self, actor: str) -> Tuple[int, Dict]:
            """FAILED/CONDITIONAL -> QUARANTINE on behalf of the HA user operating the ingress UI."""
            body = self._json()
            user = str(body.get("user", ""))
            if not re.match(r"^[A-Za-z0-9._@-]{1,64}$", user):
                raise ApiError(400, "invalid_user", "a logged-in Home Assistant user is required")
            facts, _ = agent.collect()
            with agent.lock, agent.machine() as m:
                rec = m.fire("rescan_requested", actor=f"user:{user}", facts=facts,
                             reason=str(body.get("reason") or "Erneute Sicherheitsprüfung")[:200])
            agent.wakeup.set()
            return 200, {"state": rec.state.value}

    INTERNAL_ROUTES = {
        ("GET", "/v1/internal/status"): Handler.internal_status,
        ("POST", "/v1/internal/scan/start"): Handler.internal_scan_start,
        ("POST", "/v1/internal/scan/result"): Handler.internal_scan_result,
        ("POST", "/v1/internal/scan/abort"): Handler.internal_scan_abort,
        ("POST", "/v1/internal/rescan"): Handler.internal_rescan,
    }

    ROUTES = {
        ("GET", "/v1/workshop/info"): Handler.info,
        ("POST", "/v1/workshop/identity"): Handler.identity,
        ("PUT", "/v1/workshop/golden"): Handler.golden,
        ("POST", "/v1/workshop/activation-token"): Handler.activation_token,
        ("POST", "/v1/workshop/finalize"): Handler.finalize,
    }
    return Handler


def serve(agent: Agent, lifecycle: Optional[Lifecycle] = None, channel: str = "lan") -> ThreadingHTTPServer:
    s = agent.settings
    addr = (s.api_host, s.api_port) if channel == "lan" else (s.ingress_host, s.ingress_port)
    srv = ThreadingHTTPServer(addr, make_handler(agent, lifecycle or getattr(agent, "lifecycle", None), channel))
    srv.daemon_threads = True
    return srv
