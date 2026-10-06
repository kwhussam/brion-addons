"""FastAPI app: ingress web UI + local API.

GET  /api/status        GET  /api/check/status   GET  /api/check/result
POST /api/check/start   POST /api/check/retry    GET  /api/report
Only the Home Assistant ingress gateway may connect (peer check); no CORS.
"""
from __future__ import annotations

import json
import logging
import re
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from jinja2 import Environment, FileSystemLoader, select_autoescape
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import __version__, netinfo, report, tr064
from .agent_client import AgentClient, AgentError
from .internal_auth import AgentVerifier
from .scanner import Scanner, ScanRejected
from .sensitive import Secret
from .settings import Settings, load as load_settings
from .store import Store

LOG = logging.getLogger("brion.security.app")
PKG = Path(__file__).resolve().parent
STATIC = {"style.css": "text/css; charset=utf-8", "app.js": "application/javascript; charset=utf-8"}
MAX_START_BODY = 4096
_USER_RE = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")
CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
       "connect-src 'self'; frame-ancestors 'self'; base-uri 'none'; form-action 'self'; object-src 'none'")


def _err(status: int, code: str, message: str = "", **extra: Any) -> JSONResponse:
    return JSONResponse({"error": code, "message": message or code, **extra}, status_code=status)


class _Cache:
    def __init__(self, ttl: float, fn: Callable[[], Any]) -> None:
        self.ttl, self.fn, self._val, self._at, self._lock = ttl, fn, None, 0.0, threading.Lock()

    def get(self) -> Any:
        with self._lock:
            if time.monotonic() - self._at > self.ttl:
                try:
                    self._val = self.fn()
                except Exception:  # noqa: BLE001
                    self._val = None
                self._at = time.monotonic()
            return self._val


def create_app(settings: Optional[Settings] = None, scanner: Optional[Scanner] = None,
               agent: Optional[AgentClient] = None) -> FastAPI:
    settings = settings or load_settings()
    env = Environment(loader=FileSystemLoader(str(PKG)), autoescape=select_autoescape(("html", "j2")))
    agent = agent or AgentClient(settings.agent_url, settings.supervisor_token)
    scanner = scanner or Scanner(settings, Store(settings.db_path), agent, env)

    net_cache = _Cache(60, lambda: netinfo.detect(settings.supervisor_url, settings.supervisor_token,
                                                  settings.proc_root, settings.resolv_conf,
                                                  scanner.ruleset.min_prefix))

    def _router_model() -> Optional[str]:
        net = net_cache.get()
        host = settings.router_host or (net.gateway if net else None)
        return tr064.probe_model(host) if host else None

    router_cache = _Cache(300, _router_model)
    agent_verifier = AgentVerifier(settings.supervisor_url)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        scanner.recover()
        try:
            st = agent.status()
            LOG.info("Brion Security %s started, lifecycle state %s", __version__, st.get("state"))
            if st.get("state") == "QUARANTINE":
                LOG.info("device in QUARANTINE - security check UI available, automations stay disabled")
        except AgentError as exc:
            LOG.warning("lifecycle state unknown at start (agent: %s) - checks disabled until reachable", exc.code)
        yield

    app = FastAPI(title="Brion Security", version=__version__, docs_url=None, redoc_url=None,
                  openapi_url=None, lifespan=lifespan)
    app.state.scanner, app.state.settings = scanner, settings

    # ------------------------------------------------------------- middleware
    @app.middleware("http")
    async def guard(request: Request, call_next):
        peer = request.client.host if request.client else ""
        internal = request.url.path.startswith("/internal/v1/")   # Brion Agent, own authentication
        if not internal and "*" not in settings.allowed_peers and peer not in settings.allowed_peers:
            return _err(403, "forbidden", "Zugriff nur über Home Assistant (Ingress).")
        try:
            response = await call_next(request)
        except Exception:  # noqa: BLE001
            LOG.exception("unhandled error")
            response = _err(500, "internal_error", "Interner Fehler.")
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError):
        return _err(422, "invalid_request")  # never echo the input (could contain the password)

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException):
        return _err(exc.status_code, "not_found" if exc.status_code == 404 else "http_error")

    # ---------------------------------------------------------------- helpers
    def operator(request: Request) -> Optional[str]:
        name = request.headers.get("X-Remote-User-Name") or ""
        return name if _USER_RE.match(name) else None

    async def read_credentials(request: Request) -> Tuple[str, Secret]:
        if not request.headers.get("content-type", "").startswith("application/json"):
            raise ScanRejected(415, "json_required", "Anfrage muss JSON sein.")
        raw = await request.body()
        try:
            if len(raw) > MAX_START_BODY:
                raise ScanRejected(413, "payload_too_large", "Anfrage zu groß.")
            try:
                body = json.loads(raw or b"{}")
            except ValueError:
                raise ScanRejected(400, "invalid_json", "Ungültiges JSON.") from None
            if not isinstance(body, dict):
                raise ScanRejected(400, "invalid_json", "Ungültiges JSON.")
            user, pw = body.pop("router_user", "") or "", body.pop("router_password", "") or ""
            if not isinstance(user, str) or not isinstance(pw, str) or len(user) > 64 or len(pw) > 128:
                raise ScanRejected(400, "invalid_credentials", "Ungültige Router-Zugangsdaten.")
            secret = Secret(pw)
            return user, secret
        finally:
            # drop every reference to plaintext copies held by this request
            pw = body = raw = None  # noqa: F841
            if hasattr(request, "_body"):
                request._body = b""
            request.scope.pop("_json", None)

    def status_payload() -> Dict[str, Any]:
        try:
            st = agent.status()
            agent_ok = True
        except AgentError:
            st, agent_ok = {}, False
        state = st.get("state")
        job = scanner.job()
        running = scanner.running()
        if not agent_ok:
            check = "unavailable"
        elif running or state == "SCANNING":
            check = "running"
        elif state == "QUARANTINE":
            check = "required"
        elif state in ("PASSED", "CONDITIONAL", "FAILED"):
            check = state
        else:
            check = (scanner.store.latest("completed") or {}).get("overall") or "unavailable"
        net = net_cache.get()
        model = None
        try:
            model = settings.device_model_file.read_bytes().decode(errors="replace").strip("\x00\n ")
        except OSError:
            pass
        return {
            "version": __version__,
            "installation_id": st.get("installation_id"),
            "lifecycle_state": state,
            "device": {"connected": agent_ok, "model": model},
            "network": {"detected": net is not None, "network": net.network if net else None},
            "router": {"model": (router_cache.get() if net else None)
                       or ((scanner.last_result() or {}).get("router") or {}).get("model")},
            "security_check": check,
            "remote_maintenance": bool(st.get("remote_access_active") or st.get("vpn_provisioned")),
            "automations": bool(st.get("automations_enabled", True)) if agent_ok else None,
            "can_start": agent_ok and state == "QUARANTINE" and not running,
            "can_retry": agent_ok and state in ("FAILED", "CONDITIONAL") and not running,
            "job": job,
        }

    # ----------------------------------------------------------------- pages
    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        try:
            st = agent.status()
        except AgentError:
            st = {}
        return HTMLResponse(env.get_template("index.html.j2").render(installation_id=st.get("installation_id"),
                                                                     state=st.get("state")))

    @app.get("/static/{name}")
    def static(name: str) -> Response:
        if name not in STATIC:
            return _err(404, "not_found")
        return Response((PKG / name).read_bytes(), media_type=STATIC[name])

    @app.get("/result", response_class=HTMLResponse)
    def result_view() -> Response:
        r = scanner.last_result()
        if r is None:
            return _err(404, "no_result", "Noch keine abgeschlossene Prüfung.")
        return HTMLResponse(report.render_html(env, r, view=True))

    @app.get("/internal/v1/summary")
    def internal_summary(request: Request) -> Response:
        """For the Brion Agent only: status + timestamp of the latest completed check - no scan details."""
        header = request.headers.get("Authorization", "")
        if not agent_verifier.is_agent(header[7:] if header.startswith("Bearer ") else ""):
            return _err(401, "unauthorized")
        j = scanner.store.latest("completed")
        return JSONResponse({"status": j["overall"] if j else None, "timestamp": j["finished_at"] if j else None})

    @app.get("/health")
    def health() -> Dict[str, str]:
        return {"status": "ok", "version": __version__}

    # ------------------------------------------------------------------- api
    @app.get("/api/status")
    def api_status() -> Dict[str, Any]:
        return status_payload()

    @app.post("/api/check/start")
    async def api_start(request: Request) -> JSONResponse:
        try:
            user, secret = await read_credentials(request)
            scan_id = scanner.start(user, secret, operator(request))
        except ScanRejected as exc:
            return _err(exc.status, exc.code, exc.message)
        return JSONResponse({"scan_id": scan_id, "state": "running"}, status_code=202)

    @app.post("/api/check/retry")
    async def api_retry(request: Request) -> JSONResponse:
        try:
            user, secret = await read_credentials(request)
            scan_id = scanner.retry(user, secret, operator(request))
        except ScanRejected as exc:
            return _err(exc.status, exc.code, exc.message)
        return JSONResponse({"scan_id": scan_id, "state": "running"}, status_code=202)

    @app.get("/api/check/status")
    def api_check_status() -> Response:
        job = scanner.job()
        if job is None:
            return _err(404, "no_scan", "Noch keine Prüfung gestartet.")
        return JSONResponse({**job, "running": scanner.running()})

    @app.get("/api/check/result")
    def api_result() -> Response:
        r = scanner.last_result()
        if r is None:
            return _err(404, "no_result", "Noch keine abgeschlossene Prüfung.")
        return JSONResponse(r)

    @app.get("/api/report")
    def api_report(format: str = "pdf") -> Response:
        if format not in ("pdf", "html"):
            return _err(400, "invalid_format", "format=pdf oder format=html")
        j = scanner.store.latest("completed")
        path = Path(j["report_dir"]) / f"security-report.{format}" if j and j.get("report_dir") else None
        if path is None or not path.is_file() or settings.reports_dir not in path.parents:
            return _err(404, "no_report", "Kein Bericht vorhanden.")
        return FileResponse(path, media_type="application/pdf" if format == "pdf" else "text/html; charset=utf-8",
                            filename=f"security-report.{format}")

    return app
