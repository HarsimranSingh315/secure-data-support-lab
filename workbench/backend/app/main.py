"""DataShield Support Workbench - API.

GET /api/health     the workbench itself is up (does not touch the lab)
GET /api/overview   runs every allow-listed lab check and returns cards + recent status changes
GET /api/events     recent status changes only
GET /api/topology   live network map: interfaces, OSPF adjacencies, routes, current path
GET /api/diagnostics            catalog of allow-listed operations, targets and ports
GET /api/diagnostics/{op}       run one operation (?target=db&port=5432&router=r1)
GET /api/diagnose               guided diagnosis from Site A to one service (?target=db&port=5432)
GET  /api/incidents             the incident library and each incident's state
POST /api/incidents/{id}/{break|hint|fix}   run scripts/scenario.sh for one scenario
GET  /api/incidents/{id}/runbook            the runbook (contains the answer)
GET  /api/captures/options      capture points, filters, test traffic
POST /api/captures              capture on a lab device and analyse it
POST /api/captures/upload       analyse an uploaded pcap (raw body, max 10 MB)
GET  /api/captures[/{id}[/pcap|/packets/{n}]]

There is deliberately no endpoint that accepts a command, host or file path: parameters are
names from fixed allow-lists, validated before any command is built. Endpoints that change the
lab (POST) also require the X-Workbench-Action header and a same-origin request, so another web
page open in the browser cannot trigger them (CSRF).
"""
from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
import uuid
from collections import deque
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from .checks import SPECS, now, run_check
from . import captures as cap_mod
from . import incidents as inc_mod
from .diagnostics import InvalidRequest, catalog, diagnose, run_op
from .models import CaptureAnalysis, CaptureMeta, Check, DiagResult, Event, Incident, Overview, Topology, WizardResult
from .topology import collect
from .runner import DockerRunner, Runner

VERSION = "0.3.0"
MAX_PARALLEL_DIAG = 3          # diagnostics running at once; more get HTTP 429
MIN_INTERVAL_S = 2.0          # overview results are reused for this long (protects the lab)
STATIC = Path(os.environ.get("WB_STATIC", Path(__file__).resolve().parent.parent / "static"))

log = logging.getLogger("workbench")
logging.basicConfig(level=logging.INFO, format="%(message)s")


def overall_status(checks: list[Check]) -> str:
    statuses = {c.status for c in checks}
    if "down" in statuses:
        return "down"
    if statuses & {"degraded", "unknown"}:
        return "degraded"
    return "ok" if statuses else "unknown"


class Monitor:
    """Runs the checks, remembers the last result and records status changes."""

    def __init__(self, runner: Runner, max_events: int = 200) -> None:
        self.runner = runner
        self.events: deque[Event] = deque(maxlen=max_events)
        self._last: dict[str, str] = {}
        self._cache: Overview | None = None
        self._cache_at = 0.0
        self._lock = threading.Lock()

    def _record(self, checks: list[Check]) -> None:
        for c in checks:
            prev = self._last.get(c.id)
            if prev != c.status:
                # The first observation is recorded too, so the timeline starts with a baseline.
                self.events.appendleft(Event(time=c.checked_at, check_id=c.id, title=c.title,
                                             previous=prev, status=c.status, summary=c.summary))
            self._last[c.id] = c.status

    def overview(self, force: bool = False) -> Overview:
        with self._lock:
            if self._cache and not force and time.monotonic() - self._cache_at < MIN_INTERVAL_S:
                return self._cache
            start = time.monotonic()
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=len(SPECS)) as pool:
                checks = list(pool.map(lambda s: run_check(self.runner, s), SPECS))
            self._record(checks)
            counts = {s: sum(1 for c in checks if c.status == s) for s in ("ok", "degraded", "down", "unknown")}
            reachable = any(e.error != "docker_unavailable" for c in checks for e in c.evidence)
            self._cache = Overview(overall=overall_status(checks), counts=counts, checks=checks,
                                   events=list(self.events)[:50], checked_at=now(),
                                   duration_ms=int((time.monotonic() - start) * 1000),
                                   lab_reachable=reachable)
            self._cache_at = time.monotonic()
            return self._cache


def create_app(runner: Runner | None = None) -> FastAPI:
    app = FastAPI(title="DataShield Support Workbench", version=VERSION, docs_url="/api/docs",
                  openapi_url="/api/openapi.json", redoc_url=None)
    monitor = Monitor(runner or DockerRunner())
    app.state.monitor = monitor

    @app.middleware("http")
    async def request_log(request: Request, call_next):
        rid = uuid.uuid4().hex[:8]
        start = time.monotonic()
        response = await call_next(request)
        response.headers["X-Request-ID"] = rid
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'"
        if request.url.path.startswith("/api/"):
            log.info('{"request_id":"%s","method":"%s","path":"%s","status":%d,"ms":%.1f}',
                     rid, request.method, request.url.path, response.status_code,
                     (time.monotonic() - start) * 1000)
        return response

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok", "service": "workbench", "version": VERSION}

    @app.get("/api/overview", response_model=Overview)
    async def overview(refresh: bool = False) -> Overview:
        return await asyncio.to_thread(monitor.overview, refresh)

    @app.get("/api/events")
    def events() -> list[Event]:
        return list(monitor.events)

    slots = threading.BoundedSemaphore(MAX_PARALLEL_DIAG)
    topo_cache: dict = {"at": 0.0, "value": None}
    topo_lock = threading.Lock()

    def limited(fn, *args, **kwargs):
        if not slots.acquire(blocking=False):
            raise HTTPException(429, "Too many diagnostics running; try again in a moment.")
        try:
            return fn(*args, **kwargs)
        except InvalidRequest as exc:
            raise HTTPException(400, str(exc)) from None
        finally:
            slots.release()

    def topology_cached(force: bool) -> Topology:
        with topo_lock:
            if topo_cache["value"] is None or force or time.monotonic() - topo_cache["at"] > 3:
                topo_cache["value"] = collect(monitor.runner)
                topo_cache["at"] = time.monotonic()
            return topo_cache["value"]

    @app.get("/api/topology", response_model=Topology)
    async def topology(refresh: bool = False) -> Topology:
        return await asyncio.to_thread(topology_cached, refresh)

    @app.get("/api/diagnostics")
    def diagnostics_catalog() -> dict:
        return catalog()

    @app.get("/api/diagnostics/{op}", response_model=DiagResult)
    async def diagnostics_run(op: str, target: str | None = Query(None, max_length=16),
                              port: int | None = Query(None, ge=1, le=65535),
                              router: str | None = Query(None, max_length=4)) -> DiagResult:
        return await asyncio.to_thread(limited, run_op, monitor.runner, op, target, port, router)

    @app.get("/api/diagnose", response_model=WizardResult)
    async def guided(target: str = Query(..., max_length=16), port: int = Query(..., ge=1, le=65535)) -> WizardResult:
        return await asyncio.to_thread(limited, diagnose, monitor.runner, target, port)

    # ------------------------------------------------------------- actions (change the lab)

    def guard(request: Request) -> None:
        """Only the workbench's own page may trigger actions: a custom header (which forces a CORS
        preflight that this server never approves) and, when the browser sends one, a same-origin
        Origin header."""
        from urllib.parse import urlparse
        if request.headers.get("x-workbench-action") != "1":
            raise HTTPException(403, "missing X-Workbench-Action header")
        origin = request.headers.get("origin")
        if origin and urlparse(origin).netloc != request.headers.get("host"):
            raise HTTPException(403, "cross-origin request refused")
        if request.headers.get("sec-fetch-site") not in (None, "same-origin", "none"):
            raise HTTPException(403, "cross-site request refused")

    def invalidate() -> None:
        monitor._cache = None
        topo_cache["value"] = None

    def inc_call(fn, *args):
        try:
            return fn(*args)
        except inc_mod.IncidentError as exc:
            raise HTTPException(exc.status, str(exc)) from None

    @app.get("/api/incidents", response_model=list[Incident])
    def incidents_list() -> list[Incident]:
        return inc_mod.list_incidents()

    @app.get("/api/incidents/{sid}", response_model=Incident)
    def incident_get(sid: str) -> Incident:
        return inc_call(inc_mod.get, sid)

    @app.get("/api/incidents/{sid}/runbook")
    def incident_runbook(sid: str) -> dict:
        return {"id": sid, "markdown": inc_call(inc_mod.runbook, sid)}

    @app.post("/api/incidents/{sid}/{action}", response_model=Incident)
    async def incident_action(sid: str, action: str, request: Request) -> Incident:
        guard(request)
        if action == "clear":
            return inc_call(inc_mod.reset_record, sid)
        try:
            return await asyncio.to_thread(inc_call, inc_mod.act, sid, action)
        finally:
            invalidate()

    @app.get("/api/actions")
    def actions() -> list[dict]:
        return inc_mod.recent_actions()

    # ------------------------------------------------------------- captures

    def cap_call(fn, *args):
        try:
            return fn(*args)
        except cap_mod.CaptureError as exc:
            raise HTTPException(400, str(exc)) from None
        except FileNotFoundError:
            raise HTTPException(404, "no such capture") from None

    @app.get("/api/captures/options")
    def capture_options() -> dict:
        return {"points": [{"id": k, "label": v[0]} for k, v in cap_mod.POINTS.items()],
                "filters": [{"id": k, "label": v[0], "bpf": " ".join(v[1])} for k, v in cap_mod.FILTERS.items()],
                "traffic": [{"id": k, "label": v} for k, v in cap_mod.TRAFFIC.items()],
                "seconds": {"min": 3, "max": 30, "default": 8}}

    @app.get("/api/captures", response_model=list[CaptureMeta])
    def captures_list() -> list[CaptureMeta]:
        return cap_mod.list_captures()

    @app.post("/api/captures", response_model=CaptureAnalysis)
    async def capture_run(request: Request) -> CaptureAnalysis:
        guard(request)
        try:
            body = await request.json()
            point, flt = str(body["point"]), str(body["filter"])
            seconds, traffic = int(body.get("seconds", 8)), str(body.get("traffic", "none"))
        except (ValueError, KeyError, TypeError):
            raise HTTPException(400, "expected JSON: point, filter, seconds, traffic") from None
        return await asyncio.to_thread(cap_call, cap_mod.capture, monitor.runner, point, flt, seconds, traffic)

    @app.post("/api/captures/upload", response_model=CaptureAnalysis)
    async def capture_upload(request: Request, filename: str = Query("upload.pcap", max_length=120)) -> CaptureAnalysis:
        guard(request)
        if int(request.headers.get("content-length") or 0) > cap_mod.MAX_FILE:
            raise HTTPException(413, "file too large (max 10 MB)")
        raw = b""
        async for chunk in request.stream():
            raw += chunk
            if len(raw) > cap_mod.MAX_FILE:
                raise HTTPException(413, "file too large (max 10 MB)")
        return await asyncio.to_thread(cap_call, cap_mod.upload, monitor.runner, raw, filename)

    @app.get("/api/captures/{cid}", response_model=CaptureAnalysis)
    def capture_get(cid: str) -> CaptureAnalysis:
        return cap_call(cap_mod.load, cid)

    @app.get("/api/captures/{cid}/pcap")
    def capture_pcap(cid: str) -> Response:
        data = cap_call(cap_mod.pcap_bytes, cid)
        return Response(data, media_type="application/vnd.tcpdump.pcap",
                        headers={"Content-Disposition": f'attachment; filename="lab-{cid}.pcap"'})

    @app.get("/api/captures/{cid}/packets/{no}")
    async def capture_packet(cid: str, no: int) -> dict:
        return await asyncio.to_thread(cap_call, cap_mod.packet_detail, monitor.runner, cid, no)

    @app.exception_handler(Exception)
    async def unexpected(_: Request, exc: Exception):
        log.exception("unhandled error")
        return JSONResponse({"error": "internal error"}, status_code=500)

    if (STATIC / "index.html").exists():
        app.mount("/assets", StaticFiles(directory=STATIC / "assets"), name="assets")

        @app.get("/{path:path}", include_in_schema=False)
        def spa(path: str):
            if path.startswith("api/"):
                return JSONResponse({"error": "not found"}, status_code=404)
            return FileResponse(STATIC / "index.html")

    return app


app = create_app() if os.environ.get("WB_NO_AUTOAPP") != "1" else None
