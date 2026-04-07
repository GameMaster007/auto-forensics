from __future__ import annotations

import asyncio
import collections
import hashlib
import hmac
import json
import logging
import secrets
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from .config import AppConfig
from .security import (
    SecurityError,
    confine_path,
    validate_case_id,
    validate_webhook_url,
)
from .service import AutoForensicsService

logger = logging.getLogger("auto_forensics.api")

FASTAPI_AVAILABLE = True
try:
    from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
    from fastapi.exception_handlers import http_exception_handler, request_validation_exception_handler
    from fastapi.exceptions import RequestValidationError
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.middleware.trustedhost import TrustedHostMiddleware
    from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse
    from pydantic import BaseModel, Field
except Exception:  # pragma: no cover - optional dependency path
    FASTAPI_AVAILABLE = False
    FastAPI = Any  # type: ignore
    Depends = Any  # type: ignore
    Header = Any  # type: ignore
    HTTPException = Exception  # type: ignore
    Query = Any  # type: ignore
    Request = Any  # type: ignore
    RequestValidationError = Exception  # type: ignore
    BaseModel = object  # type: ignore
    Field = lambda *args, **kwargs: None  # type: ignore
    CORSMiddleware = object  # type: ignore
    TrustedHostMiddleware = object  # type: ignore
    JSONResponse = object  # type: ignore
    PlainTextResponse = object  # type: ignore
    StreamingResponse = object  # type: ignore
    http_exception_handler = None  # type: ignore
    request_validation_exception_handler = None  # type: ignore


# Mapping of HTTP status codes to machine-readable error codes.
_STATUS_CODES: dict[int, str] = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    409: "conflict",
    422: "validation_error",
    429: "rate_limited",
    500: "internal_error",
}


class SettingsUpdateRequest(BaseModel):
    openai_endpoint: str | None = Field(
        default=None, max_length=2048
    )
    openai_api_key: str | None = Field(
        default=None, max_length=2048
    )
    llama_model: str | None = Field(
        default=None, max_length=256
    )
    virustotal_api_key: str | None = Field(
        default=None, max_length=512
    )
    abuseipdb_api_key: str | None = Field(
        default=None, max_length=512
    )


class CaseCreateRequest(BaseModel):
    case_id: str = Field(min_length=2, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$")


class IngestRequest(BaseModel):
    source_dir: str = Field(min_length=1, max_length=4096)


class AnalyzeRequest(BaseModel):
    enable_llama: bool = True


class NoteCreateRequest(BaseModel):
    content: str = Field(min_length=1, max_length=10000)
    author: str = Field(default="analyst", min_length=1, max_length=128)


class CaseExportRequest(BaseModel):
    destination_path: str = Field(min_length=1, max_length=4096)


class CaseImportRequest(BaseModel):
    archive_path: str = Field(min_length=1, max_length=4096)
    case_id_override: str | None = Field(default=None, min_length=2, max_length=64)


class JobCleanupRequest(BaseModel):
    retention_days: int | None = Field(default=None, ge=0, le=3650)


class WorkspaceViewRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    section: str = Field(default="overview", min_length=1, max_length=64)
    filters: dict[str, Any] = Field(default_factory=dict)
    sort: dict[str, Any] = Field(default_factory=dict)
    layout: dict[str, Any] = Field(default_factory=dict)
    view_id: str | None = Field(default=None, min_length=8, max_length=64)


class NotebookEntryCreateRequest(BaseModel):
    kind: str = Field(default="note", pattern="^(note|hypothesis|verdict|agent_summary)$")
    title: str = Field(min_length=1, max_length=200)
    body: str = Field(min_length=1, max_length=40000)
    links: dict[str, Any] = Field(default_factory=dict)


class NotebookEntryUpdateRequest(BaseModel):
    kind: str | None = Field(default=None, pattern="^(note|hypothesis|verdict|agent_summary)$")
    title: str | None = Field(default=None, min_length=1, max_length=200)
    body: str | None = Field(default=None, min_length=1, max_length=40000)
    links: dict[str, Any] | None = Field(default=None)


class AgentSessionCreateRequest(BaseModel):
    goal: str = Field(
        default="Investigate this case and prioritize the next analyst actions.",
        min_length=1,
        max_length=2000,
    )


class AgentSessionApproveRequest(BaseModel):
    action: str = Field(
        pattern="^(rerun_analysis|start_enrichment|generate_verdict|export_report_bundle)$"
    )


class ShareEventRequest(BaseModel):
    event: str = Field(pattern="^(share_clicked|share_copied)$")
    channel: str = Field(default="clipboard", min_length=1, max_length=64)


def _api_key_guard(config: AppConfig):
    async def guard(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
        if not config.api_key_hash:
            return
        if not x_api_key:
            raise HTTPException(status_code=401, detail="Missing API key.")
        incoming_hash = hashlib.sha256(x_api_key.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(incoming_hash, config.api_key_hash):
            raise HTTPException(status_code=401, detail="Invalid API key.")

    return guard


def create_app(config: AppConfig | None = None, service: AutoForensicsService | None = None) -> FastAPI:
    if not FASTAPI_AVAILABLE:  # pragma: no cover
        raise RuntimeError("FastAPI is not installed. Install with: pip install -e .[server]")

    config = config or AppConfig.from_env()
    app = FastAPI(
        title="Auto Forensics Framework",
        version="1.0.0",
        docs_url=None if config.production else "/docs",
        redoc_url=None,
        openapi_url=None if config.production else "/openapi.json",
    )

    # Service and guard are initialized eagerly for test compatibility,
    # but lifespan ensures proper startup/shutdown in production.
    _svc: list[AutoForensicsService | None] = [service]
    _guard: list[Any] = [None]

    def _init_service_and_guard() -> None:
        """Initialize service and guard if not already done."""
        if _svc[0] is None:
            _svc[0] = AutoForensicsService(config)
        if _guard[0] is None:
            _guard[0] = _api_key_guard(config)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """Manage service lifecycle: startup tasks and graceful shutdown."""
        _init_service_and_guard()
        _svc[0].startup()
        logger.info("Auto Forensics service started on %s:%d", config.host, config.port)
        yield
        logger.info("Auto Forensics service shutting down...")
        _svc[0].shutdown()

    app.router.lifespan_context = lifespan

    # Eager initialization for test client compatibility.
    _init_service_and_guard()

    # Helper to access service/guard from route handlers.
    def _get_svc() -> AutoForensicsService:
        s = _svc[0]
        if s is None:
            raise RuntimeError("Service not initialized. Ensure lifespan is active.")
        return s

    def _get_guard():
        g = _guard[0]
        if g is None:
            raise RuntimeError("API guard not initialized. Ensure lifespan is active.")
        return g

    @app.exception_handler(HTTPException)
    async def structured_http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        error_code = _STATUS_CODES.get(exc.status_code, "error")
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": error_code,
                "detail": exc.detail,
                "status_code": exc.status_code,
                "request_id": getattr(request.state, "request_id", None),
            },
        )

    @app.exception_handler(RequestValidationError)
    async def structured_validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        errors = exc.errors() if hasattr(exc, "errors") else []
        return JSONResponse(
            status_code=422,
            content={
                "error": "validation_error",
                "detail": "Request validation failed.",
                "status_code": 422,
                "validation_errors": [
                    {
                        "field": ".".join(str(loc) for loc in e.get("loc", [])),
                        "message": e.get("msg", ""),
                        "type": e.get("type", ""),
                    }
                    for e in errors
                ],
            },
        )

    @app.exception_handler(Exception)
    async def catch_all_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        import logging
        logger = logging.getLogger("auto_forensics.api")
        if isinstance(exc, HTTPException):
            return await structured_http_exception_handler(request, exc)
        
        logger.error("Unhandled exception: %s", exc, exc_info=True)
        return JSONResponse(
            status_code=500,
            content={
                "error": "internal_error",
                "detail": "An unexpected error occurred on the server.",
                "status_code": 500,
            },
        )

    @app.exception_handler(404)
    async def custom_404_handler(request: Request, exc: Any) -> Any:
        accept = request.headers.get("accept", "")
        if "text/html" in accept and not request.url.path.startswith("/api/"):
            # Redirect to root for browser users on non-API routes.
            from fastapi.responses import RedirectResponse
            return RedirectResponse(url="/")
            
        return JSONResponse(
            status_code=404,
            content={
                "error": "not_found",
                "detail": "The requested resource was not found.",
                "status_code": 404,
            },
        )

    # Serve dashboard if web directory exists.
    web_dir = Path(__file__).parent / "web"
    if web_dir.exists():
        _ASSET_MEDIA: dict[str, str] = {
            ".js":  "application/javascript",
            ".css": "text/css",
        }

        @app.get("/", include_in_schema=False)
        async def serve_dashboard():
            from fastapi.responses import HTMLResponse
            dashboard_file = web_dir / "dashboard.html"
            if dashboard_file.exists():
                return HTMLResponse(content=dashboard_file.read_text(encoding="utf-8"))
            return HTMLResponse(content="<h1>Dashboard file missing</h1>", status_code=404)

        @app.get("/assets/{filename}", include_in_schema=False)
        async def serve_asset(filename: str):
            # Only serve known static assets from the web directory.
            suffix = Path(filename).suffix
            if suffix not in _ASSET_MEDIA or "/" in filename or "\\" in filename:
                raise HTTPException(status_code=404, detail="Not found.")
            asset_path = web_dir / filename
            if not asset_path.exists() or not asset_path.is_file():
                raise HTTPException(status_code=404, detail="Not found.")
            return PlainTextResponse(
                content=asset_path.read_text(encoding="utf-8"),
                media_type=_ASSET_MEDIA[suffix],
            )

    # Restrict host header acceptance to expected hostnames.
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=config.trusted_hosts or ["127.0.0.1"])

    # CORS is opt-in only. Empty origins means same-origin dashboard/API.
    if config.allowed_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=config.allowed_origins,
            allow_credentials=False,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
            allow_headers=["Content-Type", "X-API-Key"],
        )

    # --- Rate limiter with TTL-based eviction to prevent memory exhaustion ---
    recent_by_host: dict[str, collections.deque[tuple[float, float]]] = {}
    rate_window_seconds = 60.0
    rate_limit_eviction_interval = 300.0  # Evict stale hosts every 5 minutes
    _last_rate_eviction = time.monotonic()

    @app.middleware("http")
    async def rate_limit(request: Request, call_next):  # type: ignore
        nonlocal _last_rate_eviction
        if config.rate_limit_per_minute > 0 and request.url.path.startswith("/api/"):
            host = request.client.host if request.client else "unknown"
            now = time.monotonic()

            # Periodic eviction of stale host entries.
            if now - _last_rate_eviction > rate_limit_eviction_interval:
                cutoff = now - rate_window_seconds
                stale_keys = [
                    k for k, q in recent_by_host.items()
                    if not q or (now - q[-1][1]) > rate_window_seconds * 2
                ]
                for k in stale_keys:
                    recent_by_host.pop(k, None)
                _last_rate_eviction = now

            queue = recent_by_host.setdefault(host, collections.deque())
            while queue and (now - queue[0][0]) > rate_window_seconds:
                queue.popleft()
            if len(queue) >= config.rate_limit_per_minute:
                return JSONResponse(
                    status_code=429,
                    content={"error": "rate_limited", "detail": "Rate limit exceeded.", "status_code": 429},
                )
            queue.append((now, now))
        return await call_next(request)

    @app.middleware("http")
    async def correlation_id_middleware(request: Request, call_next):  # type: ignore
        """Attach X-Request-ID for tracing across middleware → handler → service → DB."""
        request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex[:16]
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response

    @app.middleware("http")
    async def request_logging_middleware(request: Request, call_next):  # type: ignore
        """Log request method, path, and response status with timing."""
        start = time.monotonic()
        request_id = getattr(request.state, "request_id", "unknown")
        logger.info(
            "REQ %s %s [id=%s]",
            request.method,
            request.url.path,
            request_id,
        )
        response = await call_next(request)
        elapsed_ms = (time.monotonic() - start) * 1000
        logger.info(
            "RES %s %s %d %.0fms [id=%s]",
            request.method,
            request.url.path,
            response.status_code,
            elapsed_ms,
            request_id,
        )
        return response

    @app.middleware("http")
    async def security_headers(request: Request, call_next):  # type: ignore
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; "
            "style-src 'self' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; "
            "img-src 'self' data:; connect-src 'self'; "
            "frame-ancestors 'none'; base-uri 'self'"
        )
        return response

    @app.get("/api/health", response_class=JSONResponse)
    async def health() -> dict[str, Any]:
        """Health check with database connectivity verification for load balancers."""
        return _get_svc().health_check()

    @app.get("/api/admin/migrations", response_class=JSONResponse, dependencies=[Depends(_get_guard)])
    async def migration_status() -> dict[str, Any]:
        return _get_svc().db_migration_status()

    @app.post("/api/admin/migrations", response_class=JSONResponse, dependencies=[Depends(_get_guard)])
    async def run_migrations() -> dict[str, Any]:
        return _get_svc().run_db_migrations()

    @app.post("/api/admin/jobs/cleanup", response_class=JSONResponse, dependencies=[Depends(_get_guard)])
    async def cleanup_jobs(body: JobCleanupRequest) -> dict[str, Any]:
        return _get_svc().cleanup_job_history(retention_days=body.retention_days)

    @app.post("/api/cases", response_class=JSONResponse, dependencies=[Depends(_get_guard)])
    async def create_case(body: CaseCreateRequest) -> dict[str, Any]:
        try:
            return _get_svc().create_case(validate_case_id(body.case_id))
        except SecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/cases/import", response_class=JSONResponse, dependencies=[Depends(_get_guard)])
    async def import_case(body: CaseImportRequest) -> dict[str, Any]:
        try:
            # Validate archive_path is within allowed data directory to prevent
            # path traversal attacks
            archive_path = Path(body.archive_path).expanduser().resolve()
            data_root = _get_svc().config.data_dir
            confine_path(data_root, archive_path)
            override = validate_case_id(body.case_id_override) if body.case_id_override else None
            return _get_svc().import_case_archive(archive_path, case_id_override=override)
        except SecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/cases", response_class=JSONResponse, dependencies=[Depends(_get_guard)])
    async def list_cases(
        q: str | None = Query(default=None, min_length=1, max_length=128),
        status: str | None = Query(default=None, pattern="^(created|ready|ingesting|analyzing|complete|failed)$"),
        limit: int = Query(default=200, ge=1, le=1000),
    ) -> list[dict[str, Any]]:
        return _get_svc().list_cases(query=q, status=status, limit=limit)

    @app.get("/api/stats", response_class=JSONResponse, dependencies=[Depends(_get_guard)])
    async def case_stats() -> dict[str, Any]:
        return _get_svc().case_stats()

    @app.get("/api/cases/{case_id}", response_class=JSONResponse, dependencies=[Depends(_get_guard)])
    async def get_case(case_id: str) -> dict[str, Any]:
        try:
            return _get_svc().case_overview(validate_case_id(case_id))
        except SecurityError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/api/cases/{case_id}/artifacts", response_class=JSONResponse, dependencies=[Depends(_get_guard)])
    async def list_case_artifacts(
        case_id: str,
        page: int = Query(default=1, ge=1, le=10_000),
        page_size: int = Query(default=50, ge=1, le=200),
        artifact_type: str | None = Query(default=None, min_length=1, max_length=64),
        source: str | None = Query(default=None, min_length=1, max_length=4096),
        sort: str = Query(default="risk", pattern="^(risk|name|size)$"),
        search: str | None = Query(default=None, min_length=1, max_length=256),
    ) -> dict[str, Any]:
        try:
            return _get_svc().list_case_artifacts(
                validate_case_id(case_id),
                page=page,
                page_size=page_size,
                artifact_type=artifact_type,
                source=source,
                sort=sort,
                search=search,
            )
        except SecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/cases/{case_id}/timeline/query", response_class=JSONResponse, dependencies=[Depends(_get_guard)])
    async def query_case_timeline(
        case_id: str,
        after: str | None = Query(default=None),
        before: str | None = Query(default=None),
        min_risk: float | None = Query(default=None, ge=0, le=10_000),
        event_type: str | None = Query(default=None, min_length=1, max_length=128),
        keyword: str | None = Query(default=None, min_length=1, max_length=256),
        limit: int = Query(default=500, ge=1, le=10_000),
        view_name: str | None = Query(default=None, min_length=1, max_length=128),
    ) -> dict[str, Any]:
        try:
            return _get_svc().query_case_timeline(
                validate_case_id(case_id),
                after=after,
                before=before,
                min_risk=min_risk,
                event_type=event_type,
                keyword=keyword,
                limit=limit,
                view_name=view_name,
            )
        except SecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.delete("/api/cases/{case_id}", response_class=JSONResponse, dependencies=[Depends(_get_guard)])
    async def delete_case(case_id: str) -> dict[str, Any]:
        """Permanently delete a case, all associated DB records, and on-disk data."""
        try:
            return _get_svc().delete_case(validate_case_id(case_id))
        except SecurityError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/api/cases/{case_id}/search", response_class=JSONResponse, dependencies=[Depends(_get_guard)])
    async def search_case(case_id: str, q: str = Query(min_length=1), limit: int = Query(default=100, ge=1, le=500)):
        try:
            return _get_svc().search_case(validate_case_id(case_id), q, limit=limit)
        except SecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/cases/{case_id}/jobs", response_class=JSONResponse, dependencies=[Depends(_get_guard)])
    async def list_case_jobs(
        case_id: str,
        job_type: str | None = Query(default=None, pattern="^(analysis|enrichment)$"),
        limit: int = Query(default=100, ge=1, le=500),
    ) -> list[dict[str, Any]]:
        try:
            return _get_svc().case_job_history(validate_case_id(case_id), job_type=job_type, limit=limit)
        except SecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/cases/{case_id}/ingest", response_class=JSONResponse, dependencies=[Depends(_get_guard)])
    async def ingest_case(case_id: str, body: IngestRequest) -> dict[str, Any]:
        try:
            return _get_svc().ingest_case(validate_case_id(case_id), Path(body.source_dir))
        except SecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/cases/{case_id}/export", response_class=JSONResponse, dependencies=[Depends(_get_guard)])
    async def export_case(case_id: str, body: CaseExportRequest) -> dict[str, Any]:
        try:
            # Validate destination_path is within allowed data directory to prevent
            # path traversal attacks
            destination_path = Path(body.destination_path).expanduser().resolve()
            data_root = _get_svc().config.data_dir
            confine_path(data_root, destination_path)
            return _get_svc().export_case_archive(validate_case_id(case_id), destination_path)
        except SecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/cases/{case_id}/analyze", response_class=JSONResponse, dependencies=[Depends(_get_guard)])
    async def analyze_case(case_id: str, body: AnalyzeRequest) -> dict[str, Any]:
        try:
            return _get_svc().analyze_case(validate_case_id(case_id), enable_llama=body.enable_llama)
        except SecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/cases/{case_id}/analyze/async", response_class=JSONResponse, dependencies=[Depends(_get_guard)])
    async def analyze_case_async(case_id: str, body: AnalyzeRequest) -> dict[str, Any]:
        try:
            return _get_svc().analyze_case_async(validate_case_id(case_id), enable_llama=body.enable_llama)
        except SecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/cases/{case_id}/status", dependencies=[Depends(_get_guard)])
    async def case_status(case_id: str, stream: bool = Query(default=False)):
        try:
            safe_case_id = validate_case_id(case_id)
        except SecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        if not stream:
            return JSONResponse(content=_get_svc().get_case_status(safe_case_id))

        async def event_stream():
            """Stream status updates with client disconnect detection and max lifetime."""
            max_iterations = 600  # 10-minute maximum streaming lifetime
            iteration = 0
            try:
                while iteration < max_iterations:
                    iteration += 1
                    status = _get_svc().get_case_status(safe_case_id)
                    yield f"data: {json.dumps(status)}\n\n"
                    if status.get("state") in {"complete", "failed", "not_found"}:
                        break
                    await asyncio.sleep(1.0)
            except asyncio.CancelledError:
                logger.info("SSE status stream cancelled for case %s", safe_case_id)
                raise

        return StreamingResponse(
            event_stream(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    @app.post("/api/cases/{case_id}/enrich/async", response_class=JSONResponse, dependencies=[Depends(_get_guard)])
    async def enrich_case_async(case_id: str) -> dict[str, Any]:
        try:
            return _get_svc().enrich_case_iocs_async(validate_case_id(case_id))
        except SecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/cases/{case_id}/enrich/status", dependencies=[Depends(_get_guard)])
    async def enrich_case_status(case_id: str, stream: bool = Query(default=False)):
        try:
            safe_case_id = validate_case_id(case_id)
        except SecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        if not stream:
            return JSONResponse(content=_get_svc().get_case_enrichment_status(safe_case_id))

        async def enrich_event_stream():
            """Stream enrichment status with client disconnect detection and max lifetime."""
            max_iterations = 600  # 10-minute maximum streaming lifetime
            iteration = 0
            try:
                while iteration < max_iterations:
                    iteration += 1
                    status = _get_svc().get_case_enrichment_status(safe_case_id)
                    yield f"data: {json.dumps(status)}\n\n"
                    if status.get("state") in {"complete", "failed", "not_found", "not_started"}:
                        break
                    await asyncio.sleep(1.0)
            except asyncio.CancelledError:
                logger.info("SSE enrichment stream cancelled for case %s", safe_case_id)
                raise

        return StreamingResponse(
            enrich_event_stream(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    @app.get("/api/cases/{case_id}/notes", response_class=JSONResponse, dependencies=[Depends(_get_guard)])
    async def list_notes(
        case_id: str,
        limit: int = Query(default=200, ge=1, le=1000),
    ) -> list[dict[str, Any]]:
        try:
            return _get_svc().list_case_notes(validate_case_id(case_id), limit=limit)
        except SecurityError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/api/cases/{case_id}/views", response_class=JSONResponse, dependencies=[Depends(_get_guard)])
    async def list_views(
        case_id: str,
        limit: int = Query(default=200, ge=1, le=1000),
    ) -> list[dict[str, Any]]:
        try:
            return _get_svc().list_workspace_views(validate_case_id(case_id), limit=limit)
        except SecurityError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/api/cases/{case_id}/views", response_class=JSONResponse, dependencies=[Depends(_get_guard)])
    async def create_view(case_id: str, body: WorkspaceViewRequest) -> dict[str, Any]:
        try:
            return _get_svc().save_workspace_view(
                validate_case_id(case_id),
                name=body.name,
                section=body.section,
                filters=body.filters,
                sort=body.sort,
                layout=body.layout,
                view_id=body.view_id,
            )
        except SecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.delete("/api/cases/{case_id}/views/{view_id}", response_class=JSONResponse, dependencies=[Depends(_get_guard)])
    async def delete_view(case_id: str, view_id: str) -> dict[str, Any]:
        try:
            deleted = _get_svc().delete_workspace_view(validate_case_id(case_id), view_id)
            if not deleted:
                raise HTTPException(status_code=404, detail="Workspace view not found.")
            return {"deleted": True, "view_id": view_id}
        except SecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/cases/{case_id}/notebook", response_class=JSONResponse, dependencies=[Depends(_get_guard)])
    async def list_notebook_entries(
        case_id: str,
        limit: int = Query(default=200, ge=1, le=1000),
    ) -> list[dict[str, Any]]:
        try:
            return _get_svc().list_notebook_entries(validate_case_id(case_id), limit=limit)
        except SecurityError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/api/cases/{case_id}/notebook", response_class=JSONResponse, dependencies=[Depends(_get_guard)])
    async def create_notebook_entry(case_id: str, body: NotebookEntryCreateRequest) -> dict[str, Any]:
        try:
            return _get_svc().create_notebook_entry(
                validate_case_id(case_id),
                kind=body.kind,
                title=body.title,
                body=body.body,
                links=body.links,
            )
        except SecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.patch("/api/cases/{case_id}/notebook/{entry_id}", response_class=JSONResponse, dependencies=[Depends(_get_guard)])
    async def patch_notebook_entry(
        case_id: str,
        entry_id: str,
        body: NotebookEntryUpdateRequest,
    ) -> dict[str, Any]:
        try:
            return _get_svc().update_notebook_entry(
                validate_case_id(case_id),
                entry_id,
                title=body.title,
                body=body.body,
                kind=body.kind,
                links=body.links,
            )
        except SecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/cases/{case_id}/graph", response_class=JSONResponse, dependencies=[Depends(_get_guard)])
    async def get_case_graph(case_id: str) -> dict[str, Any]:
        try:
            return _get_svc().get_case_graph_data(validate_case_id(case_id))
        except SecurityError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/api/cases/{case_id}/agent/sessions", response_class=JSONResponse, dependencies=[Depends(_get_guard)])
    async def list_agent_sessions(case_id: str) -> list[dict[str, Any]]:
        try:
            return _get_svc().list_agent_sessions(validate_case_id(case_id))
        except SecurityError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/api/cases/{case_id}/agent/sessions", response_class=JSONResponse, dependencies=[Depends(_get_guard)])
    async def create_agent_session(case_id: str, body: AgentSessionCreateRequest) -> dict[str, Any]:
        try:
            result = _get_svc().start_agent_session(
                validate_case_id(case_id),
                goal=body.goal,
            )
            session = dict(result.get("session") or {})
            if session:
                result = dict(result)
                result.setdefault("session_id", session.get("session_id"))
                result.setdefault("status", session.get("status"))
                result.setdefault("goal", session.get("goal"))
            return result
        except SecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/cases/{case_id}/agent/sessions/{session_id}", response_class=JSONResponse, dependencies=[Depends(_get_guard)])
    async def get_agent_session(case_id: str, session_id: str) -> dict[str, Any]:
        try:
            return _get_svc().get_agent_session(validate_case_id(case_id), session_id)
        except SecurityError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/api/cases/{case_id}/agent/sessions/{session_id}/approve", response_class=JSONResponse, dependencies=[Depends(_get_guard)])
    async def approve_agent_session(
        case_id: str,
        session_id: str,
        body: AgentSessionApproveRequest,
    ) -> dict[str, Any]:
        try:
            return _get_svc().approve_agent_session(
                validate_case_id(case_id),
                session_id,
                action=body.action,
            )
        except SecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/cases/{case_id}/agent/sessions/{session_id}/cancel", response_class=JSONResponse, dependencies=[Depends(_get_guard)])
    async def cancel_agent_session(case_id: str, session_id: str) -> dict[str, Any]:
        try:
            return _get_svc().cancel_agent_session(validate_case_id(case_id), session_id)
        except SecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/cases/{case_id}/notes", response_class=JSONResponse, dependencies=[Depends(_get_guard)])
    async def create_note(case_id: str, body: NoteCreateRequest) -> dict[str, Any]:
        try:
            return _get_svc().add_case_note(
                validate_case_id(case_id),
                content=body.content,
                author=body.author,
            )
        except SecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get(
        "/api/cases/{case_id}/share/brief",
        response_class=JSONResponse,
        dependencies=[Depends(_get_guard)],
    )
    async def share_case_brief(case_id: str, request: Request) -> dict[str, Any]:
        try:
            return _get_svc().build_share_brief(
                validate_case_id(case_id),
                base_url=str(request.base_url).rstrip("/"),
            )
        except SecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post(
        "/api/cases/{case_id}/share/events",
        response_class=JSONResponse,
        dependencies=[Depends(_get_guard)],
    )
    async def track_share_event(
        case_id: str,
        body: ShareEventRequest,
    ) -> dict[str, Any]:
        try:
            return _get_svc().track_case_share_event(
                validate_case_id(case_id),
                event=body.event,
                channel=body.channel,
            )
        except SecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/cases/{case_id}/report", dependencies=[Depends(_get_guard)])
    async def report(
        case_id: str,
        fmt: str = Query(default="json", pattern="^(json|md|html|brief|navigator|stix)$"),
    ):
        try:
            payload = _get_svc().get_report(validate_case_id(case_id), fmt=fmt)
        except SecurityError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        if fmt in {"json", "navigator", "stix"}:
            media = "application/json"
        elif fmt in {"md", "brief"}:
            media = "text/markdown"
        else:
            media = "text/html"
        return PlainTextResponse(content=payload, media_type=media)

    # --- Settings persistence with async lock for concurrent access safety ---
    _settings_file = config.data_dir / "settings.json"
    _settings_lock = asyncio.Lock()
    _SETTINGS_KEYS = [
        "openai_endpoint", "openai_api_key", "llama_model",
        "virustotal_api_key", "abuseipdb_api_key",
    ]

    def _read_settings() -> dict[str, Any]:
        """Read persisted settings from disk."""
        if _settings_file.exists():
            try:
                return json.loads(
                    _settings_file.read_text(encoding="utf-8")
                )
            except (json.JSONDecodeError, OSError):
                pass
        return {}

    def _write_settings(data: dict[str, Any]) -> None:
        """Write settings to disk (atomic via tmp+rename)."""
        _settings_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = _settings_file.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(data, indent=2), encoding="utf-8"
        )
        tmp.replace(_settings_file)

    def _apply_settings(data: dict[str, Any]) -> None:
        """Push saved values into the live config + _get_svc()."""
        if data.get("openai_endpoint") is not None:
            config.openai_compatible_endpoint = (
                data["openai_endpoint"] or None
            )
        if data.get("openai_api_key") is not None:
            config.openai_api_key = data["openai_api_key"] or None
        if data.get("llama_model"):
            config.llama_model = data["llama_model"]
        if data.get("virustotal_api_key") is not None:
            config.virustotal_api_key = (
                data["virustotal_api_key"] or None
            )
        if data.get("abuseipdb_api_key") is not None:
            config.abuseipdb_api_key = (
                data["abuseipdb_api_key"] or None
            )

    # Apply saved settings on startup so they survive restarts.
    _apply_settings(_read_settings())

    @app.get("/api/settings", response_class=JSONResponse, dependencies=[Depends(_get_guard)])
    async def get_settings() -> dict[str, Any]:
        async with _settings_lock:
            saved = _read_settings()
        return {
            "openai_endpoint": saved.get(
                "openai_endpoint",
                config.openai_compatible_endpoint,
            ),
            "openai_api_key": saved.get(
                "openai_api_key",
                config.openai_api_key,
            ),
            "llama_model": saved.get(
                "llama_model", config.llama_model
            ),
            "virustotal_api_key": saved.get(
                "virustotal_api_key",
                config.virustotal_api_key,
            ),
            "abuseipdb_api_key": saved.get(
                "abuseipdb_api_key",
                config.abuseipdb_api_key,
            ),
            "data_dir": str(config.data_dir),
        }

    @app.put("/api/settings", response_class=JSONResponse, dependencies=[Depends(_get_guard)])
    async def update_settings(body: SettingsUpdateRequest) -> dict[str, Any]:
        async with _settings_lock:
            saved = _read_settings()
            updates = body.model_dump(exclude_unset=False)
            for key in _SETTINGS_KEYS:
                if key in updates:
                    saved[key] = updates[key]
            _write_settings(saved)
            _apply_settings(saved)
        return {"status": "ok"}

    # --- Threat Intelligence endpoints ---
    class _TILookupR(BaseModel):
        ioc_type: str = Field(min_length=1, max_length=64)
        value: str = Field(min_length=1, max_length=4096)

    @app.post("/api/ti/lookup", response_class=JSONResponse, dependencies=[Depends(_get_guard)])
    async def ti_lookup(body: _TILookupR) -> dict:
        result = _get_svc().lookup_ti_ioc(body.ioc_type, body.value)
        return {"found": result is not None, "record": result}

    @app.post("/api/ti/update", response_class=JSONResponse, dependencies=[Depends(_get_guard)])
    async def ti_update() -> dict:
        return _get_svc().update_ti_feeds()

    @app.get("/api/ti/status", response_class=JSONResponse, dependencies=[Depends(_get_guard)])
    async def ti_status() -> dict:
        return _get_svc().get_ti_feed_status()

    @app.post(
        "/api/cases/{case_id}/ti-enrich",
        response_class=JSONResponse, dependencies=[Depends(_get_guard)]
    )
    async def case_ti_enrich(case_id: str) -> dict:
        try:
            return _get_svc().enrich_case_with_ti(validate_case_id(case_id))
        except SecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    # --- Case comparison endpoints ---
    class _CaseCompareR(BaseModel):
        case_b_id: str = Field(min_length=2, max_length=64)
        diff_type: str = Field(default="all", pattern="^(all|common_only|diff_only)$")

    @app.post(
        "/api/cases/{case_id}/compare",
        response_class=JSONResponse, dependencies=[Depends(_get_guard)]
    )
    async def compare_case(case_id: str, body: _CaseCompareR) -> dict:
        try:
            return _get_svc().compare_cases(
                validate_case_id(case_id),
                validate_case_id(body.case_b_id),
                body.diff_type,
            )
        except SecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    # --- Alert endpoints ---
    class _AlertRuleR(BaseModel):
        rule_id: str = Field(min_length=1, max_length=64)
        name: str = Field(min_length=1, max_length=128)
        description: str = Field(default="", max_length=512)
        condition_type: str = Field(
            default="severity_threshold",
            pattern="^(severity_threshold|finding_count|risk_score|critical_ioc)$",
        )
        threshold: str = Field(default="high", max_length=64)

    @app.get("/api/alerts/rules", response_class=JSONResponse, dependencies=[Depends(_get_guard)])
    async def list_alert_rules() -> list[dict]:
        return _get_svc().list_alert_rules()

    @app.post("/api/alerts/rules", response_class=JSONResponse, dependencies=[Depends(_get_guard)])
    async def create_alert_rule(body: _AlertRuleR) -> dict:
        rule = {
            "rule_id": body.rule_id,
            "name": body.name,
            "description": body.description,
            "trigger_condition": {
                "type": body.condition_type,
                "threshold": body.threshold,
            },
        }
        ok = _get_svc().add_alert_rule(rule)
        return {"created": ok, "rule_id": body.rule_id}

    @app.delete(
        "/api/alerts/rules/{rule_id}",
        response_class=JSONResponse, dependencies=[Depends(_get_guard)]
    )
    async def delete_alert_rule(rule_id: str) -> dict:
        ok = _get_svc().remove_alert_rule(rule_id)
        return {"deleted": ok, "rule_id": rule_id}

    @app.post(
        "/api/cases/{case_id}/alerts/eval",
        response_class=JSONResponse, dependencies=[Depends(_get_guard)]
    )
    async def eval_case_alerts(case_id: str) -> list[dict]:
        try:
            return _get_svc().run_alert_evaluation(validate_case_id(case_id))
        except SecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/alerts/test-webhook", response_class=JSONResponse, dependencies=[Depends(_get_guard)])
    async def test_webhook(url: str = Query(min_length=1, max_length=2048)) -> dict:
        try:
            # Validate URL to prevent SSRF attacks
            require_https = _get_svc().config.production
            validate_webhook_url(url, require_https=require_https)
            ok = _get_svc().test_webhook(url)
            return {"success": ok, "url": url}
        except SecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    return app


def main(config: AppConfig | None = None) -> None:
    try:
        import uvicorn
    except Exception as exc:  # pragma: no cover
        raise SystemExit("uvicorn is required. Install with: pip install -e .[server]") from exc

    config = config or AppConfig.from_env()
    app = create_app(config)
    uvicorn.run(app, host=config.host, port=config.port, log_level="info")
