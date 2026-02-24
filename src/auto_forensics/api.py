from __future__ import annotations

import asyncio
import collections
import hashlib
import hmac
import json
import time
from pathlib import Path
from typing import Any

from .config import AppConfig
from .security import SecurityError, validate_case_id
from .service import AutoForensicsService

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


def create_app(config: AppConfig | None = None) -> FastAPI:
    if not FASTAPI_AVAILABLE:  # pragma: no cover
        raise RuntimeError("FastAPI is not installed. Install with: pip install -e .[server]")

    config = config or AppConfig.from_env()
    service = AutoForensicsService(config)
    api_guard = _api_key_guard(config)
    app = FastAPI(
        title="Auto Forensics Framework",
        version="1.0.0",
        docs_url=None if config.production else "/docs",
        redoc_url=None,
        openapi_url=None if config.production else "/openapi.json",
    )

    @app.exception_handler(HTTPException)
    async def structured_http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        error_code = _STATUS_CODES.get(exc.status_code, "error")
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": error_code,
                "detail": exc.detail,
                "status_code": exc.status_code,
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
    async def custom_404_handler(request: Request, exc: Any) -> JSONResponse:
        return JSONResponse(
            status_code=404,
            content={
                "error": "not_found",
                "detail": "The requested resource was not found.",
                "status_code": 404,
            },
        )

    # Restrict host header acceptance to expected hostnames.
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=config.trusted_hosts or ["127.0.0.1"])

    # CORS is opt-in only. Empty origins means same-origin dashboard/API.
    if config.allowed_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=config.allowed_origins,
            allow_credentials=False,
            allow_methods=["GET", "POST"],
            allow_headers=["Content-Type", "X-API-Key"],
        )

    recent_by_host: dict[str, collections.deque[float]] = {}
    rate_window_seconds = 60.0

    @app.middleware("http")
    async def rate_limit(request, call_next):  # type: ignore
        if config.rate_limit_per_minute > 0 and request.url.path.startswith("/api/"):
            host = request.client.host if request.client else "unknown"
            now = time.monotonic()
            queue = recent_by_host.setdefault(host, collections.deque())
            while queue and (now - queue[0]) > rate_window_seconds:
                queue.popleft()
            if len(queue) >= config.rate_limit_per_minute:
                return JSONResponse(
                    status_code=429,
                    content={"error": "rate_limited", "detail": "Rate limit exceeded.", "status_code": 429},
                )
            queue.append(now)
        return await call_next(request)

    @app.middleware("http")
    async def security_headers(request, call_next):  # type: ignore
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'"
        )
        return response

    @app.get("/api/health", response_class=JSONResponse)
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/admin/migrations", response_class=JSONResponse, dependencies=[Depends(api_guard)])
    async def migration_status() -> dict[str, Any]:
        return service.db_migration_status()

    @app.post("/api/admin/migrations", response_class=JSONResponse, dependencies=[Depends(api_guard)])
    async def run_migrations() -> dict[str, Any]:
        return service.run_db_migrations()

    @app.post("/api/admin/jobs/cleanup", response_class=JSONResponse, dependencies=[Depends(api_guard)])
    async def cleanup_jobs(body: JobCleanupRequest) -> dict[str, Any]:
        return service.cleanup_job_history(retention_days=body.retention_days)

    @app.post("/api/cases", response_class=JSONResponse, dependencies=[Depends(api_guard)])
    async def create_case(body: CaseCreateRequest) -> dict[str, Any]:
        try:
            return service.create_case(validate_case_id(body.case_id))
        except SecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/cases/import", response_class=JSONResponse, dependencies=[Depends(api_guard)])
    async def import_case(body: CaseImportRequest) -> dict[str, Any]:
        try:
            override = validate_case_id(body.case_id_override) if body.case_id_override else None
            return service.import_case_archive(Path(body.archive_path), case_id_override=override)
        except SecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/cases", response_class=JSONResponse, dependencies=[Depends(api_guard)])
    async def list_cases(
        q: str | None = Query(default=None, min_length=1, max_length=128),
        status: str | None = Query(default=None, pattern="^(created|ready|ingesting|analyzing|complete|failed)$"),
        limit: int = Query(default=200, ge=1, le=1000),
    ) -> list[dict[str, Any]]:
        return service.list_cases(query=q, status=status, limit=limit)

    @app.get("/api/stats", response_class=JSONResponse, dependencies=[Depends(api_guard)])
    async def case_stats() -> dict[str, Any]:
        return service.case_stats()

    @app.get("/api/cases/{case_id}", response_class=JSONResponse, dependencies=[Depends(api_guard)])
    async def get_case(case_id: str) -> dict[str, Any]:
        try:
            return service.case_overview(validate_case_id(case_id))
        except SecurityError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.delete("/api/cases/{case_id}", response_class=JSONResponse, dependencies=[Depends(api_guard)])
    async def delete_case(case_id: str) -> dict[str, Any]:
        """Permanently delete a case, all associated DB records, and on-disk data."""
        try:
            return service.delete_case(validate_case_id(case_id))
        except SecurityError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/api/cases/{case_id}/search", response_class=JSONResponse, dependencies=[Depends(api_guard)])
    async def search_case(case_id: str, q: str = Query(min_length=1), limit: int = Query(default=100, ge=1, le=500)):
        try:
            return service.search_case(validate_case_id(case_id), q, limit=limit)
        except SecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/cases/{case_id}/jobs", response_class=JSONResponse, dependencies=[Depends(api_guard)])
    async def list_case_jobs(
        case_id: str,
        job_type: str | None = Query(default=None, pattern="^(analysis|enrichment)$"),
        limit: int = Query(default=100, ge=1, le=500),
    ) -> list[dict[str, Any]]:
        try:
            return service.case_job_history(validate_case_id(case_id), job_type=job_type, limit=limit)
        except SecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/cases/{case_id}/ingest", response_class=JSONResponse, dependencies=[Depends(api_guard)])
    async def ingest_case(case_id: str, body: IngestRequest) -> dict[str, Any]:
        try:
            return service.ingest_case(validate_case_id(case_id), Path(body.source_dir))
        except SecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/cases/{case_id}/export", response_class=JSONResponse, dependencies=[Depends(api_guard)])
    async def export_case(case_id: str, body: CaseExportRequest) -> dict[str, Any]:
        try:
            return service.export_case_archive(validate_case_id(case_id), Path(body.destination_path))
        except SecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/cases/{case_id}/analyze", response_class=JSONResponse, dependencies=[Depends(api_guard)])
    async def analyze_case(case_id: str, body: AnalyzeRequest) -> dict[str, Any]:
        try:
            return service.analyze_case(validate_case_id(case_id), enable_llama=body.enable_llama)
        except SecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/cases/{case_id}/analyze/async", response_class=JSONResponse, dependencies=[Depends(api_guard)])
    async def analyze_case_async(case_id: str, body: AnalyzeRequest) -> dict[str, Any]:
        try:
            return service.analyze_case_async(validate_case_id(case_id), enable_llama=body.enable_llama)
        except SecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/cases/{case_id}/status", dependencies=[Depends(api_guard)])
    async def case_status(case_id: str, stream: bool = Query(default=False)):
        try:
            safe_case_id = validate_case_id(case_id)
        except SecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        if not stream:
            return JSONResponse(content=service.get_case_status(safe_case_id))

        async def event_stream():
            while True:
                status = service.get_case_status(safe_case_id)
                yield f"data: {json.dumps(status)}\n\n"
                if status.get("state") in {"complete", "failed", "not_found"}:
                    break
                await asyncio.sleep(1.0)

        return StreamingResponse(event_stream(), media_type="text/event-stream")

    @app.post("/api/cases/{case_id}/enrich/async", response_class=JSONResponse, dependencies=[Depends(api_guard)])
    async def enrich_case_async(case_id: str) -> dict[str, Any]:
        try:
            return service.enrich_case_iocs_async(validate_case_id(case_id))
        except SecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/cases/{case_id}/enrich/status", dependencies=[Depends(api_guard)])
    async def enrich_case_status(case_id: str, stream: bool = Query(default=False)):
        try:
            safe_case_id = validate_case_id(case_id)
        except SecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        if not stream:
            return JSONResponse(content=service.get_case_enrichment_status(safe_case_id))

        async def enrich_event_stream():
            while True:
                status = service.get_case_enrichment_status(safe_case_id)
                yield f"data: {json.dumps(status)}\n\n"
                if status.get("state") in {"complete", "failed", "not_found", "not_started"}:
                    break
                await asyncio.sleep(1.0)

        return StreamingResponse(enrich_event_stream(), media_type="text/event-stream")

    @app.get("/api/cases/{case_id}/notes", response_class=JSONResponse, dependencies=[Depends(api_guard)])
    async def list_notes(case_id: str) -> list[dict[str, Any]]:
        try:
            return service.list_case_notes(validate_case_id(case_id))
        except SecurityError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/api/cases/{case_id}/notes", response_class=JSONResponse, dependencies=[Depends(api_guard)])
    async def create_note(case_id: str, body: NoteCreateRequest) -> dict[str, Any]:
        try:
            return service.add_case_note(
                validate_case_id(case_id),
                content=body.content,
                author=body.author,
            )
        except SecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/cases/{case_id}/report", dependencies=[Depends(api_guard)])
    async def report(case_id: str, fmt: str = Query(default="json", pattern="^(json|md|html|navigator|stix)$")):
        try:
            payload = service.get_report(validate_case_id(case_id), fmt=fmt)
        except SecurityError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        if fmt in {"json", "navigator", "stix"}:
            media = "application/json"
        elif fmt == "md":
            media = "text/markdown"
        else:
            media = "text/html"
        return PlainTextResponse(content=payload, media_type=media)

    return app


def main(config: AppConfig | None = None) -> None:
    try:
        import uvicorn
    except Exception as exc:  # pragma: no cover
        raise SystemExit("uvicorn is required. Install with: pip install -e .[server]") from exc

    config = config or AppConfig.from_env()
    app = create_app(config)
    uvicorn.run(app, host=config.host, port=config.port, log_level="info")
