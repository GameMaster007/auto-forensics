from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
import hashlib
import json
import logging
import os
import shutil
import threading
import time
import zipfile
import tempfile
import uuid
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

from .case_manager import CaseManager
from .config import AppConfig
from .db_backend import DatabaseBackend
from .db import Database
from .db_sqlalchemy import SQLAlchemyDatabase
from .investigation import (
    build_agent_recommendations,
    build_artifact_previews,
    build_case_brief_markdown,
    build_case_graph,
    build_case_threads,
    risk_level,
)
from .ioc_enrichment import EnrichmentConfig, enabled_providers, enrich_ioc
from .models import IOC, IOCEnrichment, utc_now_iso
from .pipeline import PipelineConfig, run_case
from .plugins import PluginRegistry
from .security import (
    SecurityError,
    confine_path,
    sha256_file,
    validate_case_id,
    walk_case_directory,
)

# Optional imports for new features
try:
    from .ti_feeds import TIFeedConfig, TIFeedManager
except ImportError:
    TIFeedConfig = None  # type: ignore[misc]
    TIFeedManager = None  # type: ignore[misc]

try:
    from .case_diff import CaseDiffer, DiffType
except ImportError:
    CaseDiffer = None  # type: ignore[misc]
    DiffType = None  # type: ignore[misc]

try:
    from .alerts import AlertManager, AlertRule, AlertSeverity
except ImportError:
    AlertManager = None  # type: ignore[misc]
    AlertRule = None  # type: ignore[misc]
    AlertSeverity = None  # type: ignore[misc]


class AutoForensicsService:
    _ACTIVE_JOB_STATES = {"queued", "running"}
    _RECOVERY_MESSAGE = "Recovered interrupted work after service restart."

    def __init__(self, config: AppConfig):
        self.config = config
        self.config.ensure_dirs()
        if config.database_url and "://" in config.database_url:
            self.db: DatabaseBackend = SQLAlchemyDatabase(
                config.database_url,
                pool_size=config.db_pool_size,
                max_overflow=config.db_max_overflow,
                pool_timeout_seconds=config.db_pool_timeout_seconds,
                pool_recycle_seconds=config.db_pool_recycle_seconds,
            )
        else:
            self.db = Database(config.database_url or config.db_path)
        self.case_manager = CaseManager(config.cases_dir, config.security_policy)
        self._analysis_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="auto-forensics")
        self._enrichment_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="auto-forensics-enrich")
        self._agent_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="auto-forensics-agent")
        self._analysis_jobs: dict[str, Future[dict[str, Any]]] = {}
        self._analysis_status: dict[str, dict[str, Any]] = {}
        self._analysis_job_ids: dict[str, str] = {}
        self._enrichment_jobs: dict[str, Future[dict[str, Any]]] = {}
        self._enrichment_status: dict[str, dict[str, Any]] = {}
        self._enrichment_job_ids: dict[str, str] = {}
        self._agent_jobs: dict[str, Future[dict[str, Any]]] = {}
        self._agent_status: dict[str, dict[str, Any]] = {}
        self._analysis_lock = threading.Lock()
        self._enrichment_lock = threading.Lock()
        self._agent_lock = threading.Lock()
        self._shutdown = False

    def startup(self) -> None:
        """Run async-safe startup tasks after the service is fully constructed."""
        try:
            self.cleanup_job_history(retention_days=self.config.job_retention_days)
        except Exception as exc:
            logger.warning("Job history cleanup failed on init: %s", exc)
        try:
            recovery = self.recover_interrupted_work()
            if any(recovery.values()):
                logger.warning(
                    "Recovered interrupted work on startup: %s",
                    recovery,
                )
        except Exception as exc:
            logger.warning("Startup recovery failed: %s", exc)

    def health_check(self) -> dict[str, Any]:
        """Verify database connectivity for load balancer health checks."""
        try:
            self.db.get_schema_version()
            return {"status": "ok", "db": "connected"}
        except Exception as exc:
            return {"status": "degraded", "db": f"error: {exc}"}

    def shutdown(self) -> None:
        if self._shutdown:
            return
        self._shutdown = True
        self._analysis_executor.shutdown(wait=False)
        self._enrichment_executor.shutdown(wait=False)
        self._agent_executor.shutdown(wait=False)

    def run_db_migrations(self) -> dict[str, Any]:
        return self.db.run_migrations()

    def db_migration_status(self) -> dict[str, Any]:
        version = int(self.db.get_schema_version())
        history = list(self.db.list_schema_migrations())
        return {
            "current_version": version,
            "history": history,
        }

    def _trim_local_job_state(self) -> dict[str, int]:
        trimmed_analysis = 0
        trimmed_enrichment = 0
        trimmed_agent = 0
        with self._analysis_lock:
            for case_id, future in list(self._analysis_jobs.items()):
                if future.done():
                    self._analysis_jobs.pop(case_id, None)
                    trimmed_analysis += 1
        with self._enrichment_lock:
            for case_id, future in list(self._enrichment_jobs.items()):
                if future.done():
                    self._enrichment_jobs.pop(case_id, None)
                    trimmed_enrichment += 1
        with self._agent_lock:
            for session_id, future in list(self._agent_jobs.items()):
                if future.done():
                    self._agent_jobs.pop(session_id, None)
                    trimmed_agent += 1
        return {
            "trimmed_analysis_futures": trimmed_analysis,
            "trimmed_enrichment_futures": trimmed_enrichment,
            "trimmed_agent_futures": trimmed_agent,
        }

    def cleanup_job_history(self, retention_days: int | None = None) -> dict[str, Any]:
        effective_days = self.config.job_retention_days if retention_days is None else retention_days
        effective_days = max(0, int(effective_days))
        removed_analysis = self.db.cleanup_analysis_jobs(effective_days, job_type="analysis")
        removed_enrichment = self.db.cleanup_analysis_jobs(effective_days, job_type="enrichment")
        local = self._trim_local_job_state()
        return {
            "retention_days": effective_days,
            "removed_analysis_jobs": removed_analysis,
            "removed_enrichment_jobs": removed_enrichment,
            **local,
        }

    def recover_interrupted_work(self) -> dict[str, int]:
        """Mark jobs from a previous process that never finished cleanly.
        Limited to the 50 most recently active cases to avoid blocking startup.
        """
        recovered_analysis = 0
        recovered_enrichment = 0
        recovered_agent_sessions = 0

        all_cases = self.db.list_cases()
        # Sort by updated_at descending to recover most recent work first.
        all_cases.sort(
            key=lambda c: str(c.get("updated_at") or ""),
            reverse=True,
        )
        # Cap to avoid blocking startup on large deployments.
        cases_to_check = all_cases[:50]

        for case in cases_to_check:
            case_id = str(case.get("case_id") or "")
            if not case_id:
                continue

            analysis_failed = False
            case_analysis_recovered = 0
            case_enrichment_recovered = 0
            case_agent_recovered = 0
            for job in self.db.list_case_jobs(case_id, job_type="analysis", limit=1000):
                state = str(job.get("state") or "").lower()
                if state not in self._ACTIVE_JOB_STATES:
                    continue
                self.db.upsert_analysis_job(
                    job_id=str(job.get("job_id") or ""),
                    case_id=case_id,
                    job_type="analysis",
                    state="failed",
                    progress=100,
                    message="Analysis interrupted by service restart.",
                    error=self._RECOVERY_MESSAGE,
                    result=job.get("result"),
                )
                analysis_failed = True
                recovered_analysis += 1
                case_analysis_recovered += 1

            for job in self.db.list_case_jobs(case_id, job_type="enrichment", limit=1000):
                state = str(job.get("state") or "").lower()
                if state not in self._ACTIVE_JOB_STATES:
                    continue
                self.db.upsert_analysis_job(
                    job_id=str(job.get("job_id") or ""),
                    case_id=case_id,
                    job_type="enrichment",
                    state="failed",
                    progress=100,
                    message="IOC enrichment interrupted by service restart.",
                    error=self._RECOVERY_MESSAGE,
                    result=job.get("result"),
                )
                recovered_enrichment += 1
                case_enrichment_recovered += 1

            for session in self.db.list_agent_sessions(case_id):
                status = str(session.get("status") or "").lower()
                if status not in self._ACTIVE_JOB_STATES:
                    continue
                session_id = str(session.get("session_id") or "")
                if not session_id:
                    continue
                self.db.update_agent_session(
                    session_id,
                    status="failed",
                    summary=(
                        "Agent session was interrupted by a service restart."
                    ),
                    error=self._RECOVERY_MESSAGE,
                    completed_at=utc_now_iso(),
                )
                recovered_agent_sessions += 1
                case_agent_recovered += 1

            if analysis_failed or case_enrichment_recovered or case_agent_recovered:
                if analysis_failed:
                    self.db.set_case_status(
                        case_id,
                        "failed",
                        "Analysis interrupted by service restart.",
                    )
                self.db.append_audit_log(
                    action="job_recovered",
                    actor="system",
                    case_id=case_id,
                    details={
                        "message": self._RECOVERY_MESSAGE,
                        "analysis_jobs": case_analysis_recovered,
                        "enrichment_jobs": case_enrichment_recovered,
                        "agent_sessions": case_agent_recovered,
                    },
                )

        return {
            "analysis_jobs": recovered_analysis,
            "enrichment_jobs": recovered_enrichment,
            "agent_sessions": recovered_agent_sessions,
        }

    def case_job_history(
        self,
        case_id: str,
        job_type: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        case_id = validate_case_id(case_id)
        self.require_case(case_id)
        clean_type = job_type.strip().lower() if isinstance(job_type, str) and job_type.strip() else None
        if clean_type not in {None, "analysis", "enrichment"}:
            raise SecurityError("job_type must be 'analysis', 'enrichment', or omitted.")
        return self.db.list_case_jobs(case_id, job_type=clean_type, limit=max(1, min(500, int(limit))))

    def create_case(self, case_id: str) -> dict[str, Any]:
        case_id = validate_case_id(case_id)
        existing = self.db.get_case(case_id)
        if existing:
            return existing
        evidence_dir, output_dir = self.case_manager.init_case_dirs(case_id)
        self.db.create_case(case_id, evidence_dir=evidence_dir, output_dir=output_dir)
        self.db.append_audit_log(
            action="case_created",
            actor="system",
            details={"evidence_dir": str(evidence_dir), "output_dir": str(output_dir)},
            case_id=case_id,
        )
        return self.require_case(case_id)

    def list_cases(
        self,
        query: str | None = None,
        status: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        items = self.db.list_cases()
        clean_query = (query or "").strip().lower()
        clean_status = (status or "").strip().lower()
        allowed_statuses = {"created", "ready", "ingesting", "analyzing", "complete", "failed"}
        if clean_status and clean_status not in allowed_statuses:
            raise SecurityError(
                "status must be one of: created, ready, ingesting, analyzing, complete, failed."
            )
        if clean_status:
            items = [item for item in items if str(item.get("status", "")).lower() == clean_status]
        if clean_query:
            filtered: list[dict[str, Any]] = []
            for item in items:
                blob = " ".join(
                    [
                        str(item.get("case_id", "")),
                        str(item.get("status", "")),
                        str(item.get("last_error", "") or ""),
                    ]
                ).lower()
                if clean_query in blob:
                    filtered.append(item)
            items = filtered
        limit = max(1, min(1000, int(limit)))
        return items[:limit]

    def case_stats(self) -> dict[str, Any]:
        items = self.db.list_cases()
        by_status: dict[str, int] = {}
        for case in items:
            key = str(case.get("status") or "unknown")
            by_status[key] = by_status.get(key, 0) + 1
        newest_updated_at = None
        if items:
            newest_updated_at = max(str(item.get("updated_at", "") or "") for item in items) or None
        return {
            "total_cases": len(items),
            "by_status": by_status,
            "active_cases": by_status.get("ingesting", 0) + by_status.get("analyzing", 0),
            "failed_cases": by_status.get("failed", 0),
            "newest_updated_at": newest_updated_at,
        }

    def require_case(self, case_id: str) -> dict[str, Any]:
        case_id = validate_case_id(case_id)
        value = self.db.get_case(case_id)
        if not value:
            raise SecurityError(f"Case not found: {case_id}")
        return value

    def ingest_case(self, case_id: str, source_dir: Path) -> dict[str, Any]:
        case = self.require_case(case_id)
        source_dir = self._validate_ingest_source(source_dir)
        self.db.set_case_status(case_id, "ingesting", None)
        try:
            entries = self.case_manager.ingest_directory(case_id, source_dir)
            self.db.replace_artifacts(
                case_id,
                [
                    {
                        "rel_path": entry.rel_path,
                        "artifact_type": entry.artifact_type,
                        "size_bytes": entry.size_bytes,
                        "sha256": entry.sha256,
                        "metadata": entry.metadata,
                    }
                    for entry in entries
                ],
            )
            self.db.append_evidence_hash_log(
                case_id,
                [
                    {
                        "rel_path": entry.rel_path,
                        "sha256": entry.sha256,
                        "size_bytes": entry.size_bytes,
                    }
                    for entry in entries
                ],
            )
            self.db.append_audit_log(
                action="case_ingested",
                actor="system",
                details={"ingested_files": len(entries), "source_dir": str(source_dir)},
                case_id=case_id,
            )
            self.db.set_case_status(case_id, "ready", None)
        except Exception as exc:
            self.db.set_case_status(case_id, "failed", str(exc))
            raise
        return {
            "case": case_id,
            "evidence_dir": case["evidence_dir"],
            "ingested_files": len(entries),
        }

    def _validate_ingest_source(self, source_dir: Path) -> Path:
        resolved = source_dir.expanduser().resolve()
        if not self.config.allowed_ingest_roots:
            return resolved
        for root in self.config.allowed_ingest_roots:
            try:
                resolved.relative_to(root)
                return resolved
            except ValueError:
                continue
        raise SecurityError(
            f"Source directory is outside allowed ingest roots: {resolved}"
        )

    def _enrichment_config(self) -> EnrichmentConfig:
        return EnrichmentConfig(
            virustotal_api_key=self.config.virustotal_api_key,
            malwarebazaar_api_key=self.config.malwarebazaar_api_key,
            abuseipdb_api_key=self.config.abuseipdb_api_key,
            enable_whois_lookup=self.config.enable_whois_lookup,
            http_retries=self.config.enrichment_http_retries,
            backoff_base_seconds=self.config.enrichment_backoff_base_seconds,
            backoff_max_seconds=self.config.enrichment_backoff_max_seconds,
        )

    def _enrich_iocs_with_cache(self, iocs: list[IOC]) -> list[IOCEnrichment]:
        cfg = self._enrichment_config()
        providers = enabled_providers(cfg)
        if not providers:
            return []

        output: list[IOCEnrichment] = []
        for ioc in iocs:
            cached_providers: set[str] = set()
            for provider in providers:
                cached = self.db.get_cached_ioc_enrichment(
                    ioc_type=ioc.ioc_type,
                    value=ioc.value,
                    provider=provider,
                    ttl_minutes=self.config.enrichment_cache_ttl_minutes,
                )
                if cached is None:
                    continue
                cached.ioc_id = ioc.ioc_id
                output.append(cached)
                cached_providers.add(provider)

            if len(cached_providers) == len(providers):
                continue

            for fresh in enrich_ioc(ioc, cfg):
                if fresh.provider in cached_providers:
                    continue
                self.db.upsert_ioc_enrichment_cache(ioc.ioc_type, ioc.value, fresh)
                output.append(fresh)

        return output

    def _set_analysis_status(
        self,
        case_id: str,
        job_id: str,
        state: str,
        progress: int,
        message: str,
        error: str | None = None,
        result: dict[str, Any] | None = None,
    ) -> None:
        payload = {
            "case_id": case_id,
            "job_id": job_id,
            "state": state,
            "progress": max(0, min(100, int(progress))),
            "message": message,
            "error": error,
        }
        if result is not None:
            payload["result"] = result
        with self._analysis_lock:
            self._analysis_status[case_id] = payload
            self._analysis_job_ids[case_id] = job_id
        self.db.upsert_analysis_job(
            job_id=job_id,
            case_id=case_id,
            job_type="analysis",
            state=payload["state"],
            progress=payload["progress"],
            message=payload["message"],
            error=payload["error"],
            result=payload.get("result"),
        )

    def _set_enrichment_status(
        self,
        case_id: str,
        job_id: str,
        state: str,
        progress: int,
        message: str,
        error: str | None = None,
        result: dict[str, Any] | None = None,
    ) -> None:
        payload = {
            "case_id": case_id,
            "job_id": job_id,
            "state": state,
            "progress": max(0, min(100, int(progress))),
            "message": message,
            "error": error,
        }
        if result is not None:
            payload["result"] = result

        with self._enrichment_lock:
            self._enrichment_status[case_id] = payload
            self._enrichment_job_ids[case_id] = job_id

        self.db.upsert_analysis_job(
            job_id=job_id,
            case_id=case_id,
            job_type="enrichment",
            state=payload["state"],
            progress=payload["progress"],
            message=payload["message"],
            error=payload["error"],
            result=payload.get("result"),
        )

    def get_case_enrichment_status(self, case_id: str) -> dict[str, Any]:
        case_id = validate_case_id(case_id)
        with self._enrichment_lock:
            cached = self._enrichment_status.get(case_id)
            if cached:
                return dict(cached)
            job = self._enrichment_jobs.get(case_id)
            job_id = self._enrichment_job_ids.get(case_id)
            if job is not None and not job.done():
                return {
                    "case_id": case_id,
                    "job_id": job_id,
                    "state": "running",
                    "progress": 50,
                    "message": "IOC enrichment in progress",
                    "error": None,
                }

        db_job = self.db.get_case_latest_job(case_id, job_type="enrichment")
        if db_job is not None:
            return db_job

        case = self.db.get_case(case_id)
        if not case:
            return {
                "case_id": case_id,
                "job_id": None,
                "state": "not_found",
                "progress": 0,
                "message": "Case not found",
                "error": "case_not_found",
            }
        return {
            "case_id": case_id,
            "job_id": None,
            "state": "not_started",
            "progress": 0,
            "message": "IOC enrichment has not started",
            "error": None,
        }

    def _serialize_enrichments(self, enrichments: list[IOCEnrichment]) -> list[dict[str, Any]]:
        return [
            {
                "enrichment_id": e.enrichment_id,
                "ioc_id": e.ioc_id,
                "provider": e.provider,
                "verdict": e.verdict,
                "confidence": e.confidence,
                "details": e.details,
                "fetched_at": e.fetched_at,
            }
            for e in enrichments
        ]

    def _run_enrichment_for_case(self, case_id: str, job_id: str) -> dict[str, Any]:
        self._set_enrichment_status(
            case_id,
            job_id=job_id,
            state="running",
            progress=10,
            message="Loading case IOCs",
        )
        ioc_rows = self.db.get_case_iocs(case_id)
        iocs: list[IOC] = []
        for row in ioc_rows:
            iocs.append(
                IOC(
                    ioc_id=str(row.get("ioc_id", "")),
                    ioc_type=str(row.get("ioc_type", "")),
                    value=str(row.get("value", "")),
                    first_seen=row.get("first_seen"),
                    last_seen=row.get("last_seen"),
                    sources=list(row.get("sources", [])),
                    metadata=dict(row.get("metadata", {})),
                )
            )

        self._set_enrichment_status(
            case_id,
            job_id=job_id,
            state="running",
            progress=40,
            message="Enriching IOCs with cache/providers",
        )
        enrichments = self._enrich_iocs_with_cache(iocs)

        case = self.require_case(case_id)
        output_dir = Path(case["output_dir"])
        report_path = output_dir / "case_report.json"
        payload: dict[str, Any] = {}
        if report_path.exists():
            try:
                raw = json.loads(report_path.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    payload = raw
            except json.JSONDecodeError:
                payload = {}

        payload["ioc_enrichments"] = self._serialize_enrichments(enrichments)
        summary_obj = payload.get("summary")
        if not isinstance(summary_obj, dict):
            summary_obj = {}
        summary_obj["ioc_enrichment_count"] = len(enrichments)
        payload["summary"] = summary_obj
        report_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

        self.db.append_audit_log(
            action="case_ioc_enriched",
            actor="system",
            details={"ioc_count": len(iocs), "ioc_enrichment_count": len(enrichments)},
            case_id=case_id,
        )
        result = {
            "case_id": case_id,
            "ioc_count": len(iocs),
            "ioc_enrichment_count": len(enrichments),
        }
        self._set_enrichment_status(
            case_id,
            job_id=job_id,
            state="complete",
            progress=100,
            message="IOC enrichment complete",
            result=result,
        )
        return result

    def enrich_case_iocs_async(self, case_id: str) -> dict[str, Any]:
        case_id = validate_case_id(case_id)
        self.require_case(case_id)
        job_id = f"enrich-{uuid.uuid4().hex[:16]}"

        placeholder: Future[dict[str, Any]] = Future()
        with self._enrichment_lock:
            existing = self._enrichment_jobs.get(case_id)
            if existing is not None and not existing.done():
                return {
                    "case_id": case_id,
                    "accepted": False,
                    "detail": "IOC enrichment already running.",
                    "status": self._enrichment_status.get(case_id),
                }
            self._enrichment_jobs[case_id] = placeholder  # claim slot atomically

        self._set_enrichment_status(
            case_id,
            job_id=job_id,
            state="queued",
            progress=0,
            message="IOC enrichment queued",
        )

        def run_job() -> dict[str, Any]:
            try:
                return self._run_enrichment_for_case(case_id, job_id)
            except Exception as exc:
                self._set_enrichment_status(
                    case_id,
                    job_id=job_id,
                    state="failed",
                    progress=100,
                    message="IOC enrichment failed",
                    error=str(exc),
                )
                raise

        future = self._enrichment_executor.submit(run_job)
        with self._enrichment_lock:
            self._enrichment_jobs[case_id] = future  # replace placeholder
            self._enrichment_job_ids[case_id] = job_id
        return {
            "case_id": case_id,
            "job_id": job_id,
            "accepted": True,
            "detail": "IOC enrichment started.",
            "status": self.get_case_enrichment_status(case_id),
        }

    def get_case_status(self, case_id: str) -> dict[str, Any]:
        case_id = validate_case_id(case_id)
        with self._analysis_lock:
            cached = self._analysis_status.get(case_id)
            if cached:
                return dict(cached)
            job = self._analysis_jobs.get(case_id)
            job_id = self._analysis_job_ids.get(case_id)
            if job is not None and not job.done():
                return {
                    "case_id": case_id,
                    "job_id": job_id,
                    "state": "running",
                    "progress": 50,
                    "message": "Analysis in progress",
                    "error": None,
                }

        db_job = self.db.get_case_latest_job(case_id, job_type="analysis")
        if db_job is not None:
            return db_job

        case = self.db.get_case(case_id)
        if not case:
            return {
                "case_id": case_id,
                "job_id": None,
                "state": "not_found",
                "progress": 0,
                "message": "Case not found",
                "error": "case_not_found",
            }

        status = str(case.get("status") or "created")
        progress_map = {
            "created": 0,
            "ready": 20,
            "ingesting": 10,
            "analyzing": 50,
            "complete": 100,
            "failed": 100,
        }
        return {
            "case_id": case_id,
            "job_id": self._analysis_job_ids.get(case_id),
            "state": status,
            "progress": progress_map.get(status, 0),
            "message": f"Case status is {status}",
            "error": case.get("last_error"),
        }

    def analyze_case_async(self, case_id: str, enable_llama: bool = True) -> dict[str, Any]:
        case_id = validate_case_id(case_id)
        self.require_case(case_id)
        job_id = f"job-{uuid.uuid4().hex[:16]}"
        placeholder: Future[dict[str, Any]] = Future()
        with self._analysis_lock:
            existing = self._analysis_jobs.get(case_id)
            if existing is not None and not existing.done():
                return {
                    "case_id": case_id,
                    "accepted": False,
                    "detail": "Analysis already running.",
                    "status": self._analysis_status.get(case_id),
                }
            self._analysis_jobs[case_id] = placeholder  # claim slot atomically

        self._set_analysis_status(
            case_id,
            job_id=job_id,
            state="queued",
            progress=0,
            message="Analysis queued",
        )

        def run_job() -> dict[str, Any]:
            def progress(state: str, progress_value: int, message: str) -> None:
                self._set_analysis_status(
                    case_id,
                    job_id=job_id,
                    state=state,
                    progress=progress_value,
                    message=message,
                )

            try:
                result = self.analyze_case(case_id, enable_llama=enable_llama, progress_callback=progress)
            except Exception as exc:
                self._set_analysis_status(
                    case_id,
                    job_id=job_id,
                    state="failed",
                    progress=100,
                    message="Analysis failed",
                    error=str(exc),
                )
                raise

            self._set_analysis_status(
                case_id,
                job_id=job_id,
                state="complete",
                progress=100,
                message="Analysis complete",
                result=result,
            )
            return result

        future = self._analysis_executor.submit(run_job)
        with self._analysis_lock:
            self._analysis_jobs[case_id] = future  # replace placeholder
            self._analysis_job_ids[case_id] = job_id
        return {
            "case_id": case_id,
            "job_id": job_id,
            "accepted": True,
            "detail": "Analysis started.",
            "status": self.get_case_status(case_id),
        }

    def analyze_case(
        self,
        case_id: str,
        enable_llama: bool = True,
        progress_callback: Any | None = None,
    ) -> dict[str, Any]:
        case = self.require_case(case_id)
        evidence_dir = Path(case["evidence_dir"])
        output_dir = Path(case["output_dir"])
        if not evidence_dir.exists():
            raise SecurityError(f"Evidence directory not found for case: {case_id}")

        self.db.set_case_status(case_id, "analyzing", None)
        try:
            if callable(progress_callback):
                progress_callback("running", 5, "Initializing analysis pipeline")
            plugin_registry = PluginRegistry()
            plugin_registry.register_defaults()
            plugin_registry.load_external_plugins(self.config.plugin_dirs)
            report = run_case(
                PipelineConfig(
                    case_id=case_id,
                    input_dir=evidence_dir,
                    output_dir=output_dir,
                    enable_llama=enable_llama,
                    llama_endpoint=self.config.llama_endpoint,
                    llama_model=self.config.llama_model,
                    max_text_bytes=self.config.security_policy.max_text_bytes,
                    rules_dir=self.config.rules_dir,
                    sigma_rules_dir=self.config.sigma_rules_dir,
                    attack_stix_path=self.config.attack_stix_path,
                    openai_compatible_endpoint=self.config.openai_compatible_endpoint,
                    openai_api_key=self.config.openai_api_key,
                    plugin_registry=plugin_registry,
                )
            )
            if callable(progress_callback):
                progress_callback("running", 70, "Persisting findings and timeline")
            self.db.replace_findings_and_timeline(case_id, report.findings, report.timeline)
            self.db.replace_case_iocs(case_id, report.iocs)
            if callable(progress_callback):
                progress_callback("running", 85, "Running IOC enrichment")
            report.enrichments = self._enrich_iocs_with_cache(report.iocs)
            report.summary["ioc_enrichment_count"] = len(report.enrichments)
            (output_dir / "case_report.json").write_text(
                json.dumps(report.to_dict(), indent=2),
                encoding="utf-8",
            )
            artifacts = self.db.get_artifacts(case_id)
            graph_nodes, graph_edges = build_case_graph(
                case_id=case_id,
                artifacts=artifacts,
                findings=report.to_dict().get("findings", []),
                timeline=report.to_dict().get("timeline", []),
                iocs=report.to_dict().get("iocs", []),
            )
            self.db.replace_case_graph(case_id, graph_nodes, graph_edges)
            self.db.set_case_status(case_id, "complete", None)
            self.db.append_audit_log(
                action="case_analyzed",
                actor="system",
                details={
                    "findings": len(report.findings),
                    "timeline_events": len(report.timeline),
                    "iocs": len(report.iocs),
                    "ioc_enrichments": len(report.enrichments),
                    "graph_nodes": len(graph_nodes),
                    "graph_edges": len(graph_edges),
                },
                case_id=case_id,
            )
            brief_md = build_case_brief_markdown(self.case_overview(case_id))
            (output_dir / "case_brief.md").write_text(brief_md, encoding="utf-8")
            if callable(progress_callback):
                progress_callback("complete", 100, "Analysis complete")
        except Exception as exc:
            self.db.set_case_status(case_id, "failed", str(exc))
            if callable(progress_callback):
                progress_callback("failed", 100, f"Analysis failed: {exc}")
            raise

        return {
            "case_id": case_id,
            "findings": len(report.findings),
            "timeline_events": len(report.timeline),
            "iocs": len(report.iocs),
            "ioc_enrichments": len(report.enrichments),
            "output_json": str(output_dir / "case_report.json"),
            "output_md": str(output_dir / "case_report.md"),
            "output_html": str(output_dir / "case_report.html"),
            "output_pdf": str(output_dir / "case_report.pdf"),
            "output_attack_navigator": str(output_dir / "attack_navigator_layer.json"),
            "output_stix": str(output_dir / "case_stix_bundle.json"),
        }

    def _load_report_payload(self, case: dict[str, Any]) -> dict[str, Any]:
        report_path = Path(case["output_dir"]) / "case_report.json"
        if not report_path.exists():
            return {}
        try:
            payload = json.loads(report_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
        return payload if isinstance(payload, dict) else {}

    def list_case_artifacts(
        self,
        case_id: str,
        page: int = 1,
        page_size: int = 50,
        artifact_type: str | None = None,
        source: str | None = None,
        sort: str = "risk",
        search: str | None = None,
    ) -> dict[str, Any]:
        case_id = validate_case_id(case_id)
        case = self.require_case(case_id)
        artifacts = self.db.get_artifacts(case_id)
        findings = self.db.get_findings(case_id)
        timeline = self.db.get_timeline(case_id)
        iocs = self.db.get_case_iocs(case_id)
        previews = build_artifact_previews(
            artifacts=artifacts,
            findings=findings,
            timeline=timeline,
            iocs=iocs,
            report_payload=self._load_report_payload(case),
        )
        clean_type = (artifact_type or "").strip().lower()
        clean_source = (source or "").strip().lower()
        clean_search = (search or "").strip().lower()
        if clean_type:
            previews = [
                item for item in previews
                if str(item.get("artifact_type", "")).lower() == clean_type
            ]
        if clean_source:
            previews = [
                item
                for item in previews
                if clean_source in str(item.get("source_path") or "").lower()
            ]
        if clean_search:
            previews = [
                item
                for item in previews
                if clean_search in " ".join(
                    [
                        str(item.get("display_name") or ""),
                        str(item.get("summary") or ""),
                        str(item.get("rel_path") or ""),
                        " ".join(item.get("matched_findings", [])),
                        " ".join(item.get("ioc_hits", [])),
                    ]
                ).lower()
            ]
        sort_key = (sort or "risk").strip().lower()
        if sort_key == "name":
            previews.sort(key=lambda item: str(item.get("display_name") or "").lower())
        elif sort_key == "size":
            previews.sort(key=lambda item: int(item.get("size_bytes", 0) or 0), reverse=True)
        else:
            previews.sort(
                key=lambda item: (
                    float(item.get("risk_score", 0) or 0),
                    int(item.get("matched_timeline_events", 0) or 0),
                    str(item.get("display_name") or "").lower(),
                ),
                reverse=True,
            )
        clean_page = max(1, int(page))
        clean_page_size = max(1, min(200, int(page_size)))
        offset = (clean_page - 1) * clean_page_size
        items = previews[offset : offset + clean_page_size]
        return {
            "case_id": case_id,
            "page": clean_page,
            "page_size": clean_page_size,
            "total": len(previews),
            "sort": sort_key,
            "filters": {
                "artifact_type": clean_type or None,
                "source": clean_source or None,
                "search": clean_search or None,
            },
            "items": items,
        }

    def query_case_timeline(
        self,
        case_id: str,
        after: str | None = None,
        before: str | None = None,
        min_risk: float | None = None,
        event_type: str | None = None,
        keyword: str | None = None,
        limit: int = 500,
        view_name: str | None = None,
    ) -> dict[str, Any]:
        clean_after = after
        clean_before = before
        clean_min_risk = min_risk
        clean_event_type = event_type
        clean_keyword = keyword
        if view_name:
            views = self.db.list_workspace_views(validate_case_id(case_id))
            match = next(
                (item for item in views if str(item.get("name", "")).lower() == view_name.lower()),
                None,
            )
            if match:
                filters = dict(match.get("filters") or {})
                clean_after = filters.get("after", clean_after)
                clean_before = filters.get("before", clean_before)
                clean_min_risk = filters.get("min_risk", clean_min_risk)
                clean_event_type = filters.get("event_type", clean_event_type)
                clean_keyword = filters.get("keyword", clean_keyword)
                limit = int(filters.get("limit", limit) or limit)
        payload = self.filter_timeline(
            case_id=case_id,
            after=clean_after,
            before=clean_before,
            min_risk=clean_min_risk,
            event_type=clean_event_type,
            keyword=clean_keyword,
            limit=limit,
        )
        payload["view_name"] = view_name
        return payload

    def list_workspace_views(self, case_id: str, limit: int = 200) -> list[dict[str, Any]]:
        case_id = validate_case_id(case_id)
        self.require_case(case_id)
        views = self.db.list_workspace_views(case_id)
        return views[:max(1, min(1000, int(limit)))]

    def save_workspace_view(
        self,
        case_id: str,
        name: str,
        section: str,
        filters: dict[str, Any],
        sort: dict[str, Any],
        layout: dict[str, Any],
        view_id: str | None = None,
    ) -> dict[str, Any]:
        case_id = validate_case_id(case_id)
        self.require_case(case_id)
        view = self.db.upsert_workspace_view(
            case_id=case_id,
            name=name.strip(),
            section=section.strip() or "overview",
            filters=filters or {},
            sort=sort or {},
            layout=layout or {},
            view_id=view_id,
        )
        self.db.append_audit_log(
            action="workspace_view_saved",
            actor="analyst",
            details={"view_id": view["view_id"], "name": view["name"]},
            case_id=case_id,
        )
        return view

    def delete_workspace_view(self, case_id: str, view_id: str) -> bool:
        case_id = validate_case_id(case_id)
        self.require_case(case_id)
        deleted = self.db.delete_workspace_view(case_id, view_id)
        if deleted:
            self.db.append_audit_log(
                action="workspace_view_deleted",
                actor="analyst",
                details={"view_id": view_id},
                case_id=case_id,
            )
        return deleted

    def list_notebook_entries(self, case_id: str, limit: int = 200) -> list[dict[str, Any]]:
        case_id = validate_case_id(case_id)
        self.require_case(case_id)
        entries = self.db.list_notebook_entries(case_id)
        return entries[:max(1, min(1000, int(limit)))]

    def create_notebook_entry(
        self,
        case_id: str,
        kind: str,
        title: str,
        body: str,
        links: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        case_id = validate_case_id(case_id)
        self.require_case(case_id)
        entry = self.db.create_notebook_entry(
            case_id=case_id,
            kind=kind,
            title=title,
            body=body,
            links=links or {},
        )
        self.db.append_audit_log(
            action="notebook_entry_created",
            actor="analyst",
            details={"entry_id": entry["entry_id"], "kind": entry["kind"]},
            case_id=case_id,
        )
        return entry

    def update_notebook_entry(
        self,
        case_id: str,
        entry_id: str,
        title: str | None = None,
        body: str | None = None,
        kind: str | None = None,
        links: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        case_id = validate_case_id(case_id)
        self.require_case(case_id)
        entry = self.db.update_notebook_entry(
            case_id=case_id,
            entry_id=entry_id,
            title=title,
            body=body,
            kind=kind,
            links=links,
        )
        if entry is None:
            raise SecurityError(f"Notebook entry not found: {entry_id}")
        self.db.append_audit_log(
            action="notebook_entry_updated",
            actor="analyst",
            details={"entry_id": entry_id},
            case_id=case_id,
        )
        return entry

    def get_case_graph_data(self, case_id: str) -> dict[str, Any]:
        case_id = validate_case_id(case_id)
        case = self.require_case(case_id)
        graph = self.db.get_case_graph(case_id)
        if graph["nodes"]:
            for edge in graph["edges"]:
                if "from_node" not in edge and "source_node_id" in edge:
                    edge["from_node"] = edge.get("source_node_id")
                if "to_node" not in edge and "target_node_id" in edge:
                    edge["to_node"] = edge.get("target_node_id")
            return {
                "case_id": case_id,
                "nodes": graph["nodes"],
                "edges": graph["edges"],
            }
        artifacts = self.db.get_artifacts(case_id)
        findings = self.db.get_findings(case_id)
        timeline = self.db.get_timeline(case_id)
        iocs = self.db.get_case_iocs(case_id)
        nodes, edges = build_case_graph(case_id, artifacts, findings, timeline, iocs)
        self.db.replace_case_graph(case_id, nodes, edges)
        return {
            "case_id": case_id,
            "nodes": nodes,
            "edges": edges,
            "generated_from": str(Path(case["output_dir"]) / "case_report.json"),
        }

    def _load_agent_session_details(
        self,
        case_id: str,
        session: dict[str, Any],
    ) -> dict[str, Any]:
        session_id = str(session.get("session_id") or "")
        payload = dict(session)
        payload["steps"] = self.db.list_agent_steps(session_id)
        payload["recommendations"] = self.db.list_agent_recommendations(session_id)
        if session_id in self._agent_status:
            payload["runtime_status"] = dict(self._agent_status[session_id])
        payload["case_id"] = case_id
        return payload

    def list_agent_sessions(self, case_id: str) -> list[dict[str, Any]]:
        case_id = validate_case_id(case_id)
        self.require_case(case_id)
        sessions = self.db.list_agent_sessions(case_id)
        return [self._load_agent_session_details(case_id, session) for session in sessions]

    def get_agent_session(self, case_id: str, session_id: str) -> dict[str, Any]:
        case_id = validate_case_id(case_id)
        self.require_case(case_id)
        session = self.db.get_agent_session(case_id, session_id)
        if session is None:
            raise SecurityError(f"Agent session not found: {session_id}")
        return self._load_agent_session_details(case_id, session)

    def _write_workspace_snapshot(self, case_id: str) -> dict[str, str]:
        overview = self.case_overview(case_id)
        case = overview["case"]
        output_dir = Path(case["output_dir"])
        output_dir.mkdir(parents=True, exist_ok=True)
        brief_path = output_dir / "case_brief.md"
        snapshot_path = output_dir / "workspace_snapshot.json"
        graph_path = output_dir / "case_graph.json"
        brief_path.write_text(build_case_brief_markdown(overview), encoding="utf-8")
        snapshot_path.write_text(json.dumps(overview, indent=2), encoding="utf-8")
        graph_payload = {
            "case_id": case_id,
            "nodes": overview.get("graph", {}).get("nodes", []),
            "edges": overview.get("graph", {}).get("edges", []),
        }
        graph_path.write_text(json.dumps(graph_payload, indent=2), encoding="utf-8")
        return {
            "brief": str(brief_path),
            "snapshot": str(snapshot_path),
            "graph": str(graph_path),
        }

    def _append_agent_step_result(
        self,
        session_id: str,
        title: str,
        rationale: str,
        proposed_action: dict[str, Any],
        approval_state: str,
        result: dict[str, Any],
        linked_entities: dict[str, Any] | None = None,
    ) -> None:
        existing = self.db.list_agent_steps(session_id)
        next_index = len(existing) + 1
        existing.append(
            {
                "step_id": uuid.uuid4().hex[:16],
                "step_index": next_index,
                "title": title,
                "rationale": rationale,
                "linked_entities": linked_entities or {},
                "proposed_action": proposed_action,
                "approval_state": approval_state,
                "result": result,
                "created_at": utc_now_iso(),
                "updated_at": utc_now_iso(),
            }
        )
        self.db.replace_agent_steps(session_id, existing)

    def _update_agent_recommendation_status(
        self,
        session_id: str,
        case_id: str,
        recommendation_id: str,
        status: str,
        result: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        recommendations = self.db.list_agent_recommendations(session_id)
        for item in recommendations:
            if str(item.get("recommendation_id") or "") == recommendation_id:
                item["status"] = status
                if result is not None:
                    item["result"] = result
                item["updated_at"] = utc_now_iso()
                break
        self.db.replace_agent_recommendations(session_id, case_id, recommendations)
        return recommendations

    def _execute_agent_action(
        self,
        case_id: str,
        session_id: str,
        action: str,
    ) -> dict[str, Any]:
        clean_action = action.strip().lower()
        session = self.get_agent_session(case_id, session_id)
        enable_llama = bool(session.get("model_config", {}).get("enable_llama", True))
        if clean_action == "rerun_analysis":
            result = self.analyze_case(case_id, enable_llama=enable_llama)
            self._write_workspace_snapshot(case_id)
            return result
        if clean_action == "start_enrichment":
            result = self._run_enrichment_for_case(
                case_id,
                job_id=f"agent-enrich-{uuid.uuid4().hex[:12]}",
            )
            self._write_workspace_snapshot(case_id)
            return result
        if clean_action == "generate_verdict":
            outputs = self._write_workspace_snapshot(case_id)
            body = Path(outputs["brief"]).read_text(encoding="utf-8")
            entry = self.create_notebook_entry(
                case_id,
                kind="verdict",
                title="Agent verdict draft",
                body=body,
                links={"session_ids": [session_id]},
            )
            return {"entry_id": entry["entry_id"], "brief": outputs["brief"]}
        if clean_action == "export_report_bundle":
            case = self.require_case(case_id)
            output_dir = Path(case["output_dir"])
            self._write_workspace_snapshot(case_id)
            archive_path = output_dir / f"{case_id}-workspace.zip"
            return self.export_case_archive(case_id, archive_path)
        raise SecurityError(f"Unsupported agent action: {action}")

    def _run_agent_session(
        self,
        case_id: str,
        session_id: str,
        goal: str,
        auto_approve: bool = False,
    ) -> dict[str, Any]:
        self.db.update_agent_session(session_id, status="running", summary="Building case context.")
        overview = self.case_overview(case_id)
        findings = overview.get("findings", [])
        timeline = overview.get("timeline", [])
        threads = overview.get("threads", [])
        notebook_entries = overview.get("notebook_entries", [])
        graph = overview.get("graph", {})
        summary = (
            f"Reviewed {len(findings)} finding(s), {len(timeline)} timeline event(s), "
            f"and {len(graph.get('nodes', []))} graph node(s) for goal: {goal}."
        )
        self.db.replace_agent_steps(
            session_id,
            [
                {
                    "step_id": uuid.uuid4().hex[:16],
                    "step_index": 1,
                    "title": "Snapshot case context",
                    "rationale": "Load the current case state before recommending actions.",
                    "linked_entities": {},
                    "proposed_action": {"action": "context_snapshot"},
                    "approval_state": "not_required",
                    "result": {
                        "findings": len(findings),
                        "timeline_events": len(timeline),
                        "iocs": len(overview.get("iocs", [])),
                    },
                    "created_at": utc_now_iso(),
                    "updated_at": utc_now_iso(),
                },
                {
                    "step_id": uuid.uuid4().hex[:16],
                    "step_index": 2,
                    "title": "Cluster suspicious activity",
                    "rationale": "Group related findings and events into analyst-sized threads.",
                    "linked_entities": {"thread_ids": [item.get("thread_id") for item in threads[:10]]},
                    "proposed_action": {"action": "cluster_activity"},
                    "approval_state": "not_required",
                    "result": {"threads": len(threads)},
                    "created_at": utc_now_iso(),
                    "updated_at": utc_now_iso(),
                },
                {
                    "step_id": uuid.uuid4().hex[:16],
                    "step_index": 3,
                    "title": "Generate prioritized recommendations",
                    "rationale": "Promote the next actions that materially improve the investigation.",
                    "linked_entities": {},
                    "proposed_action": {"action": "recommend"},
                    "approval_state": "not_required",
                    "result": {},
                    "created_at": utc_now_iso(),
                    "updated_at": utc_now_iso(),
                },
            ],
        )
        recommendations = build_agent_recommendations(case_id, overview, notebook_entries)
        for item in recommendations:
            item["recommendation_id"] = item.get("recommendation_id") or uuid.uuid4().hex[:16]
        self.db.replace_agent_recommendations(session_id, case_id, recommendations)
        self.create_notebook_entry(
            case_id,
            kind="agent_summary",
            title="Agent context snapshot",
            body=summary,
            links={"session_ids": [session_id]},
        )

        if auto_approve:
            current_recommendations = recommendations
            for item in list(current_recommendations):
                action_name = str(item.get("suggested_action", {}).get("action") or "")
                result = self._execute_agent_action(case_id, session_id, action_name)
                self._append_agent_step_result(
                    session_id=session_id,
                    title=f"Execute {action_name}",
                    rationale="Auto-approved from the autonomous solve flow.",
                    proposed_action={"action": action_name},
                    approval_state="approved",
                    result=result,
                    linked_entities=item.get("linked_entities") or {},
                )
                current_recommendations = self._update_agent_recommendation_status(
                    session_id=session_id,
                    case_id=case_id,
                    recommendation_id=str(item.get("recommendation_id") or ""),
                    status="executed",
                    result=result,
                )
            outputs = self._write_workspace_snapshot(case_id)
            final_summary = (
                f"{summary} Auto-approved {len(current_recommendations)} action(s); "
                f"workspace snapshot written to {outputs['snapshot']}."
            )
            self.db.update_agent_session(
                session_id,
                status="complete",
                summary=final_summary,
                completed_at=utc_now_iso(),
            )
            return self.get_agent_session(case_id, session_id)

        pending_actions = [
            item for item in recommendations
            if str(item.get("suggested_action", {}).get("action") or "") in {
                "rerun_analysis",
                "start_enrichment",
                "generate_verdict",
                "export_report_bundle",
            }
        ]
        session_status = "awaiting_approval" if pending_actions else "complete"
        self.db.update_agent_session(
            session_id,
            status=session_status,
            summary=summary,
            completed_at=utc_now_iso() if session_status == "complete" else None,
        )
        if session_status == "complete":
            self._write_workspace_snapshot(case_id)
        return self.get_agent_session(case_id, session_id)

    def start_agent_session(
        self,
        case_id: str,
        goal: str | None = None,
        auto_approve: bool = False,
    ) -> dict[str, Any]:
        case_id = validate_case_id(case_id)
        self.require_case(case_id)
        active = [
            session for session in self.db.list_agent_sessions(case_id)
            if str(session.get("status") or "") in {"queued", "running"}
        ]
        if active:
            return {
                "accepted": False,
                "detail": "An agent session is already running for this case.",
                "session": self._load_agent_session_details(case_id, active[0]),
            }
        model_config = {
            "llama_model": self.config.llama_model,
            "enable_llama": bool(self.config.llama_model),
            "openai_compatible_endpoint": self.config.openai_compatible_endpoint,
        }
        session = self.db.create_agent_session(
            case_id=case_id,
            goal=(goal or "Autonomous case investigation").strip(),
            status="queued",
            model_config=model_config,
            summary="Queued for investigation.",
        )
        session_id = str(session["session_id"])
        placeholder: Future[dict[str, Any]] = Future()
        with self._agent_lock:
            self._agent_jobs[session_id] = placeholder
            self._agent_status[session_id] = {
                "session_id": session_id,
                "case_id": case_id,
                "state": "queued",
                "message": "Agent session queued",
            }

        def run_job() -> dict[str, Any]:
            with self._agent_lock:
                self._agent_status[session_id] = {
                    "session_id": session_id,
                    "case_id": case_id,
                    "state": "running",
                    "message": "Agent is reviewing the case",
                }
            try:
                result = self._run_agent_session(
                    case_id=case_id,
                    session_id=session_id,
                    goal=str(session.get("goal") or ""),
                    auto_approve=auto_approve,
                )
                with self._agent_lock:
                    self._agent_status[session_id] = {
                        "session_id": session_id,
                        "case_id": case_id,
                        "state": result.get("status", "complete"),
                        "message": result.get("summary", "Agent session completed"),
                    }
                return result
            except Exception as exc:
                self.db.update_agent_session(session_id, status="failed", error=str(exc))
                with self._agent_lock:
                    self._agent_status[session_id] = {
                        "session_id": session_id,
                        "case_id": case_id,
                        "state": "failed",
                        "message": str(exc),
                    }
                raise

        future = self._agent_executor.submit(run_job)
        with self._agent_lock:
            self._agent_jobs[session_id] = future
        self.db.append_audit_log(
            action="agent_session_started",
            actor="agent",
            details={"session_id": session_id, "goal": session.get("goal")},
            case_id=case_id,
        )
        return {
            "accepted": True,
            "session": self.get_agent_session(case_id, session_id),
        }

    def approve_agent_session(
        self,
        case_id: str,
        session_id: str,
        action: str | None = None,
        recommendation_id: str | None = None,
    ) -> dict[str, Any]:
        session = self.get_agent_session(case_id, session_id)
        recommendations = list(session.get("recommendations") or [])
        target = None
        if recommendation_id:
            target = next(
                (
                    item for item in recommendations
                    if str(item.get("recommendation_id") or "") == recommendation_id
                ),
                None,
            )
        elif action:
            target = next(
                (
                    item for item in recommendations
                    if str(item.get("suggested_action", {}).get("action") or "") == action
                    and str(item.get("status") or "pending") == "pending"
                ),
                None,
            )
        else:
            target = next(
                (item for item in recommendations if str(item.get("status") or "pending") == "pending"),
                None,
            )
        if target is None:
            raise SecurityError("No pending recommendation matched the approval request.")
        action_name = str(target.get("suggested_action", {}).get("action") or "")
        result = self._execute_agent_action(case_id, session_id, action_name)
        self._append_agent_step_result(
            session_id=session_id,
            title=f"Execute {action_name}",
            rationale="Executed after explicit analyst approval.",
            proposed_action={"action": action_name},
            approval_state="approved",
            result=result,
            linked_entities=target.get("linked_entities") or {},
        )
        recommendations = self._update_agent_recommendation_status(
            session_id=session_id,
            case_id=case_id,
            recommendation_id=str(target.get("recommendation_id") or ""),
            status="executed",
            result=result,
        )
        remaining = [item for item in recommendations if str(item.get("status") or "") == "pending"]
        updated = self.db.update_agent_session(
            session_id,
            status="awaiting_approval" if remaining else "complete",
            summary=f"Approved and executed {action_name}.",
            completed_at=utc_now_iso() if not remaining else None,
        )
        self.db.append_audit_log(
            action="agent_session_approved",
            actor="analyst",
            details={"session_id": session_id, "action": action_name},
            case_id=case_id,
        )
        return self._load_agent_session_details(case_id, updated or session)

    def cancel_agent_session(self, case_id: str, session_id: str) -> dict[str, Any]:
        self.require_case(validate_case_id(case_id))
        session = self.db.update_agent_session(
            session_id,
            status="cancelled",
            summary="Cancelled by analyst.",
            completed_at=utc_now_iso(),
        )
        if session is None:
            raise SecurityError(f"Agent session not found: {session_id}")
        self.db.append_audit_log(
            action="agent_session_cancelled",
            actor="analyst",
            details={"session_id": session_id},
            case_id=case_id,
        )
        return self._load_agent_session_details(case_id, session)

    def run_agent_session_sync(
        self,
        case_id: str,
        goal: str,
        poll_interval_seconds: float = 0.1,
        timeout_seconds: float = 300.0,
    ) -> dict[str, Any]:
        started = self.start_agent_session(
            case_id,
            goal=goal,
            auto_approve=True,
        )
        session = dict(started.get("session") or {})
        session_id = str(session.get("session_id") or "")
        if not session_id:
            raise SecurityError("Agent session did not return a session id.")
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            current = self.get_agent_session(case_id, session_id)
            status = str(current.get("status") or "")
            if status in {"complete", "failed", "cancelled"}:
                return current
            time.sleep(max(0.05, poll_interval_seconds))
        raise SecurityError(
            f"Timed out waiting for agent session to finish: {session_id}"
        )

    def case_overview(self, case_id: str) -> dict[str, Any]:
        case = self.require_case(case_id)
        artifacts = self.db.get_artifacts(case_id)
        findings = self.db.get_findings(case_id)
        timeline = self.db.get_timeline(case_id)
        iocs = self.db.get_case_iocs(case_id)
        ioc_enrichments = self.db.get_case_ioc_enrichments(case_id)
        notes = self.db.get_analyst_notes(case_id)
        workspace_views = self.db.list_workspace_views(case_id)
        notebook_entries = self.db.list_notebook_entries(case_id)
        agent_sessions = self.db.list_agent_sessions(case_id)
        evidence_hash_log = self.db.get_evidence_hash_log(case_id)
        audit_log = self.db.get_audit_log(case_id=case_id, limit=500)
        latest_job = self.db.get_case_latest_job(case_id, job_type="analysis")
        latest_enrichment_job = self.db.get_case_latest_job(case_id, job_type="enrichment")
        payload = self._load_report_payload(case)
        summary: dict[str, Any] = payload.get("summary", {}) if payload else {}
        threads = build_case_threads(findings, timeline)
        artifact_previews = build_artifact_previews(
            artifacts=artifacts,
            findings=findings,
            timeline=timeline,
            iocs=iocs,
            report_payload=payload,
        )
        graph = self.get_case_graph_data(case_id)
        for session in agent_sessions:
            session_id = str(session.get("session_id") or "")
            session["steps"] = self.db.list_agent_steps(session_id)
            session["recommendations"] = self.db.list_agent_recommendations(session_id)
        if threads and "risk_score" not in summary:
            summary["risk_score"] = round(
                sum(float(item.get("confidence", 0) or 0) for item in threads[:3]) * 100.0,
                2,
            )
        return {
            "case": case,
            "artifacts": artifacts,
            "artifact_previews": artifact_previews,
            "findings": findings,
            "timeline": timeline,
            "iocs": iocs,
            "ioc_enrichments": ioc_enrichments,
            "notes": notes,
            "workspace_views": workspace_views,
            "notebook_entries": notebook_entries,
            "agent_sessions": agent_sessions,
            "graph": graph,
            "threads": threads,
            "evidence_hash_log": evidence_hash_log,
            "audit_log": audit_log,
            "latest_job": latest_job,
            "latest_enrichment_job": latest_enrichment_job,
            "summary": summary,
        }

    def _share_case_urls(
        self,
        case_id: str,
        base_url: str | None = None,
    ) -> dict[str, str]:
        clean_base = (base_url or "").strip().rstrip("/")
        if clean_base:
            return {
                "workspace_url": (
                    f"{clean_base}/?case={case_id}&tab=overview"
                ),
                "brief_url": (
                    f"{clean_base}/api/cases/{case_id}/report?fmt=brief"
                ),
                "report_url": (
                    f"{clean_base}/api/cases/{case_id}/report?fmt=html"
                ),
            }
        return {
            "workspace_url": f"/?case={case_id}&tab=overview",
            "brief_url": f"/api/cases/{case_id}/report?fmt=brief",
            "report_url": f"/api/cases/{case_id}/report?fmt=html",
        }

    def track_case_share_event(
        self,
        case_id: str,
        event: str,
        channel: str = "dashboard",
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        case_id = validate_case_id(case_id)
        self.require_case(case_id)
        clean_event = event.strip().lower()
        allowed_events = {"share_clicked", "share_copied"}
        if clean_event not in allowed_events:
            raise SecurityError(
                "Share event must be share_clicked or share_copied."
            )
        clean_channel = (
            channel.strip().lower() if channel and channel.strip() else "dashboard"
        )
        details: dict[str, Any] = {
            "event": clean_event,
            "channel": clean_channel[:64],
        }
        if metadata:
            details["metadata"] = dict(metadata)
        self.db.append_audit_log(
            action=clean_event,
            actor="analyst",
            details=details,
            case_id=case_id,
        )
        return {
            "case_id": case_id,
            "event": clean_event,
            "channel": details["channel"],
            "tracked": True,
        }

    def build_share_brief(
        self,
        case_id: str,
        base_url: str | None = None,
    ) -> dict[str, Any]:
        case_id = validate_case_id(case_id)
        overview = self.case_overview(case_id)
        case = dict(overview.get("case") or {})
        output_dir_raw = str(case.get("output_dir") or "").strip()
        if not output_dir_raw:
            raise SecurityError(f"Case output directory missing: {case_id}")
        output_dir = Path(output_dir_raw)
        output_dir.mkdir(parents=True, exist_ok=True)
        brief_path = output_dir / "case_brief.md"
        if brief_path.exists():
            brief_text = brief_path.read_text(encoding="utf-8")
        else:
            brief_text = build_case_brief_markdown(overview)
            brief_path.write_text(brief_text, encoding="utf-8")

        findings = list(overview.get("findings") or [])
        critical_high = sum(
            1
            for finding in findings
            if str(finding.get("severity", "")).lower() in {"critical", "high"}
        )
        iocs = list(overview.get("iocs") or [])
        timeline = list(overview.get("timeline") or [])
        summary = dict(overview.get("summary") or {})
        risk_score = summary.get("risk_score")
        risk_text = "n/a" if risk_score is None else str(risk_score)
        urls = self._share_case_urls(case_id, base_url=base_url)

        highlights = [
            line.strip()
            for line in brief_text.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ][:3]
        share_lines = [
            f"Auto Forensics case brief: {case_id}",
            f"Status: {case.get('status', 'unknown')}",
            (
                f"Findings: {len(findings)} "
                f"(critical/high: {critical_high})"
            ),
            (
                f"IOCs: {len(iocs)} | Timeline events: {len(timeline)} "
                f"| Risk score: {risk_text}"
            ),
            f"Open workspace: {urls['workspace_url']}",
            f"Read full brief: {urls['brief_url']}",
        ]
        if highlights:
            share_lines.append("")
            share_lines.append("Highlights:")
            share_lines.extend(f"- {item}" for item in highlights)

        self.track_case_share_event(
            case_id,
            event="share_clicked",
            channel="workspace_button",
            metadata={"workspace_url": urls["workspace_url"]},
        )
        return {
            "case_id": case_id,
            "share_url": urls["workspace_url"],
            "brief_url": urls["brief_url"],
            "report_url": urls["report_url"],
            "share_text": "\n".join(share_lines),
            "metrics": {
                "share_clicked": "audit_log action=share_clicked",
                "share_copied": "audit_log action=share_copied",
            },
        }

    def add_case_note(self, case_id: str, content: str, author: str = "analyst") -> dict[str, Any]:
        case_id = validate_case_id(case_id)
        self.require_case(case_id)
        note = self.db.add_analyst_note(case_id, author=author, content=content)
        self.db.append_audit_log(
            action="note_added",
            actor=author,
            details={"note_id": note.get("note_id", "")},
            case_id=case_id,
        )
        return note

    def list_case_notes(self, case_id: str, limit: int = 200) -> list[dict[str, Any]]:
        case_id = validate_case_id(case_id)
        self.require_case(case_id)
        notes = self.db.get_analyst_notes(case_id)
        return notes[:max(1, min(1000, int(limit)))]

    def search_case(self, case_id: str, query: str, limit: int = 100) -> dict[str, Any]:
        case_id = validate_case_id(case_id)
        self.require_case(case_id)
        cleaned = query.strip()
        if not cleaned:
            raise SecurityError("Search query cannot be empty.")
        limit = max(1, min(500, int(limit)))
        raw = self.db.search_case(case_id, cleaned, limit=limit)
        result: dict[str, Any] = {
            "findings": raw.get("findings", []),
            "timeline": raw.get("timeline", []),
            "iocs": raw.get("iocs", []),
        }
        result["query"] = cleaned
        result["case_id"] = case_id
        result["counts"] = {
            "findings": len(result["findings"]),
            "timeline": len(result["timeline"]),
            "iocs": len(result["iocs"]),
        }
        return result

    def _archive_signature(self, manifest: dict[str, Any]) -> str:
        payload = json.dumps(manifest, sort_keys=True).encode("utf-8")
        salt = (self.config.api_key_hash or "auto-forensics").encode("utf-8")
        return hashlib.sha256(payload + salt).hexdigest()

    def export_case_archive(self, case_id: str, destination_zip: Path) -> dict[str, Any]:
        case = self.require_case(case_id)
        case_root = Path(case["evidence_dir"]).parent
        if not case_root.exists() or not case_root.is_dir():
            raise SecurityError(f"Case root not found for export: {case_root}")

        files: list[dict[str, Any]] = []
        # Export everything in the case root, not just supported artifacts.
        # So we use a permissive filter.
        def any_file(p: Path) -> bool:
            return True

        policy = self.config.security_policy
        for path in walk_case_directory(case_root, policy, filter_func=any_file):
            rel = str(path.relative_to(case_root))
            files.append({"rel_path": rel, "sha256": sha256_file(path), "size_bytes": path.stat().st_size})

        now = utc_now_iso()
        manifest = {
            "case_id": case_id,
            "created_at": case.get("created_at"),
            "exported_at": now,
            "files": files,
        }
        manifest["signature"] = self._archive_signature(manifest)

        destination_zip = destination_zip.expanduser().resolve()
        destination_zip.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(destination_zip, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("manifest.json", json.dumps(manifest, indent=2))
            for item in files:
                archive.write(case_root / item["rel_path"], arcname=item["rel_path"])

        self.db.append_audit_log(
            action="case_exported",
            actor="system",
            details={"archive": str(destination_zip), "files": len(files)},
            case_id=case_id,
        )
        return {"case_id": case_id, "archive": str(destination_zip), "files": len(files)}

    def import_case_archive(self, archive_path: Path, case_id_override: str | None = None) -> dict[str, Any]:
        archive_path = archive_path.expanduser().resolve()
        if not archive_path.exists() or not archive_path.is_file():
            raise SecurityError(f"Archive not found: {archive_path}")

        with tempfile.TemporaryDirectory(prefix="auto_forensics_import_") as tmp:
            tmp_root = Path(tmp).resolve()
            with zipfile.ZipFile(archive_path, "r") as archive:
                for member in archive.infolist():
                    member_name = member.filename
                    # Normalize path without following symlinks to prevent Zip Slip
                    candidate = tmp_root / member_name
                    # Use normpath to resolve .. sequences without following symlinks
                    normalized = Path(os.path.normpath(candidate))
                    try:
                        normalized.relative_to(tmp_root)
                    except ValueError as exc:
                        raise SecurityError(
                            f"Archive path escapes extraction root: {member_name}"
                        ) from exc
                    # Additional check: reject absolute paths and paths with null bytes
                    if member_name.startswith("/") or "\\x00" in member_name:
                        raise SecurityError(
                            f"Invalid archive member path: {member_name}"
                        )
                    archive.extract(member, tmp_root)

            manifest_path = tmp_root / "manifest.json"
            if not manifest_path.exists():
                raise SecurityError("Archive missing manifest.json")
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise SecurityError("Invalid archive manifest JSON") from exc

            if not isinstance(manifest, dict):
                raise SecurityError("Invalid archive manifest")
            expected_sig = str(manifest.get("signature") or "")
            unsigned_manifest = {k: v for k, v in manifest.items() if k != "signature"}
            actual_sig = self._archive_signature(unsigned_manifest)
            if expected_sig != actual_sig:
                raise SecurityError("Archive signature verification failed")

            archive_case_id = validate_case_id(str(manifest.get("case_id") or ""))
            case_id = validate_case_id(case_id_override) if case_id_override else archive_case_id
            if self.db.get_case(case_id):
                raise SecurityError(f"Case already exists: {case_id}")

            evidence_dir, output_dir = self.case_manager.init_case_dirs(case_id)
            case_root = evidence_dir.parent

            file_items = manifest.get("files", [])
            if not isinstance(file_items, list):
                raise SecurityError("Invalid file list in manifest")

            for item in file_items:
                if not isinstance(item, dict):
                    continue
                rel_path = str(item.get("rel_path") or "")
                expected_hash = str(item.get("sha256") or "")
                src = confine_path(tmp_root, tmp_root / rel_path)
                dst = confine_path(case_root, case_root / rel_path)
                if not src.exists() or not src.is_file():
                    raise SecurityError(f"Missing file from archive: {rel_path}")
                if expected_hash and sha256_file(src) != expected_hash:
                    raise SecurityError(f"File hash mismatch for {rel_path}")
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)

            self.db.create_case(case_id, evidence_dir=evidence_dir, output_dir=output_dir)
            self.db.append_audit_log(
                action="case_imported",
                actor="system",
                details={"archive": str(archive_path), "source_case_id": archive_case_id},
                case_id=case_id,
            )
            self.db.set_case_status(case_id, "ready")
            return {
                "case_id": case_id,
                "archive": str(archive_path),
                "evidence_dir": str(evidence_dir),
                "output_dir": str(output_dir),
            }

    def delete_case(self, case_id: str) -> dict[str, Any]:
        """Permanently delete a case, its database records, and its on-disk directories.

        The case must exist (raises SecurityError otherwise).  Returns a summary
        dict with ``deleted`` True and the number of filesystem directories removed.
        """
        case = self.require_case(case_id)

        # Remove from DB first (CASCADE deletes all child rows).
        self.db.delete_case(case_id)

        # Best-effort removal of on-disk evidence and output directories.
        dirs_removed = 0
        for dir_key in ("evidence_dir", "output_dir"):
            dir_path_str = case.get(dir_key)
            if not dir_path_str:
                continue
            target = Path(dir_path_str)
            # Walk up to the parent case folder (evidence_dir is  <cases>/<id>/evidence).
            case_folder = target.parent if target.name in {"evidence", "output"} else target
            if case_folder.exists() and case_folder.is_dir():
                try:
                    shutil.rmtree(case_folder)
                    dirs_removed += 1
                    break  # Both evidence and output share the same parent case folder.
                except OSError as exc:
                    logger.warning("Could not remove case directory %s: %s", case_folder, exc)

        self.db.append_audit_log(
            action="case_deleted",
            actor="system",
            details={"case_id": case_id, "dirs_removed": dirs_removed},
        )
        return {"deleted": True, "case_id": case_id, "dirs_removed": dirs_removed}

    def get_report(self, case_id: str, fmt: str = "json") -> str:
        case = self.require_case(case_id)
        output = Path(case["output_dir"])
        if fmt == "json":
            path = output / "case_report.json"
        elif fmt == "md":
            path = output / "case_report.md"
        elif fmt == "html":
            path = output / "case_report.html"
        elif fmt == "brief":
            path = output / "case_brief.md"
        elif fmt == "navigator":
            path = output / "attack_navigator_layer.json"
        elif fmt == "stix":
            path = output / "case_stix_bundle.json"
        else:
            raise SecurityError(
                "Unsupported report format. Use 'json', 'md', 'html', "
                "'brief', 'navigator', or 'stix'."
            )
        if not path.exists():
            raise SecurityError(f"Report not found: {path}")
        return path.read_text(encoding="utf-8")

    # ------------------------------------------------------------------
    # Standalone scanning (no case required)
    # ------------------------------------------------------------------

    def scan_file(self, file_path: Path) -> dict[str, Any]:
        """Scan a single file: hashes, entropy, suspicious strings, PE imports, YARA."""
        from .binary_analysis import analyze_binary
        from .yara_detector import scan_paths_with_yara
        from dataclasses import asdict

        resolved = file_path.expanduser().resolve()
        if not resolved.is_file():
            raise SecurityError(f"Not a file: {resolved}")

        feat = analyze_binary(resolved)
        result: dict[str, Any] = asdict(feat)

        # YARA scan (best-effort)
        yara_hits: list[dict[str, Any]] = []
        if self.config.rules_dir and self.config.rules_dir.exists():
            try:
                raw = scan_paths_with_yara([resolved], self.config.rules_dir)
                for hit in raw:
                    yara_hits.append({
                        "rule": hit.get("rule", ""),
                        "tags": hit.get("tags", []),
                        "meta": hit.get("meta", {}),
                    })
            except Exception as exc:
                logger.debug("YARA scan failed for %s: %s", resolved, exc)
        result["yara_hits"] = yara_hits
        return result

    def scan_directory(
        self,
        dir_path: Path,
        recursive: bool = True,
        max_files: int = 10_000,
    ) -> dict[str, Any]:
        """Walk a directory and scan every file, returning aggregate results."""
        resolved = dir_path.expanduser().resolve()
        if not resolved.is_dir():
            raise SecurityError(f"Not a directory: {resolved}")

        files: list[Path] = []
        policy = self.config.security_policy
        # scan_directory might be called on non-case dirs, but we still respect policy limits.
        
        # recursive=False isn't directly supported by walk_case_directory yet.
        # But for scan_directory, we can just use glob if not recursive.
        if not recursive:
            for p in sorted(resolved.glob("*")):
                if p.is_file():
                    files.append(p)
                    if len(files) >= max_files:
                        break
        else:
            # For recursive, use walk_case_directory with permissive filter.
            def any_file(p: Path) -> bool:
                return True
            for p in walk_case_directory(resolved, policy, filter_func=any_file):
                files.append(p)
                if len(files) >= max_files:
                    break

        scanned: list[dict[str, Any]] = []
        total_bytes = 0
        suspicious_count = 0
        for f in files:
            try:
                result = self.scan_file(f)
                scanned.append(result)
                total_bytes += result.get("size_bytes", 0)
                if result.get("suspicious_score", 0) > 0:
                    suspicious_count += 1
            except Exception as exc:
                logger.debug("Skipping %s: %s", f, exc)

        # Sort most suspicious first
        scanned.sort(key=lambda x: x.get("suspicious_score", 0), reverse=True)

        return {
            "directory": str(resolved),
            "recursive": recursive,
            "total_files": len(scanned),
            "total_bytes": total_bytes,
            "suspicious_files": suspicious_count,
            "files": scanned,
        }

    # ------------------------------------------------------------------
    # Heuristic conclusions engine
    # ------------------------------------------------------------------

    def generate_conclusions(self, case_id: str) -> dict[str, Any]:
        """Generate forensic conclusions from case data using heuristic analysis.

        Correlates findings by MITRE tactic, counts severity distributions,
        identifies the highest-risk timeline window, and produces structured
        bullet-point conclusions — no LLM required.
        """
        case_id = validate_case_id(case_id)
        overview = self.case_overview(case_id)
        findings = overview.get("findings", [])
        timeline = overview.get("timeline", [])
        iocs = overview.get("iocs", [])
        artifacts = overview.get("artifacts", [])

        conclusions: list[str] = []
        details: dict[str, Any] = {}

        # --- Severity distribution ---
        sev_counts: dict[str, int] = {}
        for f in findings:
            sev = str(f.get("severity", "low")).lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        details["severity_distribution"] = sev_counts

        total_findings = len(findings)
        crit_high = sev_counts.get("critical", 0) + sev_counts.get("high", 0)
        if total_findings == 0:
            conclusions.append("No findings were generated. The evidence may be benign or insufficient for automated analysis.")
        else:
            conclusions.append(
                f"Analysis produced {total_findings} finding(s): "
                f"{sev_counts.get('critical', 0)} critical, {sev_counts.get('high', 0)} high, "
                f"{sev_counts.get('medium', 0)} medium, {sev_counts.get('low', 0)} low."
            )
            if crit_high > 0:
                ratio = crit_high / total_findings
                if ratio >= 0.5:
                    conclusions.append(
                        f"⚠ {crit_high}/{total_findings} findings ({ratio:.0%}) are critical or high severity — "
                        "this strongly suggests malicious activity requiring immediate incident response."
                    )
                else:
                    conclusions.append(
                        f"{crit_high} critical/high severity finding(s) detected — manual review recommended."
                    )

        # --- MITRE ATT&CK tactic coverage ---
        tactics: dict[str, int] = {}
        techniques: set[str] = set()
        for f in findings:
            tactic = str(f.get("tactic", "") or "").strip()
            if tactic and tactic != "—":
                tactics[tactic] = tactics.get(tactic, 0) + 1
            tech = str(f.get("technique") or f.get("technique_id") or "").strip()
            if tech and tech != "—":
                techniques.add(tech)
        details["mitre_tactics"] = tactics
        details["mitre_techniques"] = sorted(techniques)

        if tactics:
            top_tactic = max(tactics, key=lambda k: tactics[k])
            conclusions.append(
                f"Attack lifecycle spans {len(tactics)} MITRE ATT&CK tactic(s); "
                f"dominant tactic: '{top_tactic}' ({tactics[top_tactic]} finding(s))."
            )
            kill_chain = [
                "initial-access", "execution", "persistence", "privilege-escalation",
                "defense-evasion", "credential-access", "discovery", "lateral-movement",
                "collection", "command-and-control", "exfiltration", "impact",
            ]
            detected_phases = [t for t in kill_chain if t in tactics]
            if len(detected_phases) >= 3:
                conclusions.append(
                    f"Multi-stage attack pattern detected across kill chain phases: "
                    f"{', '.join(detected_phases)}."
                )

        # --- IOC summary ---
        if iocs:
            ioc_types: dict[str, int] = {}
            for ioc in iocs:
                it = str(ioc.get("ioc_type") or ioc.get("type") or "unknown")
                ioc_types[it] = ioc_types.get(it, 0) + 1
            details["ioc_type_distribution"] = ioc_types
            ioc_summary_parts = [f"{count} {t}" for t, count in sorted(ioc_types.items(), key=lambda x: -x[1])]
            conclusions.append(
                f"{len(iocs)} Indicator(s) of Compromise extracted: {', '.join(ioc_summary_parts)}."
            )
        else:
            conclusions.append("No IOCs were extracted from the evidence.")

        # --- Timeline analysis ---
        if timeline:
            risk_scores = [
                float(ev.get("risk_score", 0))
                for ev in timeline
                if ev.get("risk_score") is not None
            ]
            high_risk_events = [ev for ev in timeline if float(ev.get("risk_score", 0)) >= 70]
            details["timeline_events"] = len(timeline)
            details["high_risk_events"] = len(high_risk_events)

            if risk_scores:
                avg_risk = sum(risk_scores) / len(risk_scores)
                max_risk = max(risk_scores)
                details["avg_risk_score"] = round(avg_risk, 1)
                details["max_risk_score"] = max_risk
                conclusions.append(
                    f"Timeline contains {len(timeline)} event(s); "
                    f"average risk score {avg_risk:.1f}, peak {max_risk:.0f}."
                )

            if high_risk_events:
                conclusions.append(
                    f"{len(high_risk_events)} high-risk event(s) (≥70) detected in the timeline — "
                    "these warrant prioritized investigation."
                )

        # --- Evidence scope ---
        if artifacts:
            conclusions.append(
                f"Evidence corpus contains {len(artifacts)} artifact(s) across the case evidence directory."
            )

        # --- Risk verdict ---
        if crit_high >= 3 or (len(high_risk_events) if timeline else 0) >= 5:
            verdict = "HIGH"
            verdict_text = "This case exhibits strong indicators of compromise and warrants immediate escalation."
        elif crit_high >= 1 or total_findings >= 3:
            verdict = "MEDIUM"
            verdict_text = "This case contains notable findings that require analyst review and potential escalation."
        else:
            verdict = "LOW"
            verdict_text = "This case shows limited or no indicators of compromise based on automated analysis."
        details["risk_verdict"] = verdict

        conclusions.append(f"Overall risk assessment: {verdict}. {verdict_text}")

        return {
            "case_id": case_id,
            "conclusions": conclusions,
            "details": details,
            "risk_verdict": verdict,
            "total_findings": total_findings,
            "total_iocs": len(iocs),
            "total_timeline_events": len(timeline),
        }

    # ------------------------------------------------------------------
    # Timeline filtering
    # ------------------------------------------------------------------

    def filter_timeline(
        self,
        case_id: str,
        after: str | None = None,
        before: str | None = None,
        min_risk: float | None = None,
        event_type: str | None = None,
        keyword: str | None = None,
        limit: int = 500,
    ) -> dict[str, Any]:
        """Filter stored timeline events by date range, risk, type, and keyword."""
        case_id = validate_case_id(case_id)
        self.require_case(case_id)
        events = self.db.get_timeline(case_id)
        filtered: list[dict[str, Any]] = []
        after_lower = (after or "").strip()
        before_lower = (before or "").strip()
        event_type_lower = (event_type or "").strip().lower()
        keyword_lower = (keyword or "").strip().lower()
        limit = max(1, min(10_000, int(limit)))

        for ev in events:
            ts = str(ev.get("timestamp") or "")

            if after_lower and ts < after_lower:
                continue
            if before_lower and ts > before_lower:
                continue

            risk = float(ev.get("risk_score", 0))
            if min_risk is not None and risk < min_risk:
                continue

            if event_type_lower:
                ev_type = str(ev.get("event_type") or "").lower()
                if event_type_lower not in ev_type:
                    continue

            if keyword_lower:
                blob = " ".join([
                    str(ev.get("description") or ""),
                    str(ev.get("event_type") or ""),
                    str(ev.get("source_file") or ""),
                ]).lower()
                if keyword_lower not in blob:
                    continue

            filtered.append(ev)
            if len(filtered) >= limit:
                break

        return {
            "case_id": case_id,
            "total_events": len(events),
            "matched_events": len(filtered),
            "filters": {
                "after": after_lower or None,
                "before": before_lower or None,
                "min_risk": min_risk,
                "event_type": event_type_lower or None,
                "keyword": keyword_lower or None,
            },
            "events": filtered,
        }

    # ------------------------------------------------------------------
    # Watcher / drop-folder support
    # ------------------------------------------------------------------

    def _ensure_ingest_root(self, path: Path) -> None:
        """Append *path* to allowed_ingest_roots if not already present.

        Safe because ``AppConfig.allowed_ingest_roots`` is a plain list.
        """
        resolved = path.resolve()
        if resolved not in self.config.allowed_ingest_roots:
            self.config.allowed_ingest_roots.append(resolved)

    def extract_image_artifacts(
        self,
        image_path: Path,
        staging_dir: Path,
        case_id: str | None = None,
    ) -> dict[str, Any]:
        """Mount *image_path*, extract artifacts to *staging_dir*, then unmount.

        Does NOT create a case or ingest artifacts — call ``ingest_case``
        separately after confirming the result.

        Returns the result dict from ``extract_image_to_staging``.
        """
        from .disk_image import extract_image_to_staging

        image_path = image_path.expanduser().resolve()
        staging_dir = staging_dir.expanduser().resolve()

        result = extract_image_to_staging(
            image_path,
            staging_dir,
            max_file_size_bytes=self.config.security_policy.max_file_size_bytes,
        )

        if case_id is not None:
            try:
                validate_case_id(case_id)
                self.db.append_audit_log(
                    action="image_extracted",
                    actor="system",
                    details={
                        "image": str(image_path),
                        "staging_dir": str(staging_dir),
                        "mounted": result.get("mounted"),
                        "artifacts_copied": result.get("artifacts_copied", 0),
                    },
                    case_id=case_id,
                )
            except Exception as exc:
                logger.debug("Could not append audit log for image extraction: %s", exc)

        return result

    def process_drop_item(
        self,
        item_path: Path,
        case_id: str,
        enable_llm: bool = True,
        auto_extract: bool = True,
    ) -> dict[str, Any]:
        """Trusted entry point for the drop-folder watcher.

        Creates a case, extracts artifacts from a disk image (if applicable),
        ingests the evidence directory, and runs analysis synchronously.

        Returns a summary dict with ``case_id``, ``artifacts``, and
        ``findings`` keys.
        """
        from .disk_image import is_disk_image

        item_path = item_path.expanduser().resolve()
        case_id = validate_case_id(case_id)

        self.create_case(case_id)

        if item_path.is_file() and is_disk_image(item_path) and auto_extract:
            staging = self.config.cases_dir / case_id / "extracted"
            self._ensure_ingest_root(staging)
            self.extract_image_artifacts(item_path, staging, case_id=case_id)
            source_dir = staging
        else:
            self._ensure_ingest_root(item_path)
            source_dir = item_path

        self.ingest_case(case_id, source_dir)
        self.analyze_case(case_id, enable_llama=enable_llm)
        overview = self.case_overview(case_id)

        return {
            "case_id": case_id,
            "artifacts": len(overview.get("artifacts", [])),
            "findings": len(overview.get("findings", [])),
        }

    # -------------------------------------------------------------------------
    # Threat Intelligence feeds
    # -------------------------------------------------------------------------
    def _ensure_ti_manager(self) -> TIFeedManager | None:
        """Initialize TI feed manager if configured."""
        if TIFeedManager is None:
            return None
        if not hasattr(self, "_ti_manager"):
            ti_config_path = self.config.data_dir / "ti_config.json"
            if ti_config_path.exists():
                import json
                cfg_data = json.loads(ti_config_path.read_text())
                cfg = TIFeedConfig(
                    cache_dir=Path(cfg_data.get("cache_dir", self.config.data_dir / "ti_cache")),
                    feeds=cfg_data.get("feeds", []),
                    ttl_seconds=cfg_data.get("ttl_seconds", 86400),
                )
            else:
                cfg = TIFeedConfig(
                    cache_dir=self.config.data_dir / "ti_cache",
                    feeds=[],
                )
            self._ti_manager = TIFeedManager(cfg, self.db)
        return self._ti_manager

    def update_ti_feeds(self) -> dict:
        """Update all configured TI feeds."""
        manager = self._ensure_ti_manager()
        if manager is None:
            return {"status": "error", "message": "TI module not available"}
        return manager.update_feeds()

    def lookup_ti_ioc(self, ioc_type: str, value: str) -> dict | None:
        """Look up an IOC in the TI cache."""
        manager = self._ensure_ti_manager()
        if manager is None:
            return None
        rec = manager.lookup_ioc(ioc_type, value)
        return rec.to_dict() if rec else None

    def get_ti_feed_status(self) -> dict:
        """Get TI feed cache status."""
        manager = self._ensure_ti_manager()
        if manager is None:
            return {"cached_records": 0, "feeds_configured": 0}
        return manager.get_feed_status()

    def enrich_case_with_ti(self, case_id: str) -> dict:
        """Enrich case IOCs with TI data."""
        validate_case_id(case_id)
        manager = self._ensure_ti_manager()
        if manager is None:
            return {"error": "TI module not available"}
        return manager.enrich_case_iocs(case_id)

    # -------------------------------------------------------------------------
    # Case comparison
    # -------------------------------------------------------------------------
    def compare_cases(
        self,
        case_a_id: str,
        case_b_id: str,
        diff_type: str = "all",
    ) -> dict:
        """Compare two cases and return a diff report."""
        validate_case_id(case_a_id)
        validate_case_id(case_b_id)
        if CaseDiffer is None:
            return {"error": "Case diff module not available"}
        differ = CaseDiffer(self.db)
        dt = DiffType(diff_type) if DiffType else "all"
        result = differ.compare_cases(case_a_id, case_b_id, dt)
        return result.to_dict()

    def diff_report_md_html(
        self,
        case_a_id: str,
        case_b_id: str,
        fmt: str = "md",
    ) -> str:
        """Generate a human-readable diff report."""
        validate_case_id(case_a_id)
        validate_case_id(case_b_id)
        if CaseDiffer is None:
            return "Error: Case diff module not available"
        differ = CaseDiffer(self.db)
        result = differ.compare_cases(case_a_id, case_b_id)
        return differ.generate_diff_report(result, fmt)

    # -------------------------------------------------------------------------
    # Alerts
    # -------------------------------------------------------------------------
    def _ensure_alert_manager(self) -> AlertManager | None:
        """Initialize alert manager."""
        if AlertManager is None:
            return None
        if not hasattr(self, "_alert_manager"):
            rules_path = self.config.data_dir / "alert_rules.json"
            self._alert_manager = AlertManager(rules_path)
        return self._alert_manager

    def list_alert_rules(self) -> list[dict]:
        """List configured alert rules."""
        manager = self._ensure_alert_manager()
        if manager is None:
            return []
        return [r.to_dict() for r in manager.rules]

    def add_alert_rule(self, rule_dict: dict) -> bool:
        """Add a new alert rule."""
        manager = self._ensure_alert_manager()
        if manager is None or AlertRule is None:
            return False
        rule = AlertRule(
            rule_id=rule_dict.get("rule_id", ""),
            name=rule_dict.get("name", ""),
            description=rule_dict.get("description", ""),
            enabled=rule_dict.get("enabled", True),
            trigger_condition=rule_dict.get("trigger_condition", {}),
            channels=[],
            webhook_url=rule_dict.get("webhook_url"),
            email_recipients=rule_dict.get("email_recipients", []),
        )
        manager.add_rule(rule)
        return True

    def remove_alert_rule(self, rule_id: str) -> bool:
        """Remove an alert rule."""
        manager = self._ensure_alert_manager()
        if manager is None:
            return False
        return manager.remove_rule(rule_id)

    def run_alert_evaluation(self, case_id: str) -> list[dict]:
        """Run case through alerting rules."""
        validate_case_id(case_id)
        manager = self._ensure_alert_manager()
        if manager is None:
            return []
        overview = self.case_overview(case_id)
        alerts = manager.evaluate_case(case_id, overview)
        return [a.to_dict() for a in alerts]

    def test_webhook(self, url: str) -> bool:
        """Test webhook connectivity."""
        manager = self._ensure_alert_manager()
        if manager is None:
            return False
        return manager.test_webhook(url)
