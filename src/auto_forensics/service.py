from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import tempfile
import threading
import uuid
import zipfile
from concurrent.futures import Future, ThreadPoolExecutor
from functools import wraps
from pathlib import Path
from typing import Any, Callable

from .archives import archive_relative_path, extract_verified_archive, record_archive_path
from .case_integrity import custody_changes, inspect_case_integrity, verified_case_report
from .case_manager import CaseManager, IngestResult
from .config import AppConfig
from .db import Database
from .db_backend import DatabaseBackend
from .db_sqlalchemy import SQLAlchemyDatabase
from .file_ops import directory_lock
from .integrity import compare_inventory
from .ioc_enrichment import EnrichmentConfig, enabled_providers, enrich_ioc
from .manifest import hash_input_tree
from .models import IOC, IOCEnrichment, utc_now_iso
from .pipeline import PipelineConfig, run_case
from .plugins import PluginRegistry
from .reviews import ReviewError, record_review_locked
from .security import SecurityError, bounded_tree_paths, sha256_file, stays_in_tree, validate_case_id


def _case_operation(method: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(method)
    def locked(self: AutoForensicsService, case_id: str, *args: Any, **kwargs: Any) -> Any:
        with directory_lock(self.case_manager.case_root(case_id)):
            return method(self, case_id, *args, **kwargs)

    return locked


def _background_submission(method: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(method)
    def submit(self: AutoForensicsService, *args: Any, **kwargs: Any) -> Any:
        # Serialize the check/create/submit sequence, including shutdown.
        # Status callbacks use their own locks and can run immediately.
        with self._submission_lock:
            if self._closed:
                raise SecurityError("Service is shutting down; no new background jobs are accepted")
            return method(self, *args, **kwargs)

    return submit


class AutoForensicsService:
    """Case lifecycle: create, ingest, analyse, and report.

    Analysis keeps a finding only when the pipeline can cite an
    ingested artifact. ``review_status`` stays ``unverified`` until
    ``auto-forensics review`` records an analyst decision on a run
    directory.
    """
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
        self._analysis_jobs: dict[str, Future[dict[str, Any]]] = {}
        self._analysis_status: dict[str, dict[str, Any]] = {}
        self._analysis_job_ids: dict[str, str] = {}
        self._enrichment_jobs: dict[str, Future[dict[str, Any]]] = {}
        self._enrichment_status: dict[str, dict[str, Any]] = {}
        self._enrichment_job_ids: dict[str, str] = {}
        self._analysis_lock = threading.Lock()
        self._enrichment_lock = threading.Lock()
        self._submission_lock = threading.Lock()
        self._shutdown_lock = threading.Lock()
        self._closed = False
        self.cleanup_job_history(retention_days=self.config.job_retention_days)

    def close(self) -> None:
        """Drain accepted jobs before disposing database connections; idempotent."""
        with self._shutdown_lock:
            if self._closed:
                return
            with self._submission_lock:
                self._closed = True
            self._analysis_executor.shutdown(wait=True)
            self._enrichment_executor.shutdown(wait=True)
            if isinstance(self.db, SQLAlchemyDatabase):
                self.db.engine.dispose()

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
        return {
            "trimmed_analysis_futures": trimmed_analysis,
            "trimmed_enrichment_futures": trimmed_enrichment,
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

    @_case_operation
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

    def list_cases(self) -> list[dict[str, Any]]:
        return self.db.list_cases()

    def require_case(self, case_id: str) -> dict[str, Any]:
        case_id = validate_case_id(case_id)
        value = self.db.get_case(case_id)
        if not value:
            raise SecurityError(f"Case not found: {case_id}")
        expected = {
            "evidence_dir": self.case_manager.evidence_dir(case_id),
            "output_dir": self.case_manager.output_dir(case_id),
        }
        for key, path in expected.items():
            recorded = value.get(key)
            if not isinstance(recorded, str) or Path(recorded).resolve() != path.resolve():
                raise SecurityError("Stored case paths do not match the configured case directory")
        return value

    @_case_operation
    def ingest_case(self, case_id: str, source_dir: Path) -> dict[str, Any]:
        case = self.require_case(case_id)
        source_dir = self._validate_ingest_source(source_dir)
        previous = {row["rel_path"]: row for row in self.db.get_artifacts(case_id)}
        evidence_root = Path(case["evidence_dir"])
        if any(custody_changes(self.db, case).values()):
            raise SecurityError("Stored evidence no longer matches its custody hash or contains unindexed files")
        self.db.set_case_status(case_id, "ingesting", None)
        intake: IngestResult | None = None
        try:
            intake = self.case_manager.ingest_directory_detailed(case_id, source_dir)
            entries = intake.entries
            published = {str(path.relative_to(evidence_root)) for path in intake.published_paths}
            if {entry.rel_path for entry in entries} != previous.keys() | published or any(
                entry.rel_path in previous and (
                    entry.sha256.lower() != previous[entry.rel_path]["sha256"].lower()
                    or entry.size_bytes != previous[entry.rel_path]["size_bytes"]
                ) for entry in entries
            ):
                raise SecurityError("Existing evidence changed during ingestion; custody was not replaced")
            for entry in entries:
                if entry.rel_path in previous:
                    entry.metadata = dict(previous[entry.rel_path].get("metadata") or {})
            added_count = sum(entry.rel_path not in previous for entry in entries)
            self.db.ingest_case_records(
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
                {"ingested_files": added_count, "total_evidence_files": len(entries), "source_dir": str(source_dir),
                 "skipped_counts": intake.skipped_counts},
            )
        except Exception as exc:
            if intake is not None:
                try:
                    current = {row["rel_path"]: row for row in self.db.get_artifacts(case_id)}
                except Exception:
                    raise SecurityError("Ingest database outcome is uncertain; new evidence was preserved for recovery") from exc
                if current != previous:
                    raise SecurityError("Ingest may have committed; new evidence was preserved. Check case integrity before retrying") from exc
                self.db.set_case_status(case_id, "failed", str(exc))
                self.case_manager.rollback_ingest(case_id, intake)
            else:
                self.db.set_case_status(case_id, "failed", str(exc))
            raise
        return {
            "case": case_id,
            "evidence_dir": case["evidence_dir"],
            "ingested_files": added_count,
            "total_evidence_files": len(entries),
            "skipped_entries": intake.skipped_entries,
            "skipped_counts": intake.skipped_counts,
            "skipped_entries_truncated": intake.skipped_entries_truncated,
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

        # Provider results are mutable cache data, exposed in the case overview.
        # As in synchronous analysis, preserve the reproducible, hashed report
        # and any analyst decisions published while provider requests ran.

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

    @_background_submission
    def enrich_case_iocs_async(self, case_id: str) -> dict[str, Any]:
        case_id = validate_case_id(case_id)
        self.require_case(case_id)
        job_id = f"enrich-{uuid.uuid4().hex[:16]}"

        with self._enrichment_lock:
            existing = self._enrichment_jobs.get(case_id)
            if existing is not None and not existing.done():
                return {
                    "case_id": case_id,
                    "accepted": False,
                    "detail": "IOC enrichment already running.",
                    "status": self._enrichment_status.get(case_id),
                }

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
            self._enrichment_jobs[case_id] = future
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

    @_background_submission
    def analyze_case_async(self, case_id: str, enable_llama: bool = True) -> dict[str, Any]:
        case_id = validate_case_id(case_id)
        self.require_case(case_id)
        job_id = f"job-{uuid.uuid4().hex[:16]}"
        with self._analysis_lock:
            existing = self._analysis_jobs.get(case_id)
            if existing is not None and not existing.done():
                return {
                    "case_id": case_id,
                    "accepted": False,
                    "detail": "Analysis already running.",
                    "status": self._analysis_status.get(case_id),
                }

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
            self._analysis_jobs[case_id] = future
            self._analysis_job_ids[case_id] = job_id
        return {
            "case_id": case_id,
            "job_id": job_id,
            "accepted": True,
            "detail": "Analysis started.",
            "status": self.get_case_status(case_id),
        }

    @_case_operation
    def analyze_case(
        self,
        case_id: str,
        enable_llama: bool = True,
        progress_callback: Any | None = None,
        llm_provider: str | None = None,
    ) -> dict[str, Any]:
        """Run the pipeline for one case and return paths to the report and manifest."""
        case = self.require_case(case_id)
        evidence_dir = Path(case["evidence_dir"])
        output_dir = Path(case["output_dir"])
        if not evidence_dir.exists():
            raise SecurityError(f"Evidence directory not found for case: {case_id}")
        if any(custody_changes(self.db, case).values()):
            raise SecurityError("Evidence does not match its custody index; analysis was not started")
        expected_inputs = [
            {"path": row["rel_path"], "sha256": row["sha256"], "size_bytes": row["size_bytes"]}
            for row in self.db.get_artifacts(case_id)
        ]

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
                    llm_provider=llm_provider,
                    expected_input_files=expected_inputs,
                    require_safe_input_tree=True,
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
            # case_report.json stays as run_case wrote it. That is the
            # file the manifest hashed. Enrichment is in the database
            # and in the return value of this method.
            self.db.set_case_status(case_id, "complete", None)
            self.db.append_audit_log(
                action="case_analyzed",
                actor="system",
                details={
                    "findings": len(report.findings),
                    "timeline_events": len(report.timeline),
                    "iocs": len(report.iocs),
                    "ioc_enrichments": len(report.enrichments),
                },
                case_id=case_id,
            )
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
            "output_pdf": str(output_dir / "case_report.pdf") if (output_dir / "case_report.pdf").is_file() else None,
            "output_attack_navigator": str(output_dir / "attack_navigator_layer.json"),
            "output_stix": str(output_dir / "case_stix_bundle.json"),
            "output_manifest": str(output_dir / "run_manifest.json"),
        }

    def case_overview(self, case_id: str) -> dict[str, Any]:
        case = self.require_case(case_id)
        artifacts = self.db.get_artifacts(case_id)
        findings = self.db.get_findings(case_id)
        timeline = self.db.get_timeline(case_id)
        iocs = self.db.get_case_iocs(case_id)
        ioc_enrichments = self.db.get_case_ioc_enrichments(case_id)
        notes = self.db.get_analyst_notes(case_id)
        evidence_hash_log = self.db.get_evidence_hash_log(case_id)
        audit_log = self.db.get_audit_log(case_id=case_id, limit=500)
        latest_job = self.db.get_case_latest_job(case_id, job_type="analysis")
        latest_enrichment_job = self.db.get_case_latest_job(case_id, job_type="enrichment")
        report_path = Path(case["output_dir"]) / "case_report.json"
        summary: dict[str, Any] = {}
        if report_path.exists():
            try:
                payload = json.loads(report_path.read_text(encoding="utf-8"))
                if isinstance(payload, dict):
                    summary = payload.get("summary", {})
            except json.JSONDecodeError:
                summary = {}
        return {
            "case": case,
            "artifacts": artifacts,
            "findings": findings,
            "timeline": timeline,
            "iocs": iocs,
            "ioc_enrichments": ioc_enrichments,
            "notes": notes,
            "evidence_hash_log": evidence_hash_log,
            "audit_log": audit_log,
            "latest_job": latest_job,
            "latest_enrichment_job": latest_enrichment_job,
            "summary": summary,
        }

    @_case_operation
    def check_case_integrity(self, case_id: str) -> dict[str, Any]:
        case = self.require_case(case_id)
        with directory_lock(Path(case["output_dir"])):
            return inspect_case_integrity(self.db, case)

    @_case_operation
    def sync_case_report(self, case_id: str) -> dict[str, Any]:
        """Repair findings/timeline views from the verified saved report."""
        case = self.require_case(case_id)
        with directory_lock(Path(case["output_dir"])):
            if any(custody_changes(self.db, case).values()):
                raise SecurityError("Evidence differs from its custody index; refusing to synchronize")
            report = verified_case_report(case)
            self.db.replace_findings_and_timeline(case_id, report.findings, report.timeline)
            self.db.append_audit_log(
                action="report_projection_synchronized", actor="system", case_id=case_id,
                details={"findings": len(report.findings), "timeline_events": len(report.timeline)},
            )
        return {"case_id": case_id, "findings": len(report.findings), "timeline_events": len(report.timeline)}

    @_case_operation
    def review_finding(
        self, case_id: str, *, finding_id: str, decision: str, actor: str,
        note: str = "", override: bool = False,
    ) -> dict[str, Any]:
        case = self.require_case(case_id)
        output = Path(case["output_dir"])
        with directory_lock(output):
            integrity = inspect_case_integrity(self.db, case)
            if not integrity["match"] or not integrity["report_present"]:
                raise ReviewError("Case integrity check failed; inspect check-case and use sync-report for a stale database view")
            entry = record_review_locked(
                output, finding_id=finding_id, decision=decision, actor=actor,
                note=note, override=override, input_dir=Path(case["evidence_dir"]),
            )
            report = verified_case_report(case)
            try:
                self.db.update_finding_reviews(case_id, report.findings)
            except Exception as exc:
                raise ReviewError("Review was saved in the report, but its database view could not be updated; run sync-report") from exc
            self.db.append_audit_log(action="finding_reviewed", actor=entry["actor"], case_id=case_id, details=entry)
        return entry

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

    def list_case_notes(self, case_id: str) -> list[dict[str, Any]]:
        case_id = validate_case_id(case_id)
        self.require_case(case_id)
        return self.db.get_analyst_notes(case_id)

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
        version = manifest.get("archive_version", 1)
        if type(version) is not int or version not in {1, 2}:
            raise SecurityError("Unsupported archive version")
        if version == 2:
            algorithm = manifest.get("integrity_algorithm")
            if algorithm == "sha256":
                return hashlib.sha256(payload).hexdigest()
            if algorithm == "hmac-sha256" and self.config.api_key_hash:
                return hmac.new(self.config.api_key_hash.encode("utf-8"), payload, hashlib.sha256).hexdigest()
            raise SecurityError("Archive requires an unavailable integrity key or algorithm")
        # Read legacy archives, whose default public salt was a checksum,
        # not an authentication key.
        salt = (self.config.api_key_hash or "auto-forensics").encode("utf-8")
        return hashlib.sha256(payload + salt).hexdigest()

    def _verify_archive_signature(self, manifest: dict[str, Any]) -> None:
        from .manifest import valid_digest

        expected = manifest.get("signature")
        if not valid_digest(expected):
            raise SecurityError("Archive has an invalid integrity digest")
        unsigned = {key: value for key, value in manifest.items() if key != "signature"}
        if not hmac.compare_digest(expected.lower(), self._archive_signature(unsigned)):
            raise SecurityError("Archive integrity verification failed")

    def export_case_archive(self, case_id: str, destination_zip: Path) -> dict[str, Any]:
        case = self.require_case(case_id)
        case_root = Path(case["evidence_dir"]).parent
        if not case_root.exists() or not case_root.is_dir():
            raise SecurityError(f"Case root not found for export: {case_root}")

        destination_zip = destination_zip.expanduser()
        if destination_zip.is_symlink():
            raise SecurityError("Archive destination must not be a symlink")
        destination_zip = destination_zip.resolve()
        if destination_zip.is_relative_to(case_root.resolve()):
            raise SecurityError("Archive destination must be outside the case directory")
        destination_zip.parent.mkdir(parents=True, exist_ok=True)
        policy = self.config.security_policy

        def inventory() -> list[dict[str, Any]]:
            rows: list[dict[str, Any]] = []
            names: set[str] = set()
            spellings: dict[str, str] = {}
            total_bytes = 0
            for path in sorted(bounded_tree_paths(case_root, max_entries=50_032, max_depth=22)):
                relative = path.relative_to(case_root)
                if relative.parts[0].startswith(".af-"):
                    continue
                if path.is_symlink():
                    raise SecurityError("Case export refuses symlinks")
                if not path.is_dir() and not path.is_file():
                    raise SecurityError("Case export refuses special files")
                if not stays_in_tree(path, case_root):
                    continue
                name = archive_relative_path(relative.as_posix())
                record_archive_path(name, spellings)
                if name.casefold() in names:
                    raise SecurityError("Case has paths that alias on another operating system")
                names.add(name.casefold())
                size = path.stat().st_size
                total_bytes += size
                if size > policy.max_file_size_bytes or total_bytes > policy.max_archive_size_bytes:
                    raise SecurityError("Case exceeds the archive size limits")
                if len(rows) >= min(policy.max_total_files + 16, 10_016):
                    raise SecurityError("Case exceeds the archive file count limit")
                rows.append({"rel_path": name, "sha256": sha256_file(path), "size_bytes": size})
            return rows

        temporary: Path | None = None
        with directory_lock(case_root), directory_lock(Path(case["output_dir"])):
            files = inventory()
            expected_evidence = [{"path": row["rel_path"], "sha256": row["sha256"], "size_bytes": row["size_bytes"]}
                                 for row in self.db.get_artifacts(case_id)]
            archived_evidence = [{"path": row["rel_path"][len("evidence/"):], "sha256": row["sha256"], "size_bytes": row["size_bytes"]}
                                 for row in files if row["rel_path"].startswith("evidence/")]
            # Bind the very bytes written to the ZIP to the custody baseline;
            # a separate successful disk check cannot authorize another snapshot.
            if any(compare_inventory(expected_evidence, archived_evidence).values()):
                raise SecurityError("Case evidence does not match its custody index; archive was not exported")
            if any(custody_changes(self.db, case).values()):
                raise SecurityError("Case evidence does not match its custody index; archive was not exported")
            manifest = {
                "archive_version": 2,
                "integrity_algorithm": "hmac-sha256" if self.config.api_key_hash else "sha256",
                "case_id": case_id,
                "created_at": case.get("created_at"),
                "exported_at": utc_now_iso(),
                "files": files,
            }
            manifest["signature"] = self._archive_signature(manifest)
            manifest_bytes = json.dumps(manifest, indent=2).encode("utf-8")
            if len(manifest_bytes) > 4 * 1024 * 1024 or len(manifest_bytes) + sum(row["size_bytes"] for row in files) > policy.max_archive_size_bytes:
                raise SecurityError("Case and manifest exceed the expanded archive size limit")
            try:
                with tempfile.NamedTemporaryFile(prefix=".af-export-", suffix=".zip", dir=destination_zip.parent, delete=False) as handle:
                    temporary = Path(handle.name)
                with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                    archive.writestr("manifest.json", manifest_bytes)
                    for item in files:
                        source_path = case_root / item["rel_path"]
                        if not stays_in_tree(source_path, case_root):
                            raise SecurityError("Case files changed during export")
                        digest = hashlib.sha256()
                        size = 0
                        with source_path.open("rb") as source, archive.open(item["rel_path"], "w") as target:
                            while chunk := source.read(1024 * 1024):
                                size += len(chunk)
                                if size > item["size_bytes"]:
                                    raise SecurityError("Case files changed during export")
                                digest.update(chunk)
                                target.write(chunk)
                        if size != item["size_bytes"] or digest.hexdigest() != item["sha256"]:
                            raise SecurityError("Case files changed during export")
                if inventory() != files:
                    raise SecurityError("Case files changed during export")
                if temporary.stat().st_size > policy.max_archive_size_bytes:
                    raise SecurityError("Archive exceeds the compressed size limit")
                if any(custody_changes(self.db, case).values()):
                    raise SecurityError("Case custody changed during export")
                os.replace(temporary, destination_zip)
            finally:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)

        self.db.append_audit_log(
            action="case_exported",
            actor="system",
            details={"archive": str(destination_zip), "files": len(files)},
            case_id=case_id,
        )
        return {
            "case_id": case_id, "archive": str(destination_zip), "files": len(files),
            "integrity_algorithm": manifest["integrity_algorithm"],
        }

    def import_case_archive(self, archive_path: Path, case_id_override: str | None = None) -> dict[str, Any]:
        archive_path = archive_path.expanduser().resolve()
        if not archive_path.exists() or not archive_path.is_file():
            raise SecurityError(f"Archive not found: {archive_path}")

        with tempfile.TemporaryDirectory(prefix=".af-import-", dir=self.config.cases_dir) as tmp:
            staging = Path(tmp) / "case"
            staging.mkdir()
            manifest = extract_verified_archive(archive_path, staging, self.config.security_policy, self._verify_archive_signature)
            archive_case_id = validate_case_id(str(manifest.get("case_id") or ""))
            case_id = validate_case_id(case_id_override) if case_id_override else archive_case_id
            case_root = self.case_manager.case_root(case_id)
            evidence_dir = case_root / "evidence"
            output_dir = case_root / "output"
            for directory in (staging / "evidence", staging / "output"):
                directory.mkdir(exist_ok=True)
            # Apply the same traversal bounds used by ingest, analysis, and
            # custody checks before any imported case becomes visible.
            hash_input_tree(staging / "evidence", max_files=min(self.config.security_policy.max_total_files, 10_000))
            with directory_lock(case_root):
                if self.db.get_case(case_id) or case_root.exists():
                    raise SecurityError(f"Case already exists: {case_id}")
                artifacts = [
                    {
                        "rel_path": str(Path(row["rel_path"]).relative_to("evidence")),
                        "artifact_type": Path(row["rel_path"]).suffix.lower().lstrip("."),
                        "size_bytes": row["size_bytes"], "sha256": row["sha256"].lower(),
                        "metadata": {"source_archive": str(archive_path)},
                    }
                    for row in manifest["files"] if Path(row["rel_path"]).parts[0] == "evidence"
                ]
                os.rename(staging, case_root)
                try:
                    self.db.import_case_records(
                        case_id, evidence_dir, output_dir, artifacts,
                        {"archive": str(archive_path), "source_case_id": archive_case_id},
                    )
                except Exception as exc:
                    # A lost commit acknowledgement is not proof of rollback.
                    # Preserve evidence if a fresh read cannot confirm absence.
                    try:
                        committed = self.db.get_case(case_id)
                    except Exception:
                        raise SecurityError("Import database outcome is uncertain; case files were preserved for recovery") from exc
                    if committed is not None:
                        raise SecurityError("Import may have committed; case files were preserved. Check case integrity before retrying") from exc
                    shutil.rmtree(case_root)
                    raise
            return {
                "case_id": case_id,
                "archive": str(archive_path),
                "evidence_dir": str(evidence_dir),
                "output_dir": str(output_dir),
                "archive_version": manifest.get("archive_version", 1),
                "integrity_algorithm": manifest.get("integrity_algorithm", "legacy-digest"),
            }

    def get_report(self, case_id: str, fmt: str = "json") -> str:
        case = self.require_case(case_id)
        output = Path(case["output_dir"])
        if fmt == "json":
            path = output / "case_report.json"
        elif fmt == "md":
            path = output / "case_report.md"
        elif fmt == "html":
            path = output / "case_report.html"
        elif fmt == "navigator":
            path = output / "attack_navigator_layer.json"
        elif fmt == "stix":
            path = output / "case_stix_bundle.json"
        else:
            raise SecurityError(
                "Unsupported report format. Use 'json', 'md', 'html', 'navigator', or 'stix'."
            )
        if not path.exists():
            raise SecurityError(f"Report not found: {path}")
        return path.read_text(encoding="utf-8")
