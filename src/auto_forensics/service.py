from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
import hashlib
import json
import logging
import shutil
import threading
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
from .ioc_enrichment import EnrichmentConfig, enabled_providers, enrich_ioc
from .models import IOC, IOCEnrichment, utc_now_iso
from .pipeline import PipelineConfig, run_case
from .plugins import PluginRegistry
from .security import SecurityError, sha256_file, validate_case_id


class AutoForensicsService:
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
        try:
            self.cleanup_job_history(retention_days=self.config.job_retention_days)
        except Exception as exc:
            logger.warning("Job history cleanup failed on init: %s", exc)

    def shutdown(self) -> None:
        self._analysis_executor.shutdown(wait=False)
        self._enrichment_executor.shutdown(wait=False)

    def __del__(self) -> None:
        try:
            self.shutdown()
        except Exception:
            pass

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
            "output_pdf": str(output_dir / "case_report.pdf"),
            "output_attack_navigator": str(output_dir / "attack_navigator_layer.json"),
            "output_stix": str(output_dir / "case_stix_bundle.json"),
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
        salt = (self.config.api_key_hash or "auto-forensics").encode("utf-8")
        return hashlib.sha256(payload + salt).hexdigest()

    def export_case_archive(self, case_id: str, destination_zip: Path) -> dict[str, Any]:
        case = self.require_case(case_id)
        case_root = Path(case["evidence_dir"]).parent
        if not case_root.exists() or not case_root.is_dir():
            raise SecurityError(f"Case root not found for export: {case_root}")

        files: list[dict[str, Any]] = []
        for path in sorted(case_root.rglob("*")):
            if not path.is_file():
                continue
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
            tmp_root = Path(tmp)
            with zipfile.ZipFile(archive_path, "r") as archive:
                for member in archive.infolist():
                    member_name = member.filename
                    candidate = (tmp_root / member_name).resolve()
                    try:
                        candidate.relative_to(tmp_root.resolve())
                    except ValueError as exc:
                        raise SecurityError(f"Archive path escapes extraction root: {member_name}") from exc
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
                src = tmp_root / rel_path
                dst = case_root / rel_path
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
        walker = resolved.rglob("*") if recursive else resolved.glob("*")
        for p in walker:
            if p.is_file():
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
