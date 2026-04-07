"""Job coordinator classes for managing background task state.

This module provides AnalysisCoordinator, EnrichmentCoordinator, and AgentCoordinator
classes that encapsulate ThreadPoolExecutor management and job state tracking.
"""

from __future__ import annotations

import threading
from concurrent.futures import Future
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING
from typing import Any

if TYPE_CHECKING:
    from .db_backend import DatabaseBackend


class JobCoordinator:
    """Base class for coordinating background job execution and state tracking.

    Subclasses should set:
        _executor: ThreadPoolExecutor instance
        _jobs: dict[str, Future] mapping case_id/session_id to Future
        _status: dict[str, dict] mapping case_id/session_id to status dict
        _job_ids: dict[str, str] mapping case_id/session_id to job_id
        _lock: threading.Lock
        _job_type: str for database job type
    """

    _executor: ThreadPoolExecutor
    _jobs: dict[str, Future[dict[str, Any]]]
    _status: dict[str, dict[str, Any]]
    _job_ids: dict[str, str]
    _lock: threading.Lock
    _job_type: str

    def get_status(self, case_id: str, db: "DatabaseBackend | None" = None) -> dict[str, Any]:
        """Get the current status of a job for a case."""
        with self._lock:
            cached = self._status.get(case_id)
            if cached:
                return dict(cached)
            job = self._jobs.get(case_id)
            job_id = self._job_ids.get(case_id)
            if job is not None and not job.done():
                return {
                    "case_id": case_id,
                    "job_id": job_id,
                    "state": "running",
                    "progress": 50,
                    "message": f"{self._job_type.title()} in progress",
                    "error": None,
                }

        if db is not None:
            db_job = db.get_case_latest_job(case_id, job_type=self._job_type)
            if db_job is not None:
                return db_job

        return {
            "case_id": case_id,
            "job_id": None,
            "state": "not_found",
            "progress": 0,
            "message": f"{self._job_type.title()} job not found",
            "error": "job_not_found",
        }

    def set_status(
        self,
        case_id: str,
        job_id: str,
        state: str,
        progress: int,
        message: str,
        error: str | None = None,
        result: dict[str, Any] | None = None,
        db: "DatabaseBackend | None" = None,
    ) -> None:
        """Update the status of a job."""
        payload: dict[str, Any] = {
            "case_id": case_id,
            "job_id": job_id,
            "state": state,
            "progress": max(0, min(100, int(progress))),
            "message": message,
            "error": error,
        }
        if result is not None:
            payload["result"] = result
        with self._lock:
            self._status[case_id] = payload
            self._job_ids[case_id] = job_id

        if db is not None:
            db.upsert_analysis_job(
                job_id=job_id,
                case_id=case_id,
                job_type=self._job_type,
                state=payload["state"],
                progress=payload["progress"],
                message=payload["message"],
                error=payload["error"],
                result=payload.get("result"),
            )

    def is_running(self, case_id: str) -> bool:
        """Check if a job is currently running for a case."""
        with self._lock:
            job = self._jobs.get(case_id)
            return job is not None and not job.done()

    def trim_completed_jobs(self) -> int:
        """Remove completed futures from local tracking. Returns count trimmed."""
        trimmed = 0
        with self._lock:
            for case_id, future in list(self._jobs.items()):
                if future.done():
                    self._jobs.pop(case_id, None)
                    trimmed += 1
        return trimmed

    def get_job_id(self, case_id: str) -> str | None:
        """Get the job ID for a case."""
        with self._lock:
            return self._job_ids.get(case_id)

    def get_future(self, case_id: str) -> Future[dict[str, Any]] | None:
        """Get the future for a case's job."""
        with self._lock:
            return self._jobs.get(case_id)

    def submit(self, case_id: str, job_id: str, fn: Any, *args: Any, **kwargs: Any) -> None:
        """Submit a job for execution."""
        with self._lock:
            self._jobs[case_id] = self._executor.submit(fn, *args, **kwargs)
            self._job_ids[case_id] = job_id


class AnalysisCoordinator(JobCoordinator):
    """Coordinates background analysis jobs."""

    def __init__(self) -> None:
        self._executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="auto-forensics")
        self._jobs: dict[str, Future[dict[str, Any]]] = {}
        self._status: dict[str, dict[str, Any]] = {}
        self._job_ids: dict[str, str] = {}
        self._lock = threading.Lock()
        self._job_type = "analysis"


class EnrichmentCoordinator(JobCoordinator):
    """Coordinates background IOC enrichment jobs."""

    def __init__(self) -> None:
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="auto-forensics-enrich")
        self._jobs: dict[str, Future[dict[str, Any]]] = {}
        self._status: dict[str, dict[str, Any]] = {}
        self._job_ids: dict[str, str] = {}
        self._lock = threading.Lock()
        self._job_type = "enrichment"


class AgentCoordinator(JobCoordinator):
    """Coordinates background agent session jobs."""

    def __init__(self) -> None:
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="auto-forensics-agent")
        self._jobs: dict[str, Future[dict[str, Any]]] = {}
        self._status: dict[str, dict[str, Any]] = {}
        self._job_ids: dict[str, str] = {}
        self._lock = threading.Lock()
        self._job_type = "agent"

    def get_status(self, session_id: str, db: "DatabaseBackend | None" = None) -> dict[str, Any]:
        """Get agent session status. Note: session_id used instead of case_id."""
        with self._lock:
            cached = self._status.get(session_id)
            if cached:
                return dict(cached)
            job = self._jobs.get(session_id)
            job_id = self._job_ids.get(session_id)
            if job is not None and not job.done():
                return {
                    "session_id": session_id,
                    "job_id": job_id,
                    "state": "running",
                    "message": "Agent session in progress",
                    "error": None,
                }

        return {
            "session_id": session_id,
            "job_id": None,
            "state": "not_found",
            "message": "Agent session job not found",
            "error": "session_not_found",
        }
