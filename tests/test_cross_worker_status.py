"""Polling must report the shared latest job across service worker caches."""
from __future__ import annotations

import threading

import pytest

import test_case_scoped_findings as existing
from auto_forensics.service import AutoForensicsService
from test_api_endpoints import _config

database_backend = existing.database_backend


@pytest.mark.parametrize("kind", ["analysis", "enrichment"])
def test_completed_worker_cache_cannot_hide_new_shared_job(database_backend, tmp_path, monkeypatch, kind):
    import auto_forensics.service as service_module

    config = _config(tmp_path)
    first, second = AutoForensicsService(config), AutoForensicsService(config)
    first.db = second.db = database_backend
    entered, release = threading.Event(), threading.Event()
    case_id = "cross-worker-status"
    start = "analyze_case_async" if kind == "analysis" else "enrich_case_iocs_async"
    jobs = "_analysis_jobs" if kind == "analysis" else "_enrichment_jobs"
    getter = "get_case_status" if kind == "analysis" else "get_case_enrichment_status"
    try:
        first.create_case(case_id)
        options = {"enable_llama": False} if kind == "analysis" else {}
        old = getattr(first, start)(case_id, **options)
        getattr(first, jobs)[case_id].result(timeout=10)
        assert getattr(first, getter)(case_id)["state"] == "complete"
        if kind == "analysis":
            original = service_module.run_case

            def block(config):
                entered.set()
                assert release.wait(10)
                return original(config)

            monkeypatch.setattr(service_module, "run_case", block)
        else:
            original = second._enrich_iocs_with_cache

            def block(iocs):
                entered.set()
                assert release.wait(10)
                return original(iocs)

            monkeypatch.setattr(second, "_enrich_iocs_with_cache", block)
        new = getattr(second, start)(case_id, **options)
        assert entered.wait(5)
        observed = getattr(first, getter)(case_id)
        assert observed["job_id"] == new["job_id"] != old["job_id"]
        assert observed["state"] == "running"
        # A late completion/heartbeat from the older worker must not become the
        # "latest" job merely because its updated_at is now the newest value.
        setter = first._set_analysis_status if kind == "analysis" else first._set_enrichment_status
        setter(case_id, old["job_id"], "complete", 100, "Older completion observed late")
        assert getattr(first, getter)(case_id)["job_id"] == new["job_id"]
        release.set()
        getattr(second, jobs)[case_id].result(timeout=10)
        final = getattr(first, getter)(case_id)
        assert final["job_id"] == new["job_id"] and final["state"] == "complete"
    finally:
        release.set()
        first.close()
        second.close()
