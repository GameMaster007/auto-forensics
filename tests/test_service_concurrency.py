"""Bounded regressions for background admission, responsiveness, and shutdown."""

from __future__ import annotations

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from auto_forensics.config import AppConfig
from auto_forensics.security import SecurityError, SecurityPolicy
from auto_forensics.service import AutoForensicsService


def _config(root: Path) -> AppConfig:
    data = root / "data"
    return AppConfig(
        data_dir=data, cases_dir=data / "cases", db_path=data / "app.db",
        host="127.0.0.1", port=8765, production=False, api_key_hash=None,
        allowed_origins=[], trusted_hosts=["127.0.0.1"], allowed_ingest_roots=[root],
        rate_limit_per_minute=240, llama_endpoint="http://localhost:11434", llama_model="test",
        security_policy=SecurityPolicy(),
    )


@pytest.mark.parametrize("job_type", ["analysis", "enrichment"])
def test_simultaneous_submissions_accept_one_job_and_shutdown_drains_it(tmp_path, monkeypatch, job_type):
    service = AutoForensicsService(_config(tmp_path))
    service.create_case("concurrent-case")
    entered = threading.Event()
    release = threading.Event()
    finished = threading.Event()

    def work(*args, **kwargs):
        entered.set()
        try:
            assert release.wait(5), "Test worker was not released"
            return {"synthetic": True}
        finally:
            finished.set()

    if job_type == "analysis":
        monkeypatch.setattr(service, "analyze_case", work)
        submit = service.analyze_case_async
    else:
        monkeypatch.setattr(service, "_run_enrichment_for_case", work)
        submit = service.enrich_case_iocs_async
    try:
        with ThreadPoolExecutor(max_workers=8) as callers:
            futures = [callers.submit(submit, "concurrent-case") for _ in range(8)]
            assert entered.wait(2)
            outcomes = [future.result(timeout=3) for future in futures]
        assert sum(result["accepted"] is True for result in outcomes) == 1
        with ThreadPoolExecutor(max_workers=1) as closer:
            closing = closer.submit(service.close)
            assert not finished.is_set()
            release.set()
            closing.result(timeout=3)
        assert finished.is_set()
        with pytest.raises(SecurityError, match="shutting down"):
            submit("concurrent-case")
        service.close()
    finally:
        release.set()
        service.close()


def test_health_remains_responsive_while_sync_analysis_waits_and_lifespan_closes_service(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    httpx = pytest.importorskip("httpx")
    from auto_forensics.api import create_app

    service = AutoForensicsService(_config(tmp_path))
    service.create_case("responsive-case")
    entered = threading.Event()
    release = threading.Event()

    def blocking_analysis(*args, **kwargs):
        entered.set()
        assert release.wait(5), "Test worker was not released"
        return {"synthetic": True}

    monkeypatch.setattr(service, "analyze_case", blocking_analysis)
    monkeypatch.setattr("auto_forensics.api.AutoForensicsService", lambda config: service)
    app = create_app(service.config)

    async def exercise():
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1") as client:
                analysis = asyncio.create_task(client.post("/api/cases/responsive-case/analyze", json={"enable_llama": False}))
                try:
                    assert await asyncio.to_thread(entered.wait, 2)
                    health = await asyncio.wait_for(client.get("/api/health"), timeout=1)
                    assert health.status_code == 200 and health.json() == {"status": "ok"}
                    assert not analysis.done()
                finally:
                    release.set()
                    response = await asyncio.wait_for(analysis, timeout=2)
                assert response.status_code == 200

    try:
        asyncio.run(exercise())
        assert service._closed is True
        with pytest.raises(SecurityError, match="shutting down"):
            service.analyze_case_async("responsive-case")
    finally:
        release.set()
        service.close()
