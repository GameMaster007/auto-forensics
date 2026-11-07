"""Search input failures are portable domain errors and cannot mutate evidence."""
from __future__ import annotations

import pytest

import test_projection_corruption as existing
from auto_forensics.security import SecurityError

database_backend = existing.database_backend


@pytest.mark.parametrize("query", ["\x00", "PowerShell\x00tail", "trace\x00"], ids=["nul", "embedded", "trailing"])
def test_nul_search_is_rejected_before_backend_query(database_backend, tmp_path, monkeypatch, query):
    import auto_forensics.api as api
    TestClient = pytest.importorskip("fastapi.testclient").TestClient
    service = existing._case(database_backend, tmp_path)
    before = (database_backend.get_findings("corruption-case"), database_backend.get_timeline("corruption-case"), database_backend.get_audit_log("corruption-case"))
    with pytest.raises(SecurityError, match="NUL"):
        service.search_case("corruption-case", query)
    monkeypatch.setattr(api, "AutoForensicsService", lambda config: service)
    with TestClient(api.create_app(service.config), base_url="http://127.0.0.1", raise_server_exceptions=False) as client:
        response = client.get("/api/cases/corruption-case/search", params={"q": query})
        assert response.status_code == 422 and response.json()["error"] == "validation_error"
    assert (database_backend.get_findings("corruption-case"), database_backend.get_timeline("corruption-case"), database_backend.get_audit_log("corruption-case")) == before


@pytest.mark.parametrize("query", ["query\ud800", "query\udfff"], ids=["high-surrogate", "low-surrogate"])
def test_direct_search_refuses_unencodable_unicode(database_backend, tmp_path, query):
    service = existing._case(database_backend, tmp_path)
    with pytest.raises(SecurityError, match="Unicode"):
        service.search_case("corruption-case", query)


def test_valid_unicode_search_remains_supported(database_backend, tmp_path, monkeypatch):
    import auto_forensics.api as api
    TestClient = pytest.importorskip("fastapi.testclient").TestClient
    service = existing._case(database_backend, tmp_path)
    monkeypatch.setattr(api, "AutoForensicsService", lambda config: service)
    with TestClient(api.create_app(service.config), base_url="http://127.0.0.1", raise_server_exceptions=False) as client:
        for query in ("powershell", "日本語", "é e\u0301 😃"):
            response = client.get("/api/cases/corruption-case/search", params={"q": query})
            assert response.status_code == 200 and response.json()["query"] == query
