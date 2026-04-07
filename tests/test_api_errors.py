from __future__ import annotations

from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient
from auto_forensics.api import create_app
from auto_forensics.config import AppConfig
from auto_forensics.security import SecurityPolicy

@pytest.fixture
def client(tmp_path):
    cfg = AppConfig(
        data_dir=tmp_path,
        cases_dir=tmp_path / "cases",
        db_path=tmp_path / "app.db",
        host="127.0.0.1",
        port=8765,
        production=False,
        api_key_hash=None,
        allowed_origins=[],
        trusted_hosts=["127.0.0.1", "localhost", "testserver"],
        allowed_ingest_roots=[tmp_path],
        rate_limit_per_minute=240,
        llama_endpoint="http://localhost:11434",
        llama_model="llama3.1:8b",
        security_policy=SecurityPolicy()
    )
    app = create_app(cfg)
    return TestClient(app, raise_server_exceptions=False)

def test_health_check(client):
    resp = client.get("/api/health")
    print(f"DEBUG: {resp.status_code} {resp.text}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "db" in data  # Health check now includes DB connectivity status

def test_404_error_standardized(client):
    resp = client.get("/api/nonexistent")
    # FastAPI default 404 handler might not be overridden yet for non-API routes 
    # if we only target /api/ or similar, but structured_http_exception_handler 
    # should catch HTTPException(404) if raised by FastAPI.
    assert resp.status_code == 404
    data = resp.json()
    assert "error" in data
    assert data["error"] == "not_found"

def test_validation_error_standardized(client):
    # Missing case_id in create_case
    resp = client.post("/api/cases", json={})
    assert resp.status_code == 422
    data = resp.json()
    assert data["error"] == "validation_error"
    assert "validation_errors" in data
    assert len(data["validation_errors"]) > 0

def test_invalid_case_id_error(client):
    resp = client.post("/api/cases", json={"case_id": "!!!"})
    assert resp.status_code == 422 # Pydantic validation first
    
def test_security_error_to_400(client):
    # This might require a mock or a specific trigger that bypasses pydantic but hits SecurityError
    # Actually create_case raises SecurityError if validate_case_id fails (though pydantic catches most)
    pass

def test_unhandled_exception_standardized(client):
    # Mocking list_cases to raise an exception
    with patch("auto_forensics.service.AutoForensicsService.list_cases", side_effect=Exception("Boom!")):
        resp = client.get("/api/cases")
        assert resp.status_code == 500
        data = resp.json()
        assert data["error"] == "internal_error"
        assert "unexpected error" in data["detail"]
