from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from auto_forensics.api import create_app
from auto_forensics.config import AppConfig
from auto_forensics.security import SecurityPolicy


def _test_client_class():
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    testclient_module = pytest.importorskip("fastapi.testclient")
    return testclient_module.TestClient


def _config(tmp_path: Path) -> AppConfig:
    data_dir = tmp_path / "data"
    return AppConfig(
        data_dir=data_dir,
        cases_dir=data_dir / "cases",
        db_path=data_dir / "app.db",
        host="127.0.0.1",
        port=8765,
        production=False,
        api_key_hash=None,
        allowed_origins=[],
        trusted_hosts=["127.0.0.1", "localhost", "testserver"],
        allowed_ingest_roots=[tmp_path.resolve()],
        rate_limit_per_minute=240,
        llama_endpoint="http://localhost:11434",
        llama_model="llama3.1:8b",
        security_policy=SecurityPolicy(max_file_size_bytes=5_000_000, max_total_files=1000, max_text_bytes=1_000_000),
        job_retention_days=30,
    )


def _create_case_with_analysis(client, tmp_path: Path, case_id: str) -> None:
    created = client.post("/api/cases", json={"case_id": case_id})
    assert created.status_code == 200

    source = tmp_path / f"source-{case_id}"
    source.mkdir()
    (source / "events.json").write_text(
        json.dumps(
            [
                {
                    "timestamp": "2026-02-17T13:12:00Z",
                    "event_type": "process_start",
                    "description": "sample process powershell",
                    "source": "unit-test",
                }
            ]
        ),
        encoding="utf-8",
    )
    (source / "sample.bin").write_text(
        "MZ fake binary powershell https://c2.example",
        encoding="utf-8",
    )

    ingested = client.post(f"/api/cases/{case_id}/ingest", json={"source_dir": str(source)})
    assert ingested.status_code == 200

    analyzed = client.post(f"/api/cases/{case_id}/analyze", json={"enable_llama": False})
    assert analyzed.status_code == 200


def test_workspace_endpoints_round_trip(tmp_path: Path):
    TestClient = _test_client_class()
    app = create_app(_config(tmp_path))
    client = TestClient(app)

    case_id = "case-workspace-001"
    _create_case_with_analysis(client, tmp_path, case_id)

    artifacts = client.get(
        f"/api/cases/{case_id}/artifacts",
        params={"page": 1, "page_size": 10, "sort": "risk"},
    )
    assert artifacts.status_code == 200
    artifact_payload = artifacts.json()
    assert artifact_payload["total"] >= 1
    assert artifact_payload["items"]
    assert "risk_level" in artifact_payload["items"][0]

    view = client.post(
        f"/api/cases/{case_id}/views",
        json={
            "name": "high-risk timeline",
            "section": "timeline",
            "filters": {"min_risk": 10, "limit": 25},
            "sort": {"field": "risk", "direction": "desc"},
            "layout": {"panel": "timeline"},
        },
    )
    assert view.status_code == 200
    view_id = view.json()["view_id"]

    views = client.get(f"/api/cases/{case_id}/views")
    assert views.status_code == 200
    assert any(item["view_id"] == view_id for item in views.json())

    timeline = client.get(
        f"/api/cases/{case_id}/timeline/query",
        params={"view_name": "high-risk timeline"},
    )
    assert timeline.status_code == 200
    assert timeline.json()["filters"]["min_risk"] == 10

    notebook = client.post(
        f"/api/cases/{case_id}/notebook",
        json={
            "kind": "hypothesis",
            "title": "Possible initial access",
            "body": "PowerShell execution may indicate initial access.",
            "links": {"artifact_paths": ["sample.bin"]},
        },
    )
    assert notebook.status_code == 200
    entry_id = notebook.json()["entry_id"]

    patched = client.patch(
        f"/api/cases/{case_id}/notebook/{entry_id}",
        json={"body": "Updated working hypothesis."},
    )
    assert patched.status_code == 200
    assert patched.json()["body"] == "Updated working hypothesis."

    graph = client.get(f"/api/cases/{case_id}/graph")
    assert graph.status_code == 200
    graph_payload = graph.json()
    assert "nodes" in graph_payload
    assert "edges" in graph_payload

    deleted = client.delete(f"/api/cases/{case_id}/views/{view_id}")
    assert deleted.status_code == 200
    assert deleted.json()["deleted"] is True


def test_agent_session_workflow(tmp_path: Path):
    TestClient = _test_client_class()
    app = create_app(_config(tmp_path))
    client = TestClient(app)

    case_id = "case-agent-001"
    _create_case_with_analysis(client, tmp_path, case_id)

    started = client.post(
        f"/api/cases/{case_id}/agent/sessions",
        json={"goal": "Investigate and propose next actions."},
    )
    assert started.status_code == 200
    session_id = started.json()["session_id"]

    deadline = time.time() + 10
    session_payload = started.json()
    while time.time() < deadline:
        status = client.get(f"/api/cases/{case_id}/agent/sessions/{session_id}")
        assert status.status_code == 200
        session_payload = status.json()
        if session_payload["status"] in {"awaiting_approval", "complete"}:
            break
        time.sleep(0.1)

    assert session_payload["status"] in {"awaiting_approval", "complete"}
    assert "steps" in session_payload
    assert "recommendations" in session_payload

    if session_payload["recommendations"]:
        action = session_payload["recommendations"][0]["suggested_action"]["action"]
        approved = client.post(
            f"/api/cases/{case_id}/agent/sessions/{session_id}/approve",
            json={"action": action},
        )
        assert approved.status_code == 200
        assert approved.json()["status"] in {"awaiting_approval", "complete"}

    sessions = client.get(f"/api/cases/{case_id}/agent/sessions")
    assert sessions.status_code == 200
    assert any(item["session_id"] == session_id for item in sessions.json())


def test_cli_parser_has_workspace_and_agent_commands() -> None:
    from auto_forensics.cli import build_parser

    parser = build_parser()

    workspace_args = parser.parse_args(["workspace", "--case-id", "case-001"])
    assert workspace_args.command == "workspace"

    notebook_args = parser.parse_args(
        ["notebook", "--case-id", "case-001", "--add", "hello", "--kind", "note"]
    )
    assert notebook_args.command == "notebook"
    assert notebook_args.kind == "note"

    agent_args = parser.parse_args(
        ["agent", "approve", "--case-id", "case-001", "--session-id", "sess-1", "--action", "generate_verdict"]
    )
    assert agent_args.command == "agent"
    assert agent_args.agent_command == "approve"
