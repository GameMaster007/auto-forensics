from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from auto_forensics.api import create_app
from auto_forensics.cli import build_parser
from auto_forensics.config import AppConfig
from auto_forensics.security import SecurityPolicy
from auto_forensics.service import AutoForensicsService


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
        security_policy=SecurityPolicy(
            max_file_size_bytes=5_000_000,
            max_total_files=1000,
            max_text_bytes=1_000_000,
        ),
        job_retention_days=30,
    )


def _write_source(source: Path) -> None:
    source.mkdir(parents=True, exist_ok=True)
    (source / "events.json").write_text(
        json.dumps(
            [
                {
                    "timestamp": "2026-02-17T13:12:00Z",
                    "event_type": "process_start",
                    "description": "powershell reached https://c2.example",
                    "source": "unit-test",
                },
                {
                    "timestamp": "2026-02-17T13:14:00Z",
                    "event_type": "network_connection",
                    "description": "Outbound connection to 198.51.100.24",
                    "source": "unit-test",
                },
            ]
        ),
        encoding="utf-8",
    )
    (source / "sample.bin").write_bytes(
        b"MZ"
        + b"\x00" * 64
        + b"powershell.exe cmd.exe https://c2.example 198.51.100.24"
    )
    (source / "notes.txt").write_text(
        "Suspicious execution chain involving powershell and outbound traffic.",
        encoding="utf-8",
    )


def _create_analyzed_case(client, tmp_path: Path, case_id: str) -> None:
    created = client.post("/api/cases", json={"case_id": case_id})
    assert created.status_code == 200
    source = tmp_path / f"{case_id}-source"
    _write_source(source)
    ingested = client.post(
        f"/api/cases/{case_id}/ingest",
        json={"source_dir": str(source)},
    )
    assert ingested.status_code == 200
    analyzed = client.post(
        f"/api/cases/{case_id}/analyze",
        json={"enable_llama": False},
    )
    assert analyzed.status_code == 200


def _wait_for_session(
    client,
    case_id: str,
    session_id: str,
    expected_states: set[str],
    timeout_seconds: float = 15.0,
) -> dict[str, object]:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        response = client.get(
            f"/api/cases/{case_id}/agent/sessions/{session_id}"
        )
        assert response.status_code == 200
        payload = response.json()
        if str(payload.get("status") or "") in expected_states:
            return payload
        time.sleep(0.1)
    raise AssertionError(
        f"Timed out waiting for session {session_id} "
        f"to reach one of {sorted(expected_states)}"
    )


def test_workspace_api_round_trip(tmp_path: Path) -> None:
    TestClient = _test_client_class()
    cfg = _config(tmp_path)
    client = TestClient(create_app(cfg))

    case_id = "case-workspace-001"
    _create_analyzed_case(client, tmp_path, case_id)

    artifacts = client.get(
        f"/api/cases/{case_id}/artifacts",
        params={
            "page": 1,
            "page_size": 2,
            "sort": "risk",
        },
    )
    assert artifacts.status_code == 200
    artifact_payload = artifacts.json()
    assert artifact_payload["case_id"] == case_id
    assert artifact_payload["page"] == 1
    assert artifact_payload["page_size"] == 2
    assert artifact_payload["total"] >= 1
    assert artifact_payload["items"]
    artifact_type = artifact_payload["items"][0].get("artifact_type")
    artifact_name = artifact_payload["items"][0].get("display_name")

    filtered = client.get(
        f"/api/cases/{case_id}/artifacts",
        params={
            "artifact_type": artifact_type,
            "search": artifact_name,
            "sort": "risk",
        },
    )
    assert filtered.status_code == 200
    filtered_payload = filtered.json()
    assert filtered_payload["filters"]["artifact_type"] == artifact_type
    assert filtered_payload["filters"]["search"] == str(artifact_name).lower()
    assert filtered_payload["items"]

    saved = client.post(
        f"/api/cases/{case_id}/views",
        json={
            "name": "Risk Timeline",
            "section": "timeline",
            "filters": {
                "keyword": "powershell",
                "min_risk": 0,
                "limit": 25,
            },
            "sort": {"field": "risk", "direction": "desc"},
            "layout": {"active_tab": "timeline"},
        },
    )
    assert saved.status_code == 200
    view = saved.json()
    assert view["name"] == "Risk Timeline"

    listed = client.get(f"/api/cases/{case_id}/views")
    assert listed.status_code == 200
    views = listed.json()
    assert any(item["view_id"] == view["view_id"] for item in views)

    timeline = client.get(
        f"/api/cases/{case_id}/timeline/query",
        params={"view_name": "Risk Timeline"},
    )
    assert timeline.status_code == 200
    timeline_payload = timeline.json()
    assert timeline_payload["case_id"] == case_id
    assert timeline_payload["view_name"] == "Risk Timeline"
    assert timeline_payload["matched_events"] >= 1

    timeline_event = (timeline_payload.get("events") or [{}])[0]
    artifact = artifact_payload["items"][0]
    notebook = client.post(
        f"/api/cases/{case_id}/notebook",
        json={
            "kind": "hypothesis",
            "title": "Initial triage hypothesis",
            "body": "The binary likely launched a PowerShell-based staging step.",
            "links": {
                "artifact_ids": [artifact.get("artifact_id")],
                "timeline_ids": [timeline_event.get("event_id")],
            },
        },
    )
    assert notebook.status_code == 200
    entry = notebook.json()
    assert entry["kind"] == "hypothesis"

    patched = client.patch(
        f"/api/cases/{case_id}/notebook/{entry['entry_id']}",
        json={
            "body": "Updated hypothesis after inspecting the artifact preview.",
            "links": {
                "artifact_ids": [artifact.get("artifact_id")],
                "timeline_ids": [timeline_event.get("event_id")],
                "finding_titles": artifact.get("matched_findings", []),
            },
        },
    )
    assert patched.status_code == 200
    patched_entry = patched.json()
    assert patched_entry["body"].startswith("Updated hypothesis")

    notebook_entries = client.get(f"/api/cases/{case_id}/notebook")
    assert notebook_entries.status_code == 200
    assert any(
        item["entry_id"] == entry["entry_id"]
        for item in notebook_entries.json()
    )

    graph = client.get(f"/api/cases/{case_id}/graph")
    assert graph.status_code == 200
    graph_payload = graph.json()
    assert graph_payload["case_id"] == case_id
    assert isinstance(graph_payload["nodes"], list)
    assert isinstance(graph_payload["edges"], list)

    deleted = client.delete(
        f"/api/cases/{case_id}/views/{view['view_id']}"
    )
    assert deleted.status_code == 200
    assert deleted.json()["deleted"] is True


def test_agent_session_api_requires_approval_and_executes_action(
    tmp_path: Path,
) -> None:
    TestClient = _test_client_class()
    cfg = _config(tmp_path)
    client = TestClient(create_app(cfg))

    case_id = "case-agent-approval-001"
    _create_analyzed_case(client, tmp_path, case_id)

    started = client.post(
        f"/api/cases/{case_id}/agent/sessions",
        json={
            "goal": "Review the case and queue only analyst-approved actions.",
        },
    )
    assert started.status_code == 200
    started_payload = started.json()
    assert started_payload["accepted"] is True
    session_id = started_payload["session"]["session_id"]

    session = _wait_for_session(
        client,
        case_id,
        session_id,
        {"awaiting_approval", "complete"},
    )
    assert session["status"] == "awaiting_approval"
    pending = [
        item for item in session.get("recommendations", [])
        if item.get("status") == "pending"
    ]
    assert pending
    action = pending[0]["suggested_action"]["action"]

    approved = client.post(
        f"/api/cases/{case_id}/agent/sessions/{session_id}/approve",
        json={"action": action},
    )
    assert approved.status_code == 200
    approved_payload = approved.json()
    assert any(
        item.get("status") == "executed"
        and item.get("suggested_action", {}).get("action") == action
        for item in approved_payload["recommendations"]
    )
    assert any(
        item.get("approval_state") == "approved"
        and item.get("proposed_action", {}).get("action") == action
        for item in approved_payload["steps"]
    )


def test_run_agent_session_sync_writes_workspace_outputs(
    tmp_path: Path,
) -> None:
    cfg = _config(tmp_path)
    svc = AutoForensicsService(cfg)

    case_id = "case-agent-sync-001"
    svc.create_case(case_id)
    source = tmp_path / "sync-source"
    _write_source(source)
    svc.ingest_case(case_id, source)
    svc.analyze_case(case_id, enable_llama=False)

    session = svc.run_agent_session_sync(
        case_id,
        goal="Produce a workspace snapshot and analyst brief.",
    )
    assert session["status"] == "complete"

    case = svc.require_case(case_id)
    output_dir = Path(case["output_dir"])
    assert (output_dir / "case_brief.md").exists()
    assert (output_dir / "workspace_snapshot.json").exists()
    assert (output_dir / "case_graph.json").exists()


def test_build_parser_has_workspace_and_agent_commands() -> None:
    parser = build_parser()
    workspace_args = parser.parse_args(
        ["workspace", "--case-id", "case-001", "--json"]
    )
    assert workspace_args.command == "workspace"
    assert workspace_args.json is True

    notebook_args = parser.parse_args(
        [
            "notebook",
            "--case-id",
            "case-001",
            "--add",
            "Analyst note",
            "--kind",
            "note",
        ]
    )
    assert notebook_args.command == "notebook"
    assert notebook_args.kind == "note"

    agent_args = parser.parse_args(
        [
            "agent",
            "approve",
            "--case-id",
            "case-001",
            "--session-id",
            "sess-123",
            "--action",
            "generate_verdict",
        ]
    )
    assert agent_args.command == "agent"
    assert agent_args.agent_command == "approve"
    assert agent_args.action == "generate_verdict"
