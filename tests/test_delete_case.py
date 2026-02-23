"""Tests for the delete_case feature across DB, service, API, and CLI layers."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from auto_forensics.config import AppConfig
from auto_forensics.db import Database
from auto_forensics.security import SecurityError, validate_case_id
from auto_forensics.security import SecurityPolicy
from auto_forensics.service import AutoForensicsService


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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
        trusted_hosts=["127.0.0.1", "localhost"],
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


# ---------------------------------------------------------------------------
# DB-layer tests
# ---------------------------------------------------------------------------


class TestDbDeleteCase:
    def test_delete_existing_case_returns_true(self, tmp_path: Path) -> None:
        db = Database(tmp_path / "test.db")
        ev = tmp_path / "ev"
        out = tmp_path / "out"
        ev.mkdir(); out.mkdir()
        db.create_case("case-del-001", evidence_dir=ev, output_dir=out)
        assert db.get_case("case-del-001") is not None
        deleted = db.delete_case("case-del-001")
        assert deleted is True
        assert db.get_case("case-del-001") is None

    def test_delete_nonexistent_case_returns_false(self, tmp_path: Path) -> None:
        db = Database(tmp_path / "test.db")
        deleted = db.delete_case("case-does-not-exist")
        assert deleted is False

    def test_delete_cascades_findings(self, tmp_path: Path) -> None:
        """Deleting a case should cascade-delete its findings."""
        from auto_forensics.models import Finding
        db = Database(tmp_path / "test.db")
        ev = tmp_path / "ev"
        out = tmp_path / "out"
        ev.mkdir(); out.mkdir()
        db.create_case("case-cascade-001", evidence_dir=ev, output_dir=out)
        finding = Finding(
            finding_id="f-001",
            title="Test Finding",
            severity="high",
            confidence=0.9,
            tactic="execution",
            technique_id="T1059",
            evidence=["foo"],
            recommendation="Investigate",
        )
        db.replace_findings_and_timeline("case-cascade-001", [finding], [])
        assert len(db.get_findings("case-cascade-001")) == 1
        db.delete_case("case-cascade-001")
        # After delete the case row is gone; querying findings returns empty
        # (the foreign key cascade removes them).
        assert db.get_findings("case-cascade-001") == []


# ---------------------------------------------------------------------------
# Service-layer tests
# ---------------------------------------------------------------------------


class TestServiceDeleteCase:
    def test_delete_case_success(self, tmp_path: Path) -> None:
        cfg = _config(tmp_path)
        svc = AutoForensicsService(cfg)
        svc.create_case("case-svc-del-001")
        result = svc.delete_case("case-svc-del-001")
        assert result["deleted"] is True
        assert result["case_id"] == "case-svc-del-001"

    def test_delete_case_removes_from_db(self, tmp_path: Path) -> None:
        cfg = _config(tmp_path)
        svc = AutoForensicsService(cfg)
        svc.create_case("case-svc-del-002")
        svc.delete_case("case-svc-del-002")
        with pytest.raises(SecurityError):
            svc.require_case("case-svc-del-002")

    def test_delete_nonexistent_case_raises(self, tmp_path: Path) -> None:
        cfg = _config(tmp_path)
        svc = AutoForensicsService(cfg)
        with pytest.raises(SecurityError):
            svc.delete_case("case-does-not-exist-xyz")

    def test_delete_case_removes_disk_dir(self, tmp_path: Path) -> None:
        cfg = _config(tmp_path)
        svc = AutoForensicsService(cfg)
        result_create = svc.create_case("case-svc-disk-001")
        evidence_dir = Path(result_create["evidence_dir"])
        case_folder = evidence_dir.parent
        assert case_folder.exists()
        svc.delete_case("case-svc-disk-001")
        assert not case_folder.exists()

    def test_delete_cleans_up_job_records(self, tmp_path: Path) -> None:
        cfg = _config(tmp_path)
        svc = AutoForensicsService(cfg)
        svc.create_case("case-svc-del-003")
        svc.db.upsert_analysis_job(
            job_id="job-del-analysis",
            case_id="case-svc-del-003",
            job_type="analysis",
            state="complete",
            progress=100,
            message="done",
        )
        jobs_before = svc.case_job_history("case-svc-del-003")
        assert len(jobs_before) == 1
        svc.delete_case("case-svc-del-003")
        # Jobs cascade-deleted; querying for them on a now-missing case raises SecurityError.
        with pytest.raises(SecurityError):
            svc.case_job_history("case-svc-del-003")


# ---------------------------------------------------------------------------
# API-layer tests
# ---------------------------------------------------------------------------


class TestApiDeleteCase:
    def test_delete_returns_200_and_deleted_true(self, tmp_path: Path) -> None:
        from fastapi.testclient import TestClient
        from auto_forensics.api import create_app

        cfg = _config(tmp_path)
        svc = AutoForensicsService(cfg)
        svc.create_case("case-api-del-001")
        app = create_app(cfg, service=svc)
        client = TestClient(app, raise_server_exceptions=True)

        resp = client.delete("/api/cases/case-api-del-001")
        assert resp.status_code == 200
        body = resp.json()
        assert body["deleted"] is True
        assert body["case_id"] == "case-api-del-001"

    def test_delete_nonexistent_returns_404(self, tmp_path: Path) -> None:
        from fastapi.testclient import TestClient
        from auto_forensics.api import create_app

        cfg = _config(tmp_path)
        svc = AutoForensicsService(cfg)
        app = create_app(cfg, service=svc)
        client = TestClient(app, raise_server_exceptions=True)

        resp = client.delete("/api/cases/case-does-not-exist-zzz")
        assert resp.status_code == 404

    def test_get_after_delete_returns_404(self, tmp_path: Path) -> None:
        from fastapi.testclient import TestClient
        from auto_forensics.api import create_app

        cfg = _config(tmp_path)
        svc = AutoForensicsService(cfg)
        svc.create_case("case-api-del-002")
        app = create_app(cfg, service=svc)
        client = TestClient(app, raise_server_exceptions=True)

        client.delete("/api/cases/case-api-del-002")
        resp = client.get("/api/cases/case-api-del-002")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# CLI-layer tests
# ---------------------------------------------------------------------------


class TestCliDeleteCase:
    def _run(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture,  # type: ignore[type-arg]
        cfg: AppConfig,
        argv: list[str],
    ) -> str:
        from auto_forensics import cli

        monkeypatch.setattr(cli.AppConfig, "from_env", classmethod(lambda cls: cfg))
        monkeypatch.setattr(sys, "argv", ["auto-forensics", *argv])
        cli.main()
        return capsys.readouterr().out.strip()

    def test_cli_delete_with_force(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture,  # type: ignore[type-arg]
        tmp_path: Path,
    ) -> None:
        cfg = _config(tmp_path)
        svc = AutoForensicsService(cfg)
        svc.create_case("case-cli-del-001")

        output = self._run(
            monkeypatch,
            capsys,
            cfg,
            ["delete", "--case-id", "case-cli-del-001", "--force"],
        )
        assert "Deleted" in output or "Case Deleted" in output

        # Verify the case is truly gone from the DB.
        with pytest.raises(SecurityError):
            svc.require_case("case-cli-del-001")
