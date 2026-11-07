"""Published report reads stay confined, bounded, and nonblocking."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import auto_forensics.service as module
from auto_forensics.security import SecurityError
from test_archive_integrity import _service

_FORMATS = {"json": "case_report.json", "md": "case_report.md", "html": "case_report.html",
            "navigator": "attack_navigator_layer.json", "stix": "case_stix_bundle.json"}


@pytest.mark.parametrize("fmt", list(_FORMATS))
def test_report_api_cannot_follow_an_outside_file_symlink(tmp_path, fmt):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from auto_forensics.api import create_app

    service = _service(tmp_path)
    case = service.create_case("read-case")
    outside = tmp_path / "outside.txt"
    outside.write_text('{"summary":{"private_fixture":"outside-content-must-not-escape"}}')
    (Path(case["output_dir"]) / _FORMATS[fmt]).symlink_to(outside)
    with pytest.raises(SecurityError, match="without symlinks"):
        service.get_report("read-case", fmt)
    with TestClient(create_app(service.config), base_url="http://127.0.0.1") as client:
        response = client.get(f"/api/cases/read-case/report?fmt={fmt}")
        assert response.status_code == 404
        assert "outside-content-must-not-escape" not in response.text
        if fmt == "json":
            overview = client.get("/api/cases/read-case")
            assert overview.status_code == 200
            assert overview.json()["summary"] == {} and overview.json()["report_error"]
            assert "outside-content-must-not-escape" not in overview.text


@pytest.mark.parametrize("kind", ["directory", "fifo", "invalid-utf8"])
def test_invalid_report_file_types_and_encoding_do_not_block_or_escape(tmp_path, monkeypatch, kind):
    service = _service(tmp_path)
    case = service.create_case("read-case")
    path = Path(case["output_dir"]) / "case_report.json"
    if kind == "directory":
        path.mkdir()
    elif kind == "fifo":
        if not hasattr(os, "mkfifo"):
            pytest.skip("Named-pipe fixture requires os.mkfifo")
        os.mkfifo(path)
        original = Path.open
        def refuse_blocking_open(candidate, *args, **kwargs):
            if candidate == path:
                pytest.fail("Report serving attempted a blocking FIFO open")
            return original(candidate, *args, **kwargs)
        monkeypatch.setattr(Path, "open", refuse_blocking_open)
    else:
        path.write_bytes(b"\xff")
    with pytest.raises(SecurityError):
        service.get_report("read-case")
    overview = service.case_overview("read-case")
    assert overview["summary"] == {} and overview["report_error"]
    json.dumps(overview, allow_nan=False)


def test_report_reads_honor_the_exact_size_bound(tmp_path, monkeypatch):
    service = _service(tmp_path)
    case = service.create_case("read-case")
    path = Path(case["output_dir"]) / "case_report.json"
    monkeypatch.setattr(module, "MAX_REPORT_BYTES", 64)
    payload = '{"summary":{}}'.ljust(64)
    path.write_text(payload)
    assert service.get_report("read-case") == payload
    assert service.case_overview("read-case")["report_error"] is None
    path.write_text(payload + " ")
    with pytest.raises(SecurityError, match="size limit"):
        service.get_report("read-case")
    assert service.case_overview("read-case")["report_error"]
