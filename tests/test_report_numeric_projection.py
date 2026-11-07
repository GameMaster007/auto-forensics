"""Finite float fields must project without integer overflow or silent rounding."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import test_projection_corruption as existing
from auto_forensics.integrity import verify_run
from auto_forensics.manifest import canonical_report_sha256, hash_output_files, write_run_manifest
from auto_forensics.security import SecurityError

database_backend = existing.database_backend


@pytest.mark.parametrize(
    "value,exact",
    [(1, True), (-0.0, True), (2**63, True), (-(2**63), True), (2**80, True), (2**1023, True), (2**63 + 1, False), (2**80 + 1, False)],
    ids=["integer-one", "signed-zero", "int64-overflow", "negative-int64-edge", "large-power", "largest-power", "inexact-int64", "inexact-large"],
)
def test_large_numeric_report_projection_is_exact_or_refused(database_backend, tmp_path, value, exact):
    service = existing._case(database_backend, tmp_path)
    output = Path(service.require_case("corruption-case")["output_dir"])
    path, manifest_path = output / "case_report.json", output / "run_manifest.json"
    report, manifest = json.loads(path.read_text()), json.loads(manifest_path.read_text())
    report["timeline"][0]["risk_score"] = value
    path.write_text(json.dumps(report))
    manifest["output"]["sha256"] = canonical_report_sha256(report)
    manifest["artifacts"] = hash_output_files(output)
    write_run_manifest(manifest_path, manifest)
    before = database_backend.get_timeline("corruption-case")
    verified = verify_run(manifest_path)
    if exact:
        assert verified["match"] is True
        service.sync_case_report("corruption-case")
        assert database_backend.get_timeline("corruption-case")[0]["risk_score"] == value
        assert service.check_case_integrity("corruption-case")["match"] is True
    else:
        assert verified["match"] is False
        with pytest.raises(SecurityError, match="integrity"):
            service.sync_case_report("corruption-case")
        assert database_backend.get_timeline("corruption-case") == before
