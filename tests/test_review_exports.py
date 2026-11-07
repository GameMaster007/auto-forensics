"""Reviews refresh every export and fail before publication on invalid data."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from auto_forensics.integrity import verify_run
from auto_forensics.models import CaseReport
from auto_forensics.pipeline import PipelineConfig, run_case
from auto_forensics.replay import replay_manifest
from auto_forensics.reviews import record_review
from auto_forensics.security import SecurityError


def _run(root: Path) -> tuple[PipelineConfig, CaseReport]:
    source = root / "source"
    source.mkdir()
    (source / "payload.bin").write_bytes(b"MZ powershell -nop -w hidden")
    config = PipelineConfig("export-review", source, root / "output", llm_provider="mock")
    return config, run_case(config)


def _json(output: Path, name: str) -> dict:
    return json.loads((output / name).read_text())


def test_review_refreshes_stix_and_navigator_and_replay_keeps_final_state(tmp_path: Path):
    stix2 = pytest.importorskip("stix2")
    config, report = _run(tmp_path)
    finding = next(item for item in report.findings if item.technique_id)
    before = _json(config.output_dir, "case_stix_bundle.json")
    def note(bundle):
        return next(item for item in bundle["objects"] if item.get("x_auto_forensics_finding_id") == finding.finding_id)
    assert note(before)["x_auto_forensics_review_status"] == "unverified"
    record_review(config.output_dir, finding_id=finding.finding_id, decision="accept", actor="Ada")
    accepted = _json(config.output_dir, "case_stix_bundle.json")
    assert note(accepted)["id"] == note(before)["id"]
    assert note(accepted)["x_auto_forensics_analyst_verified"] is True
    accepted_time = note(accepted)["modified"]
    record_review(config.output_dir, finding_id=finding.finding_id, decision="annotate", actor="Bea", note="Checked the string offset")
    annotated = _json(config.output_dir, "case_stix_bundle.json")
    assert note(annotated)["modified"] > accepted_time
    assert "Checked the string offset" in note(annotated)["content"]
    assert [entry["actor"] for entry in note(annotated)["x_auto_forensics_review_history"]] == ["Ada", "Bea"]
    stix2.parse(annotated, version="2.1", allow_custom=True)
    for item in report.findings:
        if (item.sub_technique or item.technique_id) == (finding.sub_technique or finding.technique_id):
            record_review(config.output_dir, finding_id=item.finding_id, decision="reject", actor="Bea", override=True)
    layer = _json(config.output_dir, "attack_navigator_layer.json")
    technique = next(item for item in layer["techniques"] if item["techniqueID"] == (finding.sub_technique or finding.technique_id))
    assert technique["enabled"] is False and technique["score"] == 0
    assert verify_run(config.output_dir / "run_manifest.json")["match"] is True
    replay = replay_manifest(config.output_dir / "run_manifest.json")
    assert replay["match"] is True
    replayed = _json(Path(replay["replay_output_dir"]), "case_stix_bundle.json")
    assert note(replayed)["x_auto_forensics_review_status"] == "rejected"
    stix2.parse(replayed, version="2.1", allow_custom=True)


@pytest.mark.parametrize("failure", ["nonfinite", "oversize"])
def test_invalid_report_json_preserves_previously_published_run(tmp_path: Path, monkeypatch, failure):
    config, _report = _run(tmp_path)
    before = {path.name: path.read_bytes() for path in config.output_dir.iterdir()}
    if failure == "nonfinite":
        monkeypatch.setattr("auto_forensics.pipeline._build_summary", lambda *args, **kwargs: {"invalid": float("nan")})
    else:
        monkeypatch.setattr("auto_forensics.manifest.MAX_REPORT_BYTES", 100)
    with pytest.raises(SecurityError, match="finite JSON|size limit"):
        run_case(config)
    assert before == {path.name: path.read_bytes() for path in config.output_dir.iterdir()}
