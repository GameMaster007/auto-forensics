"""Model numbers and plugin metadata cannot manufacture analyst acceptance."""

from __future__ import annotations

import math
from pathlib import Path

import pytest

from auto_forensics.citations import citation_for_binary
from auto_forensics.llama_workflow import LlamaWorkflow, _safe_float
from auto_forensics.models import BinaryFeature, Finding
from auto_forensics.pipeline import PipelineConfig, run_case
from auto_forensics.plugins import PluginRegistry


@pytest.mark.parametrize("value", [True, False, float("nan"), float("inf"), -float("inf"), "NaN", "Infinity", None, {}, 10 ** 400])
def test_invalid_model_confidence_uses_the_documented_default(value):
    assert _safe_float(value, 0.4) == 0.4


def test_model_nonfinite_numbers_do_not_become_maximum_confidence(monkeypatch):
    workflow = LlamaWorkflow("http://127.0.0.1:11434", "synthetic")
    response = {"findings": [{"title": "Synthetic", "confidence": "NaN", "confidence_low": "Infinity", "confidence_high": "-Infinity"}],
                "timeline_hints": [{"event_type": "hint", "risk_score": "NaN"}]}
    monkeypatch.setattr(workflow, "_call", lambda prompt: response)
    binary = BinaryFeature("fixture.bin", 10, "a" * 64, "b" * 32, 0.5)
    findings, hints = workflow.analyze_binary(binary, [])
    assert findings[0].confidence == 0.6
    assert findings[0].confidence_low == 0.5 and findings[0].confidence_high == 0.9
    assert hints[0].risk_score == 4.0
    assert math.isfinite(findings[0].confidence)


def test_detector_cannot_preaccept_its_own_new_finding(tmp_path: Path):
    source = tmp_path / "evidence"
    source.mkdir()
    (source / "fixture.bin").write_bytes(b"MZ synthetic powershell")
    registry = PluginRegistry()
    class PreacceptingDetector:
        name = "synthetic-preaccepting-detector"
        def detect(self, artifacts, binaries, timeline):
            return [Finding("plugin-preaccept", "Detector label", "low", 0.5, "unknown",
                            citations=[citation_for_binary(binaries[0])], review_status="accepted", analyst_verified=True,
                            review_actor="invented actor", review_at="2026-11-07T00:00:00Z", review_note="invented decision",
                            verification="supported", machine_verification="supported")]
    registry.detectors.register(PreacceptingDetector())
    report = run_case(PipelineConfig("draft-trust", source, tmp_path / "output", enable_llama=False, plugin_registry=registry))
    finding = next(item for item in report.findings if item.finding_id == "plugin-preaccept")
    assert finding.review_status == "unverified" and finding.analyst_verified is False
    assert finding.review_actor == finding.review_at == finding.review_note == finding.machine_verification == ""
    assert report.summary["verified_finding_ids"] == []
