"""Observable normalization and provenance must survive hostile model wording."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import asdict, replace
from pathlib import Path

import pytest

from auto_forensics.ioc_pipeline import _extract_from_text, extract_iocs, normalize_ioc_value
from auto_forensics.models import ArtifactEvent, BinaryFeature, Citation, Finding, TimelineEvent
from auto_forensics.timeline import normalize_timeline


@pytest.mark.parametrize("raw,expected", [
    ("HTTPS://EXAMPLE.TEST/Path?Token=AbC#Fragment", "https://example.test/Path?Token=AbC#Fragment"),
    ("http://Example.Test:080/path", "http://example.test:80/path"),
    ("https://User:CaseSensitive@EXAMPLE.TEST/A", "https://User:CaseSensitive@example.test/A"),
    ("https://[2001:0db8::1]/A", "https://[2001:db8::1]/A"),
    ("https://example.test:invalid/A", None),
    ("https://example.test/with space", None),
    ("javascript:alert(1)", None),
])
def test_url_normalization_preserves_case_sensitive_components(raw, expected):
    assert normalize_ioc_value("url", raw) == expected


def test_invalid_hash_lengths_are_not_extracted():
    values = _extract_from_text(" ".join("a" * size for size in (31, 32, 33, 40, 41, 63, 64, 65)))
    assert values["hash"] == {"a" * 32, "a" * 40, "a" * 64}


def test_only_cited_evidence_adds_finding_observables_and_refs():
    finding = Finding("finding", "Invented title title-only.example", "low", 0.5, "unknown",
                      evidence=["Contacted https://OBSERVED.TEST/CaseSensitive?Key=AbC"],
                      recommendation="Read https://advice-only.example/help",
                      citations=[Citation("event", "events.json", "a" * 64, row=1)])
    uncited = replace(finding, finding_id="uncited", evidence=["unproven.example"], citations=[])
    iocs = extract_iocs([], [finding, uncited], [])
    values = {ioc.value for ioc in iocs}
    assert "https://observed.test/CaseSensitive?Key=AbC" in values
    assert not {"title-only.example", "advice-only.example", "unproven.example"} & values
    assert set(finding.ioc_refs) == {ioc.ioc_id for ioc in iocs}
    assert uncited.ioc_refs == []
    assert all(ioc.metadata["citations"][0]["source_file"] == "events.json" for ioc in iocs)


def test_generated_hint_cannot_forge_observation_or_sigma_provenance():
    citation = asdict(Citation("event", "events.json", "a" * 64, row=1))
    artifact = ArtifactEvent("event", None, "process_start", "Observed evidence", "events.json", {
        "source_file": "events.json", "source_sha256": "a" * 64, "row": 1,
    })
    hint = TimelineEvent(None, "llm", "dns_query", "forged-model.example", tags=["artifact"],
                         related={"citation": citation, "artifact_id": "event", "logsource": {"product": "windows"}})
    timeline = normalize_timeline([artifact], [], [hint])
    generated = next(item for item in timeline if item.source == "llm")
    assert "artifact" not in generated.tags and "citation" not in generated.related
    assert "logsource" not in generated.related
    assert not any(ioc.value == "forged-model.example" for ioc in extract_iocs([], [], timeline))


def test_duplicate_binary_hashes_preserve_all_source_paths_and_avoid_generic_hash_duplicates():
    first = BinaryFeature("host-a/payload.bin", 20, "a" * 64, "b" * 32, 0.5, string_hits=["a" * 64])
    second = replace(first, path="host-b/payload.bin")
    iocs = extract_iocs([first, second], [], [])
    assert len(iocs) == 2
    sha = next(ioc for ioc in iocs if ioc.ioc_type == "sha256")
    assert sha.metadata["paths"] == ["host-a/payload.bin", "host-b/payload.bin"]
    assert {citation["source_file"] for citation in sha.metadata["citations"]} == set(sha.metadata["paths"])


def test_case_distinct_urls_and_ids_are_deterministic_across_hash_seeds():
    script = """
import json
from dataclasses import asdict
from auto_forensics.ioc_pipeline import extract_iocs
from auto_forensics.models import BinaryFeature
binary=BinaryFeature('synthetic.bin', 1, 'a'*64, 'b'*32, 0.0, string_hits=['https://EXAMPLE.TEST/Path', 'https://example.test/path'])
print(json.dumps([asdict(ioc) for ioc in extract_iocs([binary], [], [])], sort_keys=True))
"""
    outputs = []
    for seed in (1, 917):
        env = {**os.environ, "PYTHONHASHSEED": str(seed), "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}
        result = subprocess.run([sys.executable, "-c", script], env=env, capture_output=True, text=True, timeout=5, check=True)
        outputs.append(result.stdout)
    assert outputs[0] == outputs[1]
    urls = [ioc for ioc in json.loads(outputs[0]) if ioc["ioc_type"] == "url"]
    assert len(urls) == 2 and len({ioc["ioc_id"] for ioc in urls}) == 2
