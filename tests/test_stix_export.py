from __future__ import annotations

from dataclasses import replace

import pytest

from auto_forensics.models import IOC, CaseReport, Citation, Finding
from auto_forensics.security import SecurityError
from auto_forensics.stix_export import build_stix_bundle


def test_build_stix_bundle_contains_bundle_and_objects():
    report = CaseReport(
        case_id="case-1",
        generated_at="2026-02-18T00:00:00Z",
        binary_features=[],
        findings=[
            Finding(
                finding_id="f1",
                title="test finding",
                severity="high",
                confidence=0.8,
                tactic="execution",
            )
        ],
        timeline=[],
        summary={},
    )

    bundle = build_stix_bundle(report)

    assert bundle["type"] == "bundle"
    assert isinstance(bundle["objects"], list)
    assert any(item.get("type") == "grouping" for item in bundle["objects"])
    assert any(item.get("type") == "note" for item in bundle["objects"])
    assert not any(item.get("type") == "indicator" for item in bundle["objects"])


def _report() -> CaseReport:
    return CaseReport("case-'quoted", "2026-11-07T00:00:00Z", [], [
        Finding("finding-'quoted", "Synthetic finding", "high", 0.8, "execution",
                evidence=["Literal 'quoted' source text"], citations=[Citation("event-1", "events.json", "a" * 64, row=1)],
                verification="supported", ioc_refs=["url"]),
    ], [], {}, [
        IOC("ip4", "ip", "192.0.2.1"), IOC("ip6", "ip", "2001:db8::1"),
        IOC("domain", "domain", "EXAMPLE.TEST"), IOC("url", "url", "https://EXAMPLE.TEST/Path?Key=AbC"),
        IOC("md5", "md5", "b" * 32), IOC("sha1", "sha1", "c" * 40), IOC("sha256", "sha256", "d" * 64),
        IOC("unknown", "unsupported", "retained candidate value"), IOC("bad-ip", "ip", "999.999.999.999"),
    ])


def test_standard_observables_review_notes_and_all_references_parse_as_stix21():
    stix2 = pytest.importorskip("stix2")
    report = _report()
    bundle = build_stix_bundle(report)
    parsed = stix2.parse(bundle, version="2.1", allow_custom=True)
    kinds = {item.type for item in parsed.objects}
    assert {"ipv4-addr", "ipv6-addr", "domain-name", "url", "file", "observed-data", "grouping", "note"} <= kinds
    assert "indicator" not in kinds and "incident" not in kinds
    ids = {item["id"] for item in bundle["objects"]}
    assert len(ids) == len(bundle["objects"])
    for item in bundle["objects"]:
        for reference in item.get("object_refs", []):
            assert reference in ids
        assert "payload_bin" not in item
    assert len([item for item in bundle["objects"] if "unmapped-observable" in item.get("labels", [])]) == 2
    url = next(item for item in bundle["objects"] if item["type"] == "url")
    assert url["value"] == "https://example.test/Path?Key=AbC"
    assert bundle == build_stix_bundle(report)


def test_accept_reject_and_annotation_preserve_identity_with_explicit_review_state():
    report = _report()
    draft = build_stix_bundle(report)
    report.findings[0] = replace(report.findings[0], review_status="accepted", analyst_verified=True,
                                 review_actor="Ada", review_at="2026-11-07T01:00:00Z")
    accepted = build_stix_bundle(report)
    def note(bundle):
        return next(item for item in bundle["objects"] if item.get("x_auto_forensics_finding_id"))
    assert note(draft)["id"] == note(accepted)["id"]
    assert note(accepted)["x_auto_forensics_analyst_verified"] is True
    report.findings[0] = replace(report.findings[0], review_status="rejected", analyst_verified=False, verification="not verified")
    rejected = build_stix_bundle(report)
    assert note(rejected)["x_auto_forensics_review_status"] == "rejected"
    assert note(rejected)["x_auto_forensics_analyst_verified"] is False
    report.findings[0].review_note = "Additional annotation"
    annotated = build_stix_bundle(report, review_times={report.findings[0].finding_id: "2026-11-07T02:00:00Z"})
    assert note(annotated)["modified"] > note(rejected)["modified"]
    assert "Additional annotation" in note(annotated)["content"]


def test_invalid_times_fall_back_explicitly_and_duplicate_identities_are_refused():
    report = _report()
    report.iocs[0].first_seen = "invalid"
    observed = next(item for item in build_stix_bundle(report)["objects"] if item.get("x_auto_forensics_ioc_id") == "ip4")
    assert "invalid reported interval" in observed["x_auto_forensics_time_basis"]
    report.iocs.append(report.iocs[0])
    with pytest.raises(SecurityError, match="unique"):
        build_stix_bundle(report)
