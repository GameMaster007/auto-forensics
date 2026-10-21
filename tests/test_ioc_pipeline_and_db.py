from __future__ import annotations

from pathlib import Path

from auto_forensics.db import Database
from auto_forensics.ioc_pipeline import extract_iocs
from auto_forensics.models import IOC, BinaryFeature, Finding, IOCEnrichment, TimelineEvent


def test_extract_iocs_from_binary_findings_and_timeline():
    binaries = [
        BinaryFeature(
            path="sample.bin",
            size_bytes=100,
            sha256="a" * 64,
            md5="b" * 32,
            entropy=6.9,
            string_hits=["https://c2.example/path", "8.8.8.8"],
            import_hints=[],
            suspicious_score=3.0,
            rationale=[],
        )
    ]
    findings = [
        Finding(
            finding_id="f1",
            title="Detected domain bad.example",
            severity="high",
            confidence=0.8,
            tactic="execution",
            evidence=["contacted 203.0.113.55"],
        )
    ]
    timeline = [
        TimelineEvent(
            timestamp=None,
            source="pcap",
            event_type="dns_query",
            description="DNS query for evil.test",
            risk_score=5,
            tags=[],
            related={"host": "evil.test"},
        )
    ]

    iocs = extract_iocs(binaries, findings, timeline)
    pairs = {(ioc.ioc_type, ioc.value) for ioc in iocs}

    assert ("sha256", "a" * 64) in pairs
    assert ("md5", "b" * 32) in pairs
    assert ("url", "https://c2.example/path") in pairs
    assert ("ip", "203.0.113.55") in pairs


def test_db_ioc_cache_roundtrip(tmp_path: Path):
    db = Database(tmp_path / "app.db")
    db.create_case("case-1", tmp_path / "evidence", tmp_path / "output")
    ioc = IOC(ioc_id="ioc-1", ioc_type="ip", value="203.0.113.50", sources=["timeline"])
    db.replace_case_iocs("case-1", [ioc])

    enrichment = IOCEnrichment(
        enrichment_id="e1",
        ioc_id="ioc-1",
        provider="abuseipdb",
        verdict="suspicious",
        confidence=0.7,
        details={"abuse_confidence_score": 30},
    )
    db.upsert_ioc_enrichment_cache("ip", "203.0.113.50", enrichment)

    cached = db.get_cached_ioc_enrichment("ip", "203.0.113.50", "abuseipdb", ttl_minutes=60)
    case_iocs = db.get_case_iocs("case-1")
    case_enrichments = db.get_case_ioc_enrichments("case-1")

    assert cached is not None
    assert cached.verdict == "suspicious"
    assert len(case_iocs) == 1
    assert len(case_enrichments) == 1


def test_database_accepts_sqlite_url(tmp_path: Path):
    db_path = (tmp_path / "via_url.db").resolve()
    db = Database(f"sqlite:///{db_path}")
    db.create_case("case-url", tmp_path / "evidence", tmp_path / "output")

    case = db.get_case("case-url")

    assert case is not None
