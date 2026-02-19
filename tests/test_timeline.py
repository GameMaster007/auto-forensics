from auto_forensics.models import ArtifactEvent, BinaryFeature, TimelineEvent
from auto_forensics.timeline import normalize_timeline, parse_iso


def test_parse_iso_accepts_z_suffix():
    dt = parse_iso("2026-02-17T13:12:00Z")
    assert dt is not None
    assert dt.year == 2026


def test_normalize_timeline_sorts_unknown_timestamp_last():
    artifacts = [
        ArtifactEvent(
            artifact_id="a1",
            timestamp="2026-02-17T13:12:00Z",
            event_type="process_start",
            description="proc started",
            source="sysmon",
            metadata={},
        ),
    ]
    binary = [
        BinaryFeature(
            path="x.bin",
            size_bytes=10,
            sha256="aa",
            md5="bb",
            entropy=0.1,
            string_hits=[],
            import_hints=[],
            suspicious_score=0.0,
            rationale=[],
        ),
    ]
    hints = [
        TimelineEvent(
            timestamp=None,
            source="llama",
            event_type="hint",
            description="hint event",
            risk_score=5.0,
            tags=[],
            related={},
        )
    ]
    out = normalize_timeline(artifacts, binary, hints)
    assert len(out) == 3
    assert out[-1].event_type == "hint"


def test_normalize_timeline_correlates_network_events_to_process_activity():
    artifacts = [
        ArtifactEvent(
            artifact_id="p1",
            timestamp="2026-02-17T13:12:00Z",
            event_type="process_creation",
            description="cmd.exe started",
            source="security.evtx",
            metadata={},
        ),
        ArtifactEvent(
            artifact_id="n1",
            timestamp="2026-02-17T13:12:45Z",
            event_type="dns_query",
            description="DNS query for c2.example",
            source="capture.pcap",
            metadata={},
        ),
    ]
    out = normalize_timeline(artifacts, [], [])
    dns_event = next(item for item in out if item.event_type == "dns_query")

    assert "network" in dns_event.tags
    assert "correlated_process" in dns_event.tags
    assert dns_event.related["correlated_process_event_type"] == "process_creation"
