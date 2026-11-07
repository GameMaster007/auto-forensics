import pytest

from auto_forensics.models import ArtifactEvent, BinaryFeature, TimelineEvent
from auto_forensics.timeline import normalize_timeline, parse_iso


def test_parse_iso_accepts_z_suffix():
    dt = parse_iso("2026-02-17T13:12:00Z")
    assert dt is not None
    assert dt.year == 2026


@pytest.mark.parametrize("value", ["2026-02-17T13:25:12.1Z", "2026-02-17T13:25:12.1000000Z", "20260217T132512.100Z", "2026-02-17 13:25:12,1+0000"])
def test_fractional_and_compact_clocks_have_identical_cross_version_values(value):
    parsed = parse_iso(value)
    assert parsed is not None
    assert parsed.isoformat() == "2026-02-17T13:25:12.100000+00:00"
    assert parse_iso(value, require_timezone=True) == parsed


def test_review_clocks_require_explicit_timezone_and_invalid_fractional_minutes_are_refused():
    assert parse_iso("2026-02-17T13:25:12.1", require_timezone=True) is None
    assert parse_iso("2026-02-17", require_timezone=True) is None
    assert parse_iso("2026-02-17T13:25.5Z") is None


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
            metadata={"computer": "WORKSTATION-1"},
        ),
        ArtifactEvent(
            artifact_id="n1",
            timestamp="2026-02-17T13:12:45Z",
            event_type="dns_query",
            description="DNS query for c2.example",
            source="capture.pcap",
            metadata={"source_host": "workstation-1"},
        ),
    ]
    out = normalize_timeline(artifacts, [], [])
    dns_event = next(item for item in out if item.event_type == "dns_query")

    assert "network" in dns_event.tags
    assert "correlated_process" in dns_event.tags
    assert dns_event.related["correlated_process_event_type"] == "process_creation"
    assert dns_event.related["correlation_basis"] == "same-source-time-proximity"


@pytest.mark.parametrize("value", [None, 123, True, {}, [], "invalid", "Z", "2026" * 1000])
def test_bad_timestamps_do_not_crash_or_become_dates(value):
    assert parse_iso(value) is None
    events = normalize_timeline([ArtifactEvent("invalid-time", value, "process_start", "Synthetic", "fixture", {})], [], [])
    assert len(events) == 1


@pytest.mark.parametrize("process_host,network_host,process_time,network_time", [
    ("host-a", "host-b", "00:00:00", "00:00:30"),
    ("host-a", "host-a", "00:00:59", "00:00:30"),
    ("host-a", "host-a", "00:00:00", "00:03:00"),
    (None, None, "00:00:00", "00:00:30"),
])
def test_cross_host_unknown_host_future_and_old_processes_are_not_correlated(process_host, network_host, process_time, network_time):
    events = [
        ArtifactEvent("p1", f"2026-11-07T{process_time}Z", "process_start", "Process", "fixture", {"host": process_host}),
        ArtifactEvent("n1", f"2026-11-07T{network_time}Z", "dns_query", "Network", "fixture", {"host": network_host}),
    ]
    network = next(event for event in normalize_timeline(events, [], []) if event.event_type == "dns_query")
    assert "network" in network.tags and "correlated_process" not in network.tags


def test_matching_process_id_selects_older_causal_candidate_and_preserves_provenance():
    events = [
        ArtifactEvent("p1", "2026-11-07T00:00:00Z", "process_start", "First", "fixture", {"host": "192.0.2.1", "NewProcessId": "0x10"}),
        ArtifactEvent("p2", "2026-11-07T00:00:20Z", "process_start", "Second", "fixture", {"host": "192.0.2.1", "pid": 17}),
        ArtifactEvent("n1", "2026-11-07T00:00:30Z", "http_request", "Network", "fixture", {"src_ip": "192.0.2.1", "host": "destination.example", "pid": "16"}),
    ]
    network = next(event for event in normalize_timeline(events, [], []) if event.event_type == "http_request")
    assert "source_host" not in network.related
    assert network.related["correlated_process_artifact_id"] == "p1"
    assert network.related["correlation_time_delta_seconds"] == 30
    assert network.related["correlation_basis"] == "same-source-process-and-time"
    events[-1].metadata["pid"] = 999
    network = next(event for event in normalize_timeline(events, [], []) if event.event_type == "http_request")
    assert "correlated_process" not in network.tags


def test_model_hints_cannot_supply_an_observed_process_candidate():
    network = ArtifactEvent("n1", "2026-11-07T00:00:30Z", "dns_query", "Network", "fixture", {"host": "host-a"})
    hint = TimelineEvent("2026-11-07T00:00:00Z", "llm", "process_start", "Unobserved process", related={"source_host": "host-a"})
    actual = next(event for event in normalize_timeline([network], [], [hint]) if event.event_type == "dns_query")
    assert "correlated_process" not in actual.tags
