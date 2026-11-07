"""Packet timing from unrelated source hosts must not form one beacon."""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from auto_forensics.artifacts import beaconing_events_from_flows, load_pcap_artifacts


def _capture(path: Path, sources: list[str]) -> Path:
    dpkt = pytest.importorskip("dpkt")
    with path.open("wb") as handle:
        writer = dpkt.pcap.Writer(handle)
        for index, source in enumerate(sources):
            query = dpkt.dns.DNS(id=index, qd=[dpkt.dns.DNS.Q(name="synthetic.example")])
            udp = dpkt.udp.UDP(sport=45000 + index, dport=53, data=bytes(query))
            udp.ulen = len(udp)
            ip = dpkt.ip.IP(src=socket.inet_aton(source), dst=socket.inet_aton("198.51.100.22"), p=17, data=udp)
            ip.len = len(ip)
            packet = dpkt.ethernet.Ethernet(src=b"\x01" * 6, dst=b"\x02" * 6, type=dpkt.ethernet.ETH_TYPE_IP, data=ip)
            writer.writepkt(bytes(packet), ts=1708170000.0 + index * 60)
        writer.close()
    return path


def test_separate_sources_are_not_combined_into_one_regular_beacon(tmp_path: Path):
    path = _capture(tmp_path / "separate.pcap", ["192.0.2.1", "192.0.2.2"] * 3)
    events = load_pcap_artifacts(path)
    assert len([event for event in events if event.event_type == "dns_query"]) == 6
    assert not any(event.event_type == "c2_beacon_suspected" for event in events)
    path = _capture(tmp_path / "same.pcap", ["192.0.2.1"] * 6)
    beacons = [event for event in load_pcap_artifacts(path) if event.event_type == "c2_beacon_suspected"]
    assert len(beacons) == 1
    assert beacons[0].metadata["src_ip"] == "192.0.2.1"
    assert beacons[0].metadata["packet_count"] == 6


def test_nonfinite_or_unrepresentable_packet_times_are_not_reported_as_beacons():
    flow = ("192.0.2.1", "198.51.100.22", 443, "tcp")
    assert beaconing_events_from_flows("synthetic.pcap", {flow: [float("nan"), float("inf"), 10 ** 400, -10 ** 400, True]}) == []
