from __future__ import annotations

import json
from pathlib import Path

from auto_forensics.artifacts import beaconing_events_from_flows, discover_artifacts, parse_evtx_xml_record
from auto_forensics.models import ArtifactEvent
from auto_forensics.plugins import ArtifactParserRegistry, PluginRegistry


def test_artifact_parser_registry_default_dispatch(tmp_path: Path):
    (tmp_path / "events.json").write_text(
        json.dumps(
            {
                "timestamp": "2026-02-17T13:12:00Z",
                "event_type": "process_start",
                "description": "json event",
                "source": "json-test",
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "table.CSV").write_text(
        "timestamp,event_type,description\n"
        "2026-02-17T13:13:00Z,network_connect,csv event\n",
        encoding="utf-8",
    )
    (tmp_path / "notes.log").write_text(
        "2026-02-17T13:14:00Z|text_event|log event\n",
        encoding="utf-8",
    )
    (tmp_path / "sample.bin").write_bytes(b"MZ")

    events, binaries = discover_artifacts(tmp_path)

    assert len(events) == 3
    assert len(binaries) == 1
    assert sorted(e.event_type for e in events) == ["network_connect", "process_start", "text_event"]


def test_artifact_parser_registry_custom_suffix(tmp_path: Path):
    class CustomParser:
        name = "custom"
        supported_suffixes = (".cust",)

        def parse(self, path: Path, max_text_bytes: int = 4 * 1024 * 1024) -> list[ArtifactEvent]:
            return [
                ArtifactEvent(
                    artifact_id="cust-1",
                    timestamp="2026-02-17T13:20:00Z",
                    event_type="custom_event",
                    description=path.read_text(encoding="utf-8"),
                    source=path.name,
                    metadata={"parser": self.name, "max_text_bytes": max_text_bytes},
                )
            ]

    (tmp_path / "input.cust").write_text("custom parser payload", encoding="utf-8")
    parser_registry = ArtifactParserRegistry()
    parser_registry.register(CustomParser())

    events, binaries = discover_artifacts(tmp_path, parser_registry=parser_registry)

    assert len(events) == 1
    assert events[0].event_type == "custom_event"
    assert events[0].metadata["parser"] == "custom"
    assert binaries == []


def test_plugin_registry_register_defaults_includes_parsers_and_binary_analyzer():
    registry = PluginRegistry()
    registry.register_defaults()

    assert registry.artifact_parsers.parser_for_suffix(".json") is not None
    assert registry.artifact_parsers.parser_for_suffix("csv") is not None
    assert registry.artifact_parsers.parser_for_suffix(".evtx") is not None
    assert registry.artifact_parsers.parser_for_suffix(".pcapng") is not None
    assert registry.artifact_parsers.parser_for_suffix(".pf") is not None
    assert registry.artifact_parsers.parser_for_suffix(".dmp") is not None
    assert registry.artifact_parsers.parser_for_name("SOFTWARE") is not None
    assert registry.artifact_parsers.parser_for_name("$MFT") is not None
    assert len(registry.binary_analyzers) == 1
    assert len(registry.detectors.detectors) >= 4


def test_parse_evtx_xml_record_maps_event_id_to_attack_metadata():
    xml_payload = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System>"
        '<Provider Name="Microsoft-Windows-Security-Auditing"/>'
        "<EventID>4688</EventID>"
        '<TimeCreated SystemTime="2026-02-17T13:25:12.0000000Z"/>'
        "<Channel>Security</Channel>"
        "<Computer>host-a</Computer>"
        "</System>"
        "<EventData>"
        '<Data Name="SubjectUserName">alice</Data>'
        '<Data Name="NewProcessName">C:\\Windows\\System32\\cmd.exe</Data>'
        '<Data Name="CommandLine">cmd.exe /c whoami</Data>'
        "</EventData>"
        "</Event>"
    )
    event = parse_evtx_xml_record(xml_payload, source="security.evtx")

    assert event is not None
    assert event.event_type == "process_creation"
    assert event.timestamp == "2026-02-17T13:25:12.0000000Z"
    assert event.metadata["event_id"] == 4688
    assert event.metadata["attack_tactic"] == "execution"
    assert event.metadata["attack_technique_id"] == "T1059"


def test_beaconing_events_from_flows_flags_low_jitter_intervals():
    flows = {
        ("198.51.100.22", 443, "tcp"): [
            1708170000.0,
            1708170060.1,
            1708170120.0,
            1708170180.2,
            1708170240.1,
            1708170300.0,
        ]
    }
    events = beaconing_events_from_flows("sample.pcap", flows)

    assert len(events) == 1
    assert events[0].event_type == "c2_beacon_suspected"
    assert events[0].metadata["dst_ip"] == "198.51.100.22"
    assert events[0].metadata["beacon_score"] > 8.0


def test_prefetch_and_mft_fallback_parsers_emit_events_without_optional_tools(tmp_path: Path):
    (tmp_path / "CMD.EXE-1234ABCD.pf").write_bytes(b"prefetch")
    (tmp_path / "$MFT").write_bytes(b"mft")
    (tmp_path / "memory.raw").write_bytes(b"mem")

    events, binaries = discover_artifacts(tmp_path)
    event_types = sorted(item.event_type for item in events)

    assert binaries == []
    assert "prefetch_execution_observed" in event_types
    assert "mft_artifact_ingested" in event_types
    assert "memory_artifact_ingested" in event_types


def test_plugin_registry_loads_external_register_function(tmp_path: Path):
    plugin_file = tmp_path / "example_plugin.py"
    plugin_file.write_text(
        "class ExampleParser:\n"
        "    name = 'example-parser'\n"
        "    supported_suffixes = ('.xyz',)\n"
        "    supported_names = ()\n"
        "    def parse(self, path, max_text_bytes=4 * 1024 * 1024):\n"
        "        return []\n"
        "\n"
        "def register(registry):\n"
        "    registry.artifact_parsers.register(ExampleParser())\n",
        encoding="utf-8",
    )
    registry = PluginRegistry()
    registry.register_defaults()

    loaded = registry.load_external_plugins([tmp_path])

    assert str(plugin_file) in loaded
    assert registry.artifact_parsers.parser_for_suffix(".xyz") is not None
