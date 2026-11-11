from __future__ import annotations

import csv
import io
import json
import logging
import math
import re
import shutil
import socket  # used for inet_ntop in network parsing
import statistics
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .ids import stable_id
from .models import ArtifactEvent
from .security import (
    SecurityError,
    bounded_tree_paths,
    read_limited_text,
    sha256_file,
    stays_in_tree,
    validate_json_nesting,
)

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from .plugins import ArtifactParserRegistry


EVTX_EVENT_MAP: dict[int, dict[str, str]] = {
    4624: {
        "event_type": "windows_logon_success",
        "description": "Successful account logon",
        "attack_tactic": "initial-access",
        "attack_technique_id": "T1078",
        "attack_sub_technique": "",
    },
    4625: {
        "event_type": "windows_logon_failure",
        "description": "Failed account logon",
        "attack_tactic": "credential-access",
        "attack_technique_id": "T1110",
        "attack_sub_technique": "",
    },
    4688: {
        "event_type": "process_creation",
        "description": "A new process has been created",
        "attack_tactic": "execution",
        "attack_technique_id": "T1059",
        "attack_sub_technique": "",
    },
    4698: {
        "event_type": "scheduled_task_created",
        "description": "A scheduled task was created",
        "attack_tactic": "persistence",
        "attack_technique_id": "T1053.005",
        "attack_sub_technique": "",
    },
    7045: {
        "event_type": "service_install",
        "description": "A service was installed",
        "attack_tactic": "persistence",
        "attack_technique_id": "T1543.003",
        "attack_sub_technique": "",
    },
}

PREFETCH_FILENAME_RE = re.compile(r"^(?P<image>[A-Za-z0-9_.-]+)-[A-F0-9]{8}\.pf$", re.IGNORECASE)

REGISTRY_PERSISTENCE_KEYS: tuple[tuple[str, str], ...] = (
    (
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        "registry_run_key",
    ),
    (
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "registry_runonce_key",
    ),
    (
        r"Microsoft\Windows\CurrentVersion\Run",
        "registry_run_key",
    ),
    (
        r"Microsoft\Windows\CurrentVersion\RunOnce",
        "registry_runonce_key",
    ),
)

VOLATILITY_PLUGINS: tuple[str, ...] = (
    "windows.pslist",
    "windows.netscan",
    "windows.malfind",
    "windows.cmdline",
    "windows.dlllist",
)


def _gen_artifact_id(prefix: str, *parts: object) -> str:
    """Stable id so a replay of the same file sees the same artifact."""
    return stable_id(prefix, *parts) if parts else stable_id(prefix, prefix)


def _make_event(
    row: dict[str, Any],
    source: str,
    fallback_type: str = "artifact_event",
    identity: str = "",
) -> ArtifactEvent:
    timestamp = row.get("timestamp")
    event_type = str(row.get("event_type") or fallback_type)
    description = str(row.get("description") or row.get("message") or "no description")
    raw_id = row.get("artifact_id")
    artifact_id = (
        str(raw_id)
        if raw_id
        else _gen_artifact_id("evt", source, identity, event_type, description)
    )
    metadata = {
        k: v
        for k, v in row.items()
        if k not in {"timestamp", "event_type", "description", "message", "artifact_id"}
    }
    return ArtifactEvent(
        artifact_id=artifact_id,
        timestamp=timestamp if timestamp else None,
        event_type=event_type,
        description=description,
        source=source,
        metadata=metadata,
    )


def load_json_artifacts(path: Path, max_text_bytes: int = 4 * 1024 * 1024) -> list[ArtifactEvent]:
    try:
        text = read_limited_text(path, max_text_bytes)
    except SecurityError:
        return []
    digest = sha256_file(path).lower()
    if path.suffix.lower() == ".jsonl":
        # JSONL always addresses object records by physical line. An array
        # value on one line is not several logical records on other lines.
        return _events_from_physical_json_lines(text, path.name, digest, allow_generic=True)
    try:
        raw = json.loads(text)
        validate_json_nesting(raw)
    except (ValueError, RecursionError):
        return _events_from_physical_json_lines(text, path.name, digest)
    items = raw if isinstance(raw, list) else [raw]
    return _events_from_json_items(items, path.name, digest)


def _events_from_physical_json_lines(
    text: str, source_file: str, digest: str, *, allow_generic: bool = False,
) -> list[ArtifactEvent]:
    """Count LF/CRLF/CR lines without splitting Unicode inside JSON fields."""
    from .timeline_imports import event_from_record

    out: list[ArtifactEvent] = []
    for line_number, line in enumerate(io.StringIO(text, newline=""), start=1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
            validate_json_nesting(item)
        except (ValueError, RecursionError):
            continue
        if not isinstance(item, dict):
            continue
        event = event_from_record(item, source_file, digest, line_number)
        if event is None and allow_generic:
            source = str(item.get("source") or source_file)
            event = _make_event(item, source=source, identity=f"{source_file}:{line_number}")
            _stamp_provenance(event, source_file, digest, row=line_number)
        if event is not None:
            out.append(event)
    return out


def _events_from_json_items(
    items: list[Any] | Any,
    source_file: str,
    digest: str,
) -> list[ArtifactEvent]:
    """Keep the teaching JSON shape, and recognize tool exports in it."""
    from .timeline_imports import event_from_record

    records = items if isinstance(items, list) else [items]
    out: list[ArtifactEvent] = []
    record = 0
    for item in records:
        if not isinstance(item, dict):
            continue
        record += 1
        specialized = event_from_record(item, source_file, digest, record)
        if specialized is not None:
            out.append(specialized)
            continue
        source = str(item.get("source") or source_file)
        event = _make_event(item, source=source, identity=f"{source_file}:{record}")
        _stamp_provenance(event, source_file, digest, row=record)
        out.append(event)
    return out


def load_csv_artifacts(path: Path, max_text_bytes: int = 4 * 1024 * 1024) -> list[ArtifactEvent]:
    out: list[ArtifactEvent] = []
    try:
        text = read_limited_text(path, max_text_bytes)
    except SecurityError:
        return out
    # Reuse CSV parser safely on bounded input.
    if not text.strip():
        return out
    digest = sha256_file(path).lower()
    reader = csv.DictReader(io.StringIO(text.removeprefix("\ufeff"), newline=""))
    from .timeline_imports import events_from_csv

    specialized = events_from_csv(reader, path.name, digest)
    if specialized is not None:
        return specialized
    # Cite the physical line on which the CSV record ends, including
    # quoted fields that span more than one line.
    for row in reader:
        line_number = reader.line_num
        event = _make_event(row, source=path.name, identity=f"{path.name}:{line_number}")
        _stamp_provenance(event, path.name, digest, row=line_number)
        out.append(event)
    return out


def load_txt_artifacts(path: Path, max_text_bytes: int = 4 * 1024 * 1024) -> list[ArtifactEvent]:
    out: list[ArtifactEvent] = []
    with path.open("rb") as handle:
        data = handle.read(max_text_bytes + 1)
    if len(data) > max_text_bytes:
        return out
    # Surrogate escaping keeps undecodable bytes available for exact offset
    # accounting. Event text still uses the existing replacement decoding.
    content = data.decode("utf-8", errors="surrogateescape")
    digest = sha256_file(path).lower()
    offset = 0
    for line_number, line in enumerate(content.splitlines(keepends=True), start=1):
        raw_line = line.encode("utf-8", errors="surrogateescape")
        start = offset
        offset += len(raw_line)
        text = raw_line.decode("utf-8", errors="replace").strip()
        if not text:
            continue
        parts = [x.strip() for x in text.split("|", 2)]
        if len(parts) == 3:
            event = ArtifactEvent(
                artifact_id=_gen_artifact_id("evt", path.name, line_number, text),
                timestamp=parts[0] or None,
                event_type=parts[1] or "text_event",
                description=parts[2] or "no description",
                source=path.name,
                metadata={},
            )
        else:
            event = ArtifactEvent(
                artifact_id=_gen_artifact_id("note", path.name, line_number, text),
                timestamp=None,
                event_type="text_note",
                description=text,
                source=path.name,
                metadata={},
            )
        _stamp_provenance(event, path.name, digest, row=line_number, offset=start)
        out.append(event)
    return out


def _stamp_provenance(
    event: ArtifactEvent,
    source_file: str,
    digest: str,
    row: int,
    offset: int | None = None,
) -> None:
    """Record where an event came from so a finding can cite it."""
    event.metadata["source_file"] = source_file
    event.metadata["source_sha256"] = digest
    event.metadata["row"] = row
    if offset is not None:
        event.metadata["offset"] = offset


def _ensure_provenance(events: list[ArtifactEvent], path: Path, source_file: str | None = None) -> None:
    """Bind parser records to the file actually discovered by this run.

    ``row`` falls back to the 1-based order of records returned for
    this file. A parser that already set ``row`` keeps that value.
    """
    if not events:
        return
    digest = sha256_file(path).lower()
    for index, event in enumerate(events, start=1):
        event.metadata["source_file"] = source_file or path.name
        event.metadata["source_sha256"] = digest
        event.metadata.setdefault("row", index)


def _first_tag_text(root: ET.Element, tag: str) -> str | None:
    node = root.find(f".//{{*}}{tag}")
    if node is None or node.text is None:
        return None
    value = node.text.strip()
    return value or None


_MAX_EVENT_FIELD = 32 * 1024


_HEX_VALUE = re.compile(r"^0x[0-9a-fA-F]+$")
_EVTX_TIME = re.compile(r"^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\.(\d+))?\s*(?:Z|\+00:00)?$")


def _canonical_evtx_time(raw: str) -> str | None:
    """One timestamp form whichever EVTX reader produced it: UTC, milliseconds, Z.

    The Rust reader prints the stored 100 ns ticks; python-evtx goes through
    a float and can be off by one microsecond. Milliseconds agree for both.
    """
    if not raw:
        return None
    match = _EVTX_TIME.match(raw)
    if not match:
        return raw
    day, clock, fraction = match.groups()
    return f"{day}T{clock}.{(fraction or '0')[:3].ljust(3, '0')}Z"


_STRING_TAG = re.compile(r"<string>(.*?)</string>", re.DOTALL)
_ONLY_STRING_TAGS = re.compile(r"^\s*(<string>[^<]{0,32768}</string>\s*)+$")
# Keys the parser sets itself. An event's own payload may not overwrite them.
_RESERVED_KEYS = {"event_id", "provider", "channel", "computer", "row", "offset", "source_file", "source_sha256",
                  "attack_tactic", "attack_technique_id", "attack_sub_technique", "importer"}
_ZERO_FILETIME = {"1601-01-01T00:00:00.0000000Z", "0001-01-01 00:00:00", "1601-01-01 00:00:00"}


def _canonical_value(value: str) -> str:
    """Remove differences in how EVTX readers print the same stored value.

    Hex loses zero padding, booleans are lower case, a zero FILETIME is
    empty, and ``<string>`` wrappers (python-evtx) become " | "-joined text.
    """
    if _HEX_VALUE.match(value):
        return "0x" + (value[2:].lower().lstrip("0") or "0")
    if value in ("True", "False"):
        return value.lower()
    if value in _ZERO_FILETIME:
        return ""
    if _ONLY_STRING_TAGS.match(value):
        # Only a value made entirely of python-evtx <string> wrappers is unwrapped.
        # Text that merely contains "<string>" (an attacker can append it) is kept.
        return " | ".join(part.strip() for part in _STRING_TAG.findall(value) if part.strip())
    return value


def _event_data_map(root: ET.Element) -> dict[str, str]:
    """Named ``EventData/Data`` fields, plus the two shapes older providers use.

    Unnamed ``<Data>`` values (SQL Server, many Application-log sources)
    are joined into ``Data``. ``<UserData>`` leaf elements (Terminal
    Services, WinRM) are kept under their element names, such as
    ``Param1``. A named field always wins over a UserData leaf.
    """
    metadata: dict[str, str] = {}
    unnamed: list[str] = []
    for node in root.findall(".//{*}EventData/{*}Data"):
        key = (node.attrib.get("Name") or "").strip()
        value = (node.text or "").strip()[:_MAX_EVENT_FIELD]
        if not value:
            continue
        value = _canonical_value(value)
        if not value:
            continue
        if key:
            metadata[key] = value
        else:
            unnamed.append(value.strip())
    if unnamed and "Data" not in metadata:
        metadata["Data"] = " | ".join(unnamed)[:_MAX_EVENT_FIELD]
    for user_data in root.findall(".//{*}UserData"):
        for node in user_data.iter():
            if len(node) or node is user_data:
                continue
            key = node.tag.rsplit("}", 1)[-1].strip()
            value = (node.text or "").strip()[:_MAX_EVENT_FIELD]
            if key and value and key not in metadata:
                metadata[key] = _canonical_value(value)
    return metadata


def parse_evtx_xml_record(xml_text: str, source: str) -> ArtifactEvent | None:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None

    event_id_text = _first_tag_text(root, "EventID")
    if event_id_text is None:
        return None
    try:
        event_id = int(event_id_text)
    except ValueError:
        return None

    time_node = root.find(".//{*}TimeCreated")
    timestamp = None
    if time_node is not None:
        raw_ts = (time_node.attrib.get("SystemTime") or "").strip()
        timestamp = _canonical_evtx_time(raw_ts)

    provider_node = root.find(".//{*}Provider")
    provider = None
    if provider_node is not None:
        provider = (provider_node.attrib.get("Name") or "").strip() or None

    computer = _first_tag_text(root, "Computer")
    channel = _first_tag_text(root, "Channel")
    payload = _event_data_map(root)
    mapped = EVTX_EVENT_MAP.get(event_id, {})
    event_type = mapped.get("event_type", f"windows_event_{event_id}")
    description = mapped.get("description", f"Windows event ID {event_id}")

    details: list[str] = []
    for key in (
        "SubjectUserName",
        "TargetUserName",
        "NewProcessName",
        "CommandLine",
        "ServiceName",
        "TaskName",
    ):
        if payload.get(key):
            details.append(f"{key}={payload[key]}")
    if details:
        description = f"{description} ({', '.join(details[:4])})"

    metadata: dict[str, Any] = {
        "event_id": event_id,
        "provider": provider,
        "computer": computer,
        "channel": channel,
        "attack_tactic": mapped.get("attack_tactic", ""),
        "attack_technique_id": mapped.get("attack_technique_id", ""),
        "attack_sub_technique": mapped.get("attack_sub_technique", ""),
    }
    for key, value in payload.items():
        metadata[f"data_{key}" if key in _RESERVED_KEYS else key] = value

    return ArtifactEvent(
        artifact_id=_gen_artifact_id("evtx", source, event_id, timestamp, description),
        timestamp=timestamp,
        event_type=event_type,
        description=description,
        source=source,
        metadata=metadata,
    )


def evtx_reader_name() -> str:
    """Which EVTX reader this install uses; recorded so a replay can compare like with like."""
    try:
        import evtx  # type: ignore  # noqa: F401

        return "evtx (rust)"
    except ImportError:
        pass
    try:
        import Evtx  # type: ignore  # noqa: F401

        return "python-evtx"
    except ImportError:
        return "none"


def _evtx_xml_records(path: Path) -> Any:
    """Yield record XML in file order.

    The Rust ``evtx`` reader is preferred; it is several hundred times
    faster on large logs. ``python-evtx`` is the fallback. Both yield the
    same records in the same order, so a 1-based row cites the same event
    whichever reader is installed. Returns None when neither is installed.
    """
    try:
        from evtx import PyEvtxParser  # type: ignore
    except ImportError:
        PyEvtxParser = None  # noqa: N806
    if PyEvtxParser is not None:
        def rust() -> Any:
            for record in PyEvtxParser(str(path)).records():
                yield record["data"]
        return rust()
    try:
        from Evtx.Evtx import Evtx  # type: ignore
    except ImportError:
        return None

    def python() -> Any:
        with Evtx(str(path)) as handle:
            for record in handle.records():
                yield record.xml()
    return python()


def load_evtx_artifacts(path: Path) -> list[ArtifactEvent]:
    records = _evtx_xml_records(path)
    if records is None:
        return []

    out: list[ArtifactEvent] = []
    try:
        for xml_text in records:
            try:
                item = parse_evtx_xml_record(xml_text, source=path.name)
                if item is not None:
                    out.append(item)
            except Exception as exc:
                logger.debug("Failed to parse EVTX record in %s: %s", path.name, exc)
    except OSError as exc:
        logger.warning("Could not open EVTX file %s: %s", path, exc)
    except Exception as exc:
        logger.warning("Unexpected error reading EVTX %s: %s", path, exc)
    return out


def _to_iso_utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _inet_to_str(raw: bytes) -> str:
    if len(raw) == 4:
        return socket.inet_ntop(socket.AF_INET, raw)
    return socket.inet_ntop(socket.AF_INET6, raw)


def _extract_tls_sni(data: bytes) -> str | None:
    if len(data) < 9 or data[0] != 22:
        return None
    record_len = int.from_bytes(data[3:5], "big")
    record = data[5 : 5 + record_len]
    if len(record) < 4 or record[0] != 1:
        return None

    handshake_len = int.from_bytes(record[1:4], "big")
    body = record[4 : 4 + handshake_len]
    if len(body) < 39:
        return None

    idx = 34
    if idx >= len(body):
        return None
    session_id_len = body[idx]
    idx += 1 + session_id_len
    if idx + 2 > len(body):
        return None
    cipher_len = int.from_bytes(body[idx : idx + 2], "big")
    idx += 2 + cipher_len
    if idx >= len(body):
        return None
    compression_len = body[idx]
    idx += 1 + compression_len
    if idx + 2 > len(body):
        return None
    ext_len = int.from_bytes(body[idx : idx + 2], "big")
    idx += 2
    end = min(len(body), idx + ext_len)

    while idx + 4 <= end:
        ext_type = int.from_bytes(body[idx : idx + 2], "big")
        ext_size = int.from_bytes(body[idx + 2 : idx + 4], "big")
        ext_data_start = idx + 4
        ext_data_end = ext_data_start + ext_size
        if ext_data_end > end:
            return None
        if ext_type == 0 and ext_size >= 5:
            pos = ext_data_start + 2
            while pos + 3 <= ext_data_end:
                name_type = body[pos]
                name_len = int.from_bytes(body[pos + 1 : pos + 3], "big")
                value_start = pos + 3
                value_end = value_start + name_len
                if value_end > ext_data_end:
                    return None
                if name_type == 0:
                    value = body[value_start:value_end].decode("utf-8", errors="ignore").strip()
                    return value or None
                pos = value_end
            return None
        idx = ext_data_end
    return None


def beaconing_events_from_flows(
    source: str,
    flow_timestamps: dict[tuple[str, str, int, str], list[float]],
) -> list[ArtifactEvent]:
    out: list[ArtifactEvent] = []
    for (src_ip, dst_ip, dst_port, proto), stamps in sorted(flow_timestamps.items()):
        stamps = [stamp for stamp in stamps if type(stamp) in {float, int} and -62135596800 <= stamp <= 253402300799 and math.isfinite(stamp)]
        if len(stamps) < 5:
            continue
        ordered = sorted(stamps)
        intervals = [ordered[i] - ordered[i - 1] for i in range(1, len(ordered))]
        if not intervals:
            continue
        mean = statistics.fmean(intervals)
        if mean <= 0.0:
            continue
        stdev = statistics.pstdev(intervals) if len(intervals) > 1 else 0.0
        coeff_var = stdev / mean
        if coeff_var > 0.2:
            continue
        score = round(max(0.0, min(10.0, (1.0 - coeff_var) * 10.0)), 2)
        out.append(
            ArtifactEvent(
                artifact_id=_gen_artifact_id("pcap", source, src_ip, dst_ip, dst_port, proto, ordered[0]),
                timestamp=_to_iso_utc(ordered[0]),
                event_type="c2_beacon_suspected",
                description=(
                    f"Potential beaconing to {dst_ip}:{dst_port}/{proto} "
                    f"every ~{mean:.2f}s (jitter {coeff_var:.3f})"
                ),
                source=source,
                metadata={
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "protocol": proto,
                    "packet_count": len(stamps),
                    "interval_mean_seconds": round(mean, 3),
                    "interval_jitter": round(coeff_var, 5),
                    "beacon_score": score,
                },
            )
        )
    return out


def load_pcap_artifacts(path: Path) -> list[ArtifactEvent]:
    try:
        import dpkt  # type: ignore
    except ImportError:
        return []

    out: list[ArtifactEvent] = []
    flow_timestamps: dict[tuple[str, str, int, str], list[float]] = {}

    def packet_stream() -> Any:
        with path.open("rb") as f:
            try:
                reader: Any = dpkt.pcap.Reader(f)
                for item in reader:
                    yield item
                return
            except Exception:
                f.seek(0)
                try:
                    reader = dpkt.pcapng.Reader(f)
                    for item in reader:
                        yield item
                except Exception:
                    return

    for ts, buf in packet_stream():
        try:
            packet_time = float(ts)
            timestamp = _to_iso_utc(packet_time)
        except (ValueError, TypeError, OverflowError, OSError):
            continue
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except Exception:
            continue
        ip = getattr(eth, "data", None)
        if ip is None or not hasattr(ip, "src") or not hasattr(ip, "dst"):
            continue

        try:
            src_ip = _inet_to_str(ip.src)
            dst_ip = _inet_to_str(ip.dst)
        except Exception:
            continue

        l4 = getattr(ip, "data", None)
        if not isinstance(l4, (dpkt.udp.UDP, dpkt.tcp.TCP)):
            continue
        sport = int(getattr(l4, "sport", 0) or 0)
        dport = int(getattr(l4, "dport", 0) or 0)

        payload = getattr(l4, "data", b"")
        if isinstance(payload, memoryview):
            payload = payload.tobytes()

        proto = "udp" if l4.__class__.__name__.lower() == "udp" else "tcp"
        flow_timestamps.setdefault((src_ip, dst_ip, dport, proto), []).append(packet_time)

        if proto == "udp" and (sport == 53 or dport == 53):
            try:
                dns = dpkt.dns.DNS(payload)
            except Exception:
                dns = None
            if dns is not None:
                for question in getattr(dns, "qd", []):
                    name = getattr(question, "name", "")
                    if not name:
                        continue
                    out.append(
                        ArtifactEvent(
                            artifact_id=_gen_artifact_id("pcap", "dns", name, ts),
                            timestamp=timestamp,
                            event_type="dns_query",
                            description=f"DNS query for {name}",
                            source=path.name,
                            metadata={
                                "query": name,
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "src_port": sport,
                                "dst_port": dport,
                            },
                        )
                    )

        if proto == "tcp" and isinstance(payload, (bytes, bytearray)) and payload:
            try:
                req = dpkt.http.Request(payload)
            except Exception:
                req = None
            if req is not None:
                host = str(req.headers.get("host", ""))
                user_agent = str(req.headers.get("user-agent", ""))
                path_part = str(req.uri)
                out.append(
                    ArtifactEvent(
                        artifact_id=_gen_artifact_id("pcap", "http", host, path_part, ts),
                        timestamp=timestamp,
                        event_type="http_request",
                        description=f"HTTP {req.method} {path_part}",
                        source=path.name,
                        metadata={
                            "host": host,
                            "user_agent": user_agent,
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "src_port": sport,
                            "dst_port": dport,
                        },
                    )
                )

            sni = _extract_tls_sni(bytes(payload))
            if sni:
                out.append(
                    ArtifactEvent(
                        artifact_id=_gen_artifact_id("pcap", "tls", sni, ts),
                        timestamp=timestamp,
                        event_type="tls_client_hello",
                        description=f"TLS client hello with SNI {sni}",
                        source=path.name,
                        metadata={
                            "tls_sni": sni,
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "src_port": sport,
                            "dst_port": dport,
                        },
                    )
                )

    out.extend(beaconing_events_from_flows(path.name, flow_timestamps))
    return out


def _safe_timestamp_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z") or "+" in text or "T" in text:
        return text
    return text.replace(" ", "T")


def _prefetch_event(
    source: str,
    executable: str,
    timestamp: str | None,
    run_count: int | None,
    metadata: dict[str, Any] | None = None,
) -> ArtifactEvent:
    details = f"Prefetch execution evidence for {executable}"
    if run_count is not None:
        details = f"{details} (run_count={run_count})"
    merged_metadata: dict[str, Any] = {
        "executable": executable,
        "run_count": run_count,
        "attack_tactic": "execution",
        "attack_technique_id": "T1204",
        "attack_sub_technique": "",
    }
    if metadata:
        merged_metadata.update(metadata)
    return ArtifactEvent(
        artifact_id=_gen_artifact_id("prefetch", source, executable, timestamp, run_count),
        timestamp=timestamp,
        event_type="prefetch_execution_observed",
        description=details,
        source=source,
        metadata=merged_metadata,
    )


def _load_prefetch_from_pecmd(path: Path) -> list[ArtifactEvent]:
    tool = shutil.which("PECmd.exe") or shutil.which("PECmd") or shutil.which("pecmd")
    if not tool:
        return []

    out: list[ArtifactEvent] = []
    with tempfile.TemporaryDirectory(prefix="auto_forensics_pecmd_") as tmp:
        tmp_dir = Path(tmp)
        command_variants = [
            [tool, "-f", str(path), "--json", str(tmp_dir)],
            [tool, "-f", str(path), "--jsonf", str(tmp_dir), "--json", path.stem],
        ]
        for cmd in command_variants:
            try:
                subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
            except Exception:
                continue
            json_files = list(tmp_dir.rglob("*.json"))
            if json_files:
                break

        for json_file in tmp_dir.rglob("*.json"):
            try:
                payload = json.loads(json_file.read_text(encoding="utf-8"))
            except Exception:
                continue
            rows = payload if isinstance(payload, list) else [payload]
            for row in rows:
                if not isinstance(row, dict):
                    continue
                executable = str(
                    row.get("ExecutableName")
                    or row.get("SourceFilename")
                    or row.get("Executable")
                    or path.name
                )
                run_count_raw = row.get("RunCount")
                try:
                    run_count = int(run_count_raw) if run_count_raw is not None else None
                except Exception:
                    run_count = None
                last_runs = row.get("LastRunTimes")
                if isinstance(last_runs, list) and last_runs:
                    for ts in [x for x in last_runs[:8] if x]:
                        out.append(
                            _prefetch_event(
                                source=path.name,
                                executable=executable,
                                timestamp=_safe_timestamp_text(ts),
                                run_count=run_count,
                                metadata={"parser": "pecmd"},
                            )
                        )
                    continue
                ts = _safe_timestamp_text(row.get("LastRun") or row.get("LastRunTime"))
                out.append(
                    _prefetch_event(
                        source=path.name,
                        executable=executable,
                        timestamp=ts,
                        run_count=run_count,
                        metadata={"parser": "pecmd"},
                    )
                )
    return out


def load_prefetch_artifacts(path: Path) -> list[ArtifactEvent]:
    out = _load_prefetch_from_pecmd(path)
    if out:
        return out

    match = PREFETCH_FILENAME_RE.match(path.name)
    executable = match.group("image") if match else path.stem
    return [
        _prefetch_event(
            source=path.name,
            executable=executable,
            timestamp=None,
            run_count=None,
            metadata={"parser": "filename-fallback", "timestamp_basis": "unknown"},
        )
    ]


def _registry_value_to_text(value: Any) -> str:
    try:
        if isinstance(value, bytes):
            return value.decode("utf-16-le", errors="ignore").strip("\x00")
        return str(value)
    except Exception:
        return ""


def load_registry_artifacts(path: Path) -> list[ArtifactEvent]:
    try:
        from Registry import Registry  # type: ignore
    except ImportError:
        return []

    out: list[ArtifactEvent] = []
    max_events = 5000
    try:
        hive = Registry.Registry(str(path))
    except OSError as exc:
        logger.warning("Could not open registry hive %s: %s", path, exc)
        return out
    except Exception as exc:
        logger.warning("Unexpected error opening registry hive %s: %s", path, exc)
        return out

    hive_name = path.name
    for key_path, event_type in REGISTRY_PERSISTENCE_KEYS:
        if len(out) >= max_events:
            break
        try:
            key = hive.open(key_path)
        except Exception as exc:
            logger.debug("Registry key not found %s in %s: %s", key_path, path.name, exc)
            continue
        for value in key.values():
            if len(out) >= max_events:
                break
            command = _registry_value_to_text(value.value())
            if not command:
                continue
            timestamp = None
            try:
                timestamp = key.timestamp().isoformat().replace("+00:00", "Z")
            except Exception:
                timestamp = None
            out.append(
                ArtifactEvent(
                    artifact_id=_gen_artifact_id("reg", hive_name, key_path, value.name(), command),
                    timestamp=timestamp,
                    event_type=event_type,
                    description=f"Registry persistence value {value.name()} -> {command}",
                    source=hive_name,
                    metadata={
                        "registry_hive": hive_name,
                        "registry_key": key_path,
                        "registry_value": value.name(),
                        "command": command,
                        "attack_tactic": "persistence",
                        "attack_technique_id": "T1547.001",
                        "attack_sub_technique": "",
                    },
                )
            )

    if len(out) < max_events:
        try:
            services = hive.open(r"ControlSet001\Services")
        except Exception as exc:
            logger.debug("No ControlSet001\\Services in %s: %s", path.name, exc)
            services = None
        if services is not None:
            for service_key in services.subkeys():
                if len(out) >= max_events:
                    break
                try:
                    image_path = _registry_value_to_text(service_key.value("ImagePath").value())
                except Exception:
                    image_path = ""
                if not image_path:
                    continue
                try:
                    timestamp = service_key.timestamp().isoformat().replace("+00:00", "Z")
                except Exception:
                    timestamp = None
                out.append(
                    ArtifactEvent(
                        artifact_id=_gen_artifact_id("reg", hive_name, service_key.name(), image_path),
                        timestamp=timestamp,
                        event_type="registry_service_entry",
                        description=f"Service entry {service_key.name()} image path {image_path}",
                        source=hive_name,
                        metadata={
                            "registry_hive": hive_name,
                            "registry_key": service_key.path(),
                            "service_name": service_key.name(),
                            "image_path": image_path,
                            "attack_tactic": "persistence",
                            "attack_technique_id": "T1543.003",
                            "attack_sub_technique": "",
                        },
                    )
                )

    return out


def _mft_event_from_row(path: Path, row: dict[str, Any]) -> ArtifactEvent | None:
    full_path = str(
        row.get("full_path")
        or row.get("filename")
        or row.get("FileName")
        or row.get("Full Path")
        or ""
    ).strip()
    if not full_path:
        return None

    timestamp = (
        _safe_timestamp_text(row.get("si_create_time"))
        or _safe_timestamp_text(row.get("fn_create_time"))
        or _safe_timestamp_text(row.get("si_mtime"))
        or _safe_timestamp_text(row.get("SI Creation Time"))
        or _safe_timestamp_text(row.get("FN Creation Time"))
    )
    inode = str(row.get("inode") or row.get("record_number") or row.get("Record Number") or "").strip()
    flags = str(row.get("flags") or row.get("Flags") or "").strip()
    deleted = str(row.get("deleted") or row.get("Deleted") or "").strip().lower() in {
        "1",
        "true",
        "yes",
        "y",
    }

    description = f"MFT record observed for {full_path}"
    if deleted:
        description = f"MFT deletion evidence for {full_path}"

    return ArtifactEvent(
        artifact_id=_gen_artifact_id("mft", path.name, full_path, inode),
        timestamp=timestamp,
        event_type="mft_file_record",
        description=description,
        source=path.name,
        metadata={
            "path": full_path,
            "inode": inode,
            "flags": flags,
            "deleted": deleted,
            "attack_tactic": "defense-evasion" if deleted else "discovery",
            "attack_technique_id": "T1070.004" if deleted else "",
            "attack_sub_technique": "",
        },
    )


def _load_mft_from_analyzemft(path: Path) -> list[ArtifactEvent]:
    tool = shutil.which("analyzeMFT.py") or shutil.which("analyzeMFT")
    if not tool:
        return []

    with tempfile.TemporaryDirectory(prefix="auto_forensics_mft_") as tmp:
        out_csv = Path(tmp) / "mft.csv"
        commands = [
            [tool, "-f", str(path), "-o", str(out_csv)],
            [tool, "-f", str(path), "--output", str(out_csv)],
        ]
        for cmd in commands:
            try:
                subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)
            except Exception:
                continue
            if out_csv.exists() and out_csv.stat().st_size > 0:
                break

        if not out_csv.exists() or out_csv.stat().st_size == 0:
            return []
        try:
            text = out_csv.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []

    out: list[ArtifactEvent] = []
    reader = csv.DictReader(text.splitlines())
    for row in reader:
        item = _mft_event_from_row(path, row)
        if item is not None:
            out.append(item)
            if len(out) >= 100000:
                break
    return out


def load_mft_artifacts(path: Path) -> list[ArtifactEvent]:
    out = _load_mft_from_analyzemft(path)
    if out:
        return out
    return [
        ArtifactEvent(
            artifact_id=_gen_artifact_id("mft", path.name, "fallback"),
            timestamp=None,
            event_type="mft_artifact_ingested",
            description=f"MFT artifact detected: {path.name}",
            source=path.name,
            metadata={"parser": "fallback", "timestamp_basis": "unknown"},
        )
    ]


def _volatility_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    rows = payload.get("rows")
    columns = payload.get("columns")
    if not isinstance(rows, list) or not isinstance(columns, list):
        return []
    out: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, list):
            continue
        item: dict[str, Any] = {}
        for idx, col in enumerate(columns):
            key = str(col)
            if idx < len(row):
                item[key] = row[idx]
        out.append(item)
    return out


def load_memory_artifacts(path: Path) -> list[ArtifactEvent]:
    tool = shutil.which("vol") or shutil.which("vol.py") or shutil.which("volatility3")
    if not tool:
        return [
            ArtifactEvent(
                artifact_id=_gen_artifact_id("mem", path.name, "fallback"),
                timestamp=None,
                event_type="memory_artifact_ingested",
                description=f"Memory image detected: {path.name}",
                source=path.name,
                metadata={"parser": "fallback", "timestamp_basis": "unknown"},
            )
        ]

    out: list[ArtifactEvent] = []
    for plugin in VOLATILITY_PLUGINS:
        cmd = [tool, "-f", str(path), plugin, "--output", "json"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180, check=False)
        except Exception:
            continue
        if not result.stdout.strip():
            continue
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            continue
        rows = _volatility_rows(payload if isinstance(payload, dict) else {})
        if not rows:
            continue

        for index, row in enumerate(rows[:2000]):
            out.append(
                ArtifactEvent(
                    artifact_id=_gen_artifact_id("mem", path.name, plugin, index),
                    timestamp=None,
                    event_type=f"memory_{plugin.replace('.', '_')}",
                    description=f"Volatility {plugin} record",
                    source=path.name,
                    metadata={
                        "plugin": plugin,
                        "record": row,
                        "attack_tactic": "execution" if "pslist" in plugin else "command-and-control",
                        "attack_technique_id": "T1055" if "malfind" in plugin else "",
                        "attack_sub_technique": "",
                    },
                )
            )
    if out:
        return out
    return [
        ArtifactEvent(
            artifact_id=_gen_artifact_id("mem", path.name, "volatility-empty"),
            timestamp=None,
            event_type="memory_artifact_ingested",
            description=f"Memory image detected: {path.name}",
            source=path.name,
            metadata={"parser": "volatility-empty", "timestamp_basis": "unknown"},
        )
    ]


class JsonArtifactParser:
    name = "json-artifact-parser"
    supported_suffixes = (".json", ".jsonl")
    supported_names: tuple[str, ...] = ()

    def parse(self, path: Path, max_text_bytes: int = 4 * 1024 * 1024) -> list[ArtifactEvent]:
        return load_json_artifacts(path, max_text_bytes=max_text_bytes)


class CsvArtifactParser:
    name = "csv-artifact-parser"
    supported_suffixes = (".csv",)
    supported_names: tuple[str, ...] = ()

    def parse(self, path: Path, max_text_bytes: int = 4 * 1024 * 1024) -> list[ArtifactEvent]:
        return load_csv_artifacts(path, max_text_bytes=max_text_bytes)


class TextArtifactParser:
    name = "text-artifact-parser"
    supported_suffixes = (".txt", ".log")
    supported_names: tuple[str, ...] = ()

    def parse(self, path: Path, max_text_bytes: int = 4 * 1024 * 1024) -> list[ArtifactEvent]:
        return load_txt_artifacts(path, max_text_bytes=max_text_bytes)


class EvtxArtifactParser:
    name = "evtx-artifact-parser"
    supported_suffixes = (".evtx",)
    supported_names: tuple[str, ...] = ()

    def parse(self, path: Path, max_text_bytes: int = 4 * 1024 * 1024) -> list[ArtifactEvent]:
        del max_text_bytes
        return load_evtx_artifacts(path)


class PcapArtifactParser:
    name = "pcap-artifact-parser"
    supported_suffixes = (".pcap", ".pcapng")
    supported_names: tuple[str, ...] = ()

    def parse(self, path: Path, max_text_bytes: int = 4 * 1024 * 1024) -> list[ArtifactEvent]:
        del max_text_bytes
        return load_pcap_artifacts(path)


class PrefetchArtifactParser:
    name = "prefetch-artifact-parser"
    supported_suffixes = (".pf",)
    supported_names: tuple[str, ...] = ()

    def parse(self, path: Path, max_text_bytes: int = 4 * 1024 * 1024) -> list[ArtifactEvent]:
        del max_text_bytes
        return load_prefetch_artifacts(path)


class RegistryArtifactParser:
    name = "registry-artifact-parser"
    supported_suffixes = (".hiv", ".hive")
    supported_names = ("SOFTWARE", "SYSTEM", "SAM", "SECURITY", "NTUSER.DAT", "USRCLASS.DAT")

    def parse(self, path: Path, max_text_bytes: int = 4 * 1024 * 1024) -> list[ArtifactEvent]:
        del max_text_bytes
        return load_registry_artifacts(path)


class MftArtifactParser:
    name = "mft-artifact-parser"
    supported_suffixes = (".mft",)
    supported_names = ("$MFT",)

    def parse(self, path: Path, max_text_bytes: int = 4 * 1024 * 1024) -> list[ArtifactEvent]:
        del max_text_bytes
        return load_mft_artifacts(path)


class MemoryDumpArtifactParser:
    name = "memory-dump-artifact-parser"
    supported_suffixes = (".raw", ".dmp", ".mem")
    supported_names: tuple[str, ...] = ()

    def parse(self, path: Path, max_text_bytes: int = 4 * 1024 * 1024) -> list[ArtifactEvent]:
        del max_text_bytes
        return load_memory_artifacts(path)


def discover_artifacts(
    input_dir: Path,
    max_text_bytes: int = 4 * 1024 * 1024,
    parser_registry: "ArtifactParserRegistry | None" = None,
) -> tuple[list[ArtifactEvent], list[Path]]:
    events: list[ArtifactEvent] = []
    binaries: list[Path] = []
    binary_suffixes = {".exe", ".dll", ".sys", ".bin"}
    if parser_registry is None:
        from .plugins import ArtifactParserRegistry

        parser_registry = ArtifactParserRegistry()
    parser_registry.register_defaults()

    root = input_dir.resolve()
    for path in sorted(bounded_tree_paths(root)):
        if not stays_in_tree(path, root):
            continue
        suffix = path.suffix.lower()
        if suffix in binary_suffixes:
            binaries.append(path)
            continue
        try:
            parsed = parser_registry.parse(path, max_text_bytes=max_text_bytes)
        except SecurityError:
            raise
        except (csv.Error, ValueError, UnicodeError, RecursionError, OverflowError, KeyError, TypeError) as exc:
            # One malformed file must not end the analysis of every other file.
            # The failure is kept as an event so the analyst sees the gap.
            logger.warning("Could not parse %s: %s", path.name, type(exc).__name__)
            parsed = [ArtifactEvent(
                artifact_id=_gen_artifact_id("parse-error", path.name, 0, None, type(exc).__name__),
                timestamp=None,
                event_type="parse_error",
                description=f"File could not be parsed ({type(exc).__name__}); review it manually",
                source=path.name,
                metadata={"parse_error": type(exc).__name__},
            )]
        _ensure_provenance(parsed, path, str(path.relative_to(root)))
        events.extend(parsed)

    return events, binaries

