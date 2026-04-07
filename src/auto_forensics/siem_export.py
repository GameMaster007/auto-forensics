"""SIEM export module for Auto Forensics.

Supports exporting forensics data to multiple SIEM platforms including
Splunk (HEC), Elasticsearch/ELK, and generic syslog/CEF formats.
"""
from __future__ import annotations

import json
import logging
import socket
import ssl
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol
from urllib.request import Request, urlopen
from urllib.error import HTTPError

logger = logging.getLogger(__name__)


class SIEMExporter(ABC):
    """Abstract base class for SIEM exporters."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self._validate_config()

    @abstractmethod
    def _validate_config(self) -> None:
        """Validate exporter-specific configuration."""
        pass

    @abstractmethod
    def export_event(self, event: dict[str, Any]) -> bool:
        """Export a single event to the SIEM."""
        pass

    @abstractmethod
    def export_batch(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        """Export a batch of events."""
        pass

    def _format_timestamp(self, ts: str | datetime | None) -> str:
        """Format timestamp for SIEM."""
        if ts is None:
            return datetime.now(timezone.utc).isoformat()
        if isinstance(ts, datetime):
            return ts.isoformat()
        return str(ts)


class SplunkHECExporter(SIEMExporter):
    """Export to Splunk via HTTP Event Collector."""

    def _validate_config(self) -> None:
        required = ["url", "token"]
        for key in required:
            if key not in self.config:
                raise ValueError(f"Splunk HEC config missing: {key}")

        self.url = self.config["url"].rstrip("/") + "/services/collector/event"
        self.token = self.config["token"]
        self.verify_ssl = self.config.get("verify_ssl", True)
        self.sourcetype = self.config.get("sourcetype", "auto-forensics")
        self.index = self.config.get("index", "main")

    def export_event(self, event: dict[str, Any]) -> bool:
        """Send single event to Splunk HEC."""
        payload = self._build_hec_payload(event)
        return self._send_to_splunk([payload])

    def export_batch(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        """Send batch of events to Splunk HEC."""
        if not events:
            return {"success": True, "sent": 0, "failed": 0}

        payloads = [self._build_hec_payload(e) for e in events]
        success = self._send_to_splunk(payloads)

        return {
            "success": success,
            "sent": len(events) if success else 0,
            "failed": 0 if success else len(events),
        }

    def _build_hec_payload(self, event: dict[str, Any]) -> dict[str, Any]:
        """Build HEC payload with metadata."""
        return {
            "time": self._format_timestamp(event.get("timestamp")),
            "event": event,
            "sourcetype": self.sourcetype,
            "source": event.get("source", "auto-forensics"),
            "index": self.index,
            "fields": {
                "case_id": event.get("case_id"),
                "event_type": event.get("event_type"),
                "risk_score": event.get("risk_score", 0),
            },
        }

    def _send_to_splunk(self, payloads: list[dict[str, Any]]) -> bool:
        """Send payloads to Splunk HEC."""
        headers = {
            "Authorization": f"Splunk {self.token}",
            "Content-Type": "application/json",
        }

        # HEC accepts newline-delimited JSON for batch
        body = "\\n".join(json.dumps(p) for p in payloads)

        try:
            req = Request(
                self.url,
                data=body.encode("utf-8"),
                headers=headers,
                method="POST",
            )

            # TODO: Handle SSL verification properly
            with urlopen(req, timeout=30) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                if result.get("code") != 0:
                    logger.error("Splunk HEC error: %s", result)
                    return False
                return True

        except HTTPError as e:
            logger.error("Splunk HEC HTTP error %s: %s", e.code, e.reason)
            return False
        except Exception as e:
            logger.error("Splunk HEC error: %s", e)
            return False


class ElasticsearchExporter(SIEMExporter):
    """Export to Elasticsearch/ELK stack."""

    def _validate_config(self) -> None:
        required = ["url"]
        for key in required:
            if key not in self.config:
                raise ValueError(f"Elasticsearch config missing: {key}")

        self.url = self.config["url"].rstrip("/")
        self.username = self.config.get("username")
        self.password = self.config.get("password")
        self.api_key = self.config.get("api_key")
        self.index_prefix = self.config.get("index_prefix", "auto-forensics")
        self.verify_ssl = self.config.get("verify_ssl", True)

    def export_event(self, event: dict[str, Any]) -> bool:
        """Index single event in Elasticsearch."""
        index = self._get_index_name(event)
        doc_id = event.get("event_id", self._generate_id())

        url = f"{self.url}/{index}/_doc/{doc_id}"
        return self._send_to_elasticsearch(url, event)

    def export_batch(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        """Bulk index events in Elasticsearch."""
        if not events:
            return {"success": True, "sent": 0, "failed": 0}

        # Build bulk request
        bulk_body = []
        for event in events:
            index = self._get_index_name(event)
            doc_id = event.get("event_id", self._generate_id())

            # Action line
            bulk_body.append(json.dumps({
                "index": {"_index": index, "_id": doc_id}
            }))
            # Document line
            bulk_body.append(json.dumps(event))

        url = f"{self.url}/_bulk"
        body = "\\n".join(bulk_body) + "\\n"

        try:
            req = self._create_request(url, body.encode("utf-8"))
            with urlopen(req, timeout=60) as resp:
                result = json.loads(resp.read().decode("utf-8"))

                if result.get("errors"):
                    failed = sum(1 for item in result.get("items", [])
                               if "error" in item.get("index", {}))
                    logger.error("Elasticsearch bulk errors: %s failed", failed)
                    return {"success": False, "sent": len(events) - failed, "failed": failed}

                return {"success": True, "sent": len(events), "failed": 0}

        except Exception as e:
            logger.error("Elasticsearch bulk error: %s", e)
            return {"success": False, "sent": 0, "failed": len(events)}

    def _get_index_name(self, event: dict[str, Any]) -> str:
        """Generate index name based on date."""
        ts = event.get("timestamp")
        if ts:
            try:
                dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
                date_str = dt.strftime("%Y.%m.%d")
            except (ValueError, TypeError):
                date_str = datetime.now(timezone.utc).strftime("%Y.%m.%d")
        else:
            date_str = datetime.now(timezone.utc).strftime("%Y.%m.%d")

        return f"{self.index_prefix}-{date_str}"

    def _create_request(self, url: str, data: bytes) -> Request:
        """Create authenticated request for Elasticsearch."""
        headers = {"Content-Type": "application/json"}

        if self.api_key:
            headers["Authorization"] = f"ApiKey {self.api_key}"
        elif self.username and self.password:
            import base64
            creds = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
            headers["Authorization"] = f"Basic {creds}"

        return Request(url, data=data, headers=headers, method="POST")

    def _send_to_elasticsearch(self, url: str, document: dict[str, Any]) -> bool:
        """Send document to Elasticsearch."""
        try:
            req = self._create_request(url, json.dumps(document).encode("utf-8"))
            with urlopen(req, timeout=30) as resp:
                return resp.status in (200, 201)
        except Exception as e:
            logger.error("Elasticsearch error: %s", e)
            return False

    def _generate_id(self) -> str:
        """Generate unique document ID."""
        import uuid
        return str(uuid.uuid4())


class SyslogExporter(SIEMExporter):
    """Export to syslog/UDP/TCP."""

    FACILITY_USER = 1
    SEVERITY_INFO = 6
    SEVERITY_WARNING = 4
    SEVERITY_ERROR = 3

    def _validate_config(self) -> None:
        self.host = self.config.get("host", "localhost")
        self.port = self.config.get("port", 514)
        self.protocol = self.config.get("protocol", "udp")
        self.use_tls = self.config.get("use_tls", False)
        self.facility = self.config.get("facility", self.FACILITY_USER)

        if self.protocol not in ("udp", "tcp"):
            raise ValueError("Protocol must be 'udp' or 'tcp'")

    def export_event(self, event: dict[str, Any]) -> bool:
        """Send event via syslog."""
        message = self._format_syslog(event)
        return self._send_syslog(message)

    def export_batch(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        """Send multiple events via syslog."""
        success_count = 0
        for event in events:
            if self.export_event(event):
                success_count += 1

        return {
            "success": success_count == len(events),
            "sent": success_count,
            "failed": len(events) - success_count,
        }

    def _format_syslog(self, event: dict[str, Any]) -> str:
        """Format event as RFC 5424 syslog message."""
        # Calculate priority
        severity = self._get_severity(event.get("risk_score", 0))
        priority = self.facility * 8 + severity

        # Timestamp
        ts = self._format_timestamp(event.get("timestamp"))

        # Hostname
        hostname = socket.gethostname()

        # Structured data (optional)
        sd = self._build_structured_data(event)

        # Message
        msg = json.dumps(event, ensure_ascii=False)

        return f"<{priority}>1 {ts} {hostname} auto-forensics - - {sd} {msg}"

    def _get_severity(self, risk_score: float) -> int:
        """Map risk score to syslog severity."""
        if risk_score >= 8:
            return 2  # Critical
        elif risk_score >= 6:
            return 3  # Error
        elif risk_score >= 4:
            return 4  # Warning
        return 6  # Info

    def _build_structured_data(self, event: dict[str, Any]) -> str:
        """Build RFC 5424 structured data element."""
        elements = [
            f'case_id="{event.get("case_id", "")}"',
            f'event_type="{event.get("event_type", "")}"',
            f'risk_score="{event.get("risk_score", 0)}"',
        ]
        return f"[auto-forensics@12345 {' '.join(elements)}]"

    def _send_syslog(self, message: str) -> bool:
        """Send syslog message."""
        sock = None
        try:
            if self.protocol == "udp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(message.encode("utf-8"), (self.host, self.port))
                return True
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)

                if self.use_tls:
                    context = ssl.create_default_context()
                    sock = context.wrap_socket(sock, server_hostname=self.host)

                sock.connect((self.host, self.port))
                sock.sendall(message.encode("utf-8"))
                return True

        except Exception as e:
            logger.error("Syslog error: %s", e)
            return False

        finally:
            if sock:
                sock.close()


class CEFExporter(SIEMExporter):
    """Export in Common Event Format (CEF)."""

    def _validate_config(self) -> None:
        self.device_vendor = self.config.get("device_vendor", "AutoForensics")
        self.device_product = self.config.get("device_product", "Forensics Platform")
        self.device_version = self.config.get("device_version", "1.0")
        self.device_event_class = self.config.get("device_event_class", "forensics")

        self.output_file = self.config.get("output_file")
        self.output_dir = Path(self.config.get("output_dir", "."))

    def export_event(self, event: dict[str, Any]) -> bool:
        """Export single event as CEF."""
        cef_message = self._format_cef(event)

        if self.output_file:
            try:
                with open(self.output_file, "a") as f:
                    f.write(cef_message + "\\n")
                return True
            except Exception as e:
                logger.error("CEF file write error: %s", e)
                return False
        else:
            # Write to separate files per case
            case_id = event.get("case_id", "unknown")
            file_path = self.output_dir / f"{case_id}.cef"
            try:
                with open(file_path, "a") as f:
                    f.write(cef_message + "\\n")
                return True
            except Exception as e:
                logger.error("CEF file write error: %s", e)
                return False

    def export_batch(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        """Export batch as CEF."""
        success_count = 0
        for event in events:
            if self.export_event(event):
                success_count += 1

        return {
            "success": success_count == len(events),
            "sent": success_count,
            "failed": len(events) - success_count,
        }

    def _format_cef(self, event: dict[str, Any]) -> str:
        """Format event as CEF message."""
        # CEF:Version|DeviceVendor|DeviceProduct|DeviceVersion|SignatureID|Name|Severity|Extension
        sig_id = event.get("event_id", "1")
        name = event.get("description", "Forensics Event")
        severity = self._risk_to_severity(event.get("risk_score", 0))

        # Build extension
        extensions = []
        for key, value in event.items():
            if key in ("event_id", "description"):
                continue
            # Escape pipe characters in values
            safe_value = str(value).replace("|", "\\|").replace("\\", "\\\\")
            extensions.append(f"{key}={safe_value}")

        return (
            f"CEF:0|{self.device_vendor}|{self.device_product}|"
            f"{self.device_version}|{sig_id}|{name}|{severity}|"
            f"{' '.join(extensions)}"
        )

    def _risk_to_severity(self, risk_score: float) -> int:
        """Convert risk score to CEF severity (0-10)."""
        return min(int(risk_score), 10)


class SIEMExportManager:
    """Manages multiple SIEM exporters."""

    EXPORTERS = {
        "splunk_hec": SplunkHECExporter,
        "elasticsearch": ElasticsearchExporter,
        "syslog": SyslogExporter,
        "cef": CEFExporter,
    }

    def __init__(self, config: dict[str, Any]):
        """Initialize with export configuration.

        Args:
            config: Dict mapping exporter names to their configs.
        """
        self.exporters: dict[str, SIEMExporter] = {}
        self._init_exporters(config)

    def _init_exporters(self, config: dict[str, Any]) -> None:
        """Initialize configured exporters."""
        for name, exporter_config in config.items():
            if not exporter_config.get("enabled", True):
                continue

            exporter_type = exporter_config.get("type", name)
            if exporter_type not in self.EXPORTERS:
                logger.warning("Unknown SIEM exporter type: %s", exporter_type)
                continue

            try:
                exporter_class = self.EXPORTERS[exporter_type]
                self.exporters[name] = exporter_class(exporter_config)
                logger.info("Initialized %s SIEM exporter", name)
            except Exception as e:
                logger.error("Failed to initialize %s exporter: %s", name, e)

    def export_case_events(
        self,
        case_id: str,
        events: list[dict[str, Any]],
        exporters: list[str] | None = None,
    ) -> dict[str, Any]:
        """Export case events to configured SIEMs.

        Args:
            case_id: Case identifier.
            events: Events to export.
            exporters: Specific exporters to use (None = all).

        Returns:
            Export results by exporter name.
        """
        # Add case_id to all events
        for event in events:
            event["case_id"] = case_id
            if "timestamp" not in event:
                event["timestamp"] = datetime.now(timezone.utc).isoformat()

        results = {}
        target_exporters = exporters or list(self.exporters.keys())

        for name in target_exporters:
            if name not in self.exporters:
                results[name] = {"success": False, "error": "Exporter not configured"}
                continue

            try:
                result = self.exporters[name].export_batch(events)
                results[name] = result
            except Exception as e:
                logger.error("Export to %s failed: %s", name, e)
                results[name] = {"success": False, "error": str(e)}

        return results

    def test_exporter(self, name: str) -> bool:
        """Test connectivity to an exporter."""
        if name not in self.exporters:
            return False

        test_event = {
            "event_id": "test",
            "event_type": "test",
            "description": "SIEM connectivity test",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "risk_score": 0,
        }

        return self.exporters[name].export_event(test_event)

    def get_exporter_status(self) -> dict[str, str]:
        """Get status of all configured exporters."""
        return {
            name: "configured" for name in self.exporters.keys()
        }


def create_index_template() -> dict[str, Any]:
    """Create Elasticsearch index template for forensics data."""
    return {
        "index_patterns": ["auto-forensics-*"],
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 1,
            },
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "case_id": {"type": "keyword"},
                    "event_type": {"type": "keyword"},
                    "event_id": {"type": "keyword"},
                    "description": {"type": "text"},
                    "risk_score": {"type": "float"},
                    "mitre_technique": {"type": "keyword"},
                    "source_ip": {"type": "ip"},
                    "dest_ip": {"type": "ip"},
                    "domain": {"type": "keyword"},
                    "hash": {"type": "keyword"},
                }
            }
        }
    }
