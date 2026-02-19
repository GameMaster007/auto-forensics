from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from .models import CaseReport


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _stix_id(stix_type: str) -> str:
    return f"{stix_type}--{uuid.uuid4()}"


def build_stix_bundle(report: CaseReport) -> dict[str, Any]:
    now = _now()
    identity_id = _stix_id("identity")
    incident_id = _stix_id("incident")
    objects: list[dict[str, Any]] = [
        {
            "type": "identity",
            "id": identity_id,
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "name": "Auto Forensics Framework",
            "identity_class": "organization",
        },
        {
            "type": "incident",
            "id": incident_id,
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "name": f"Case {report.case_id}",
            "description": "Automated incident analysis output",
            "created_by_ref": identity_id,
        },
    ]

    for finding in report.findings:
        indicator_id = _stix_id("indicator")
        pattern_parts = [f"[x-auto-forensics-finding:id = '{finding.finding_id}']"]
        if finding.technique_id:
            pattern_parts.append(f"[x-mitre-technique:id = '{finding.technique_id}']")
        objects.append(
            {
                "type": "indicator",
                "id": indicator_id,
                "spec_version": "2.1",
                "created": now,
                "modified": now,
                "name": finding.title,
                "description": "\n".join(finding.evidence)[:5000],
                "indicator_types": ["malicious-activity"],
                "pattern": " AND ".join(pattern_parts),
                "pattern_type": "stix",
                "valid_from": now,
                "labels": [finding.severity, finding.tactic],
            }
        )
        objects.append(
            {
                "type": "relationship",
                "id": _stix_id("relationship"),
                "spec_version": "2.1",
                "created": now,
                "modified": now,
                "relationship_type": "indicates",
                "source_ref": indicator_id,
                "target_ref": incident_id,
            }
        )

    for ioc in report.iocs:
        observable_id = _stix_id("observed-data")
        objects.append(
            {
                "type": "observed-data",
                "id": observable_id,
                "spec_version": "2.1",
                "created": now,
                "modified": now,
                "first_observed": ioc.first_seen or report.generated_at,
                "last_observed": ioc.last_seen or report.generated_at,
                "number_observed": 1,
                "objects": {
                    "0": {
                        "type": "artifact",
                        "mime_type": f"application/x-auto-forensics-{ioc.ioc_type}",
                        "payload_bin": ioc.value.encode("utf-8").hex(),
                    }
                },
                "labels": [ioc.ioc_type],
            }
        )
        objects.append(
            {
                "type": "relationship",
                "id": _stix_id("relationship"),
                "spec_version": "2.1",
                "created": now,
                "modified": now,
                "relationship_type": "related-to",
                "source_ref": observable_id,
                "target_ref": incident_id,
            }
        )

    return {
        "type": "bundle",
        "id": _stix_id("bundle"),
        "spec_version": "2.1",
        "objects": objects,
    }
