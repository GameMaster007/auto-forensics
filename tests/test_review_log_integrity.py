"""Checksummed producer records must still agree with their analyst log."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import test_projection_corruption as existing
from auto_forensics.integrity import verify_run
from auto_forensics.manifest import canonical_report_sha256, hash_output_files, write_run_manifest
from auto_forensics.replay import replay_manifest
from auto_forensics.security import SecurityError

database_backend = existing.database_backend


@pytest.mark.parametrize("scenario", ["unlogged-accept", "contradictory-decision", "wrong-actor", "wrong-note", "orphan-entry", "wrong-count", "wrong-verified-ids"])
def test_checksum_valid_review_inconsistency_cannot_verify_or_synchronize(database_backend, tmp_path, scenario):
    service = existing._case(database_backend, tmp_path)
    output = Path(service.require_case("corruption-case")["output_dir"])
    finding_id = service.db.get_findings("corruption-case")[0]["finding_id"]
    if scenario == "contradictory-decision":
        service.review_finding("corruption-case", finding_id=finding_id, decision="reject", actor="Ada")
    elif scenario == "wrong-note":
        service.review_finding("corruption-case", finding_id=finding_id, decision="annotate", actor="Ada", note="Actual annotation")
    elif scenario in {"wrong-actor", "wrong-count", "wrong-verified-ids"}:
        service.review_finding("corruption-case", finding_id=finding_id, decision="accept", actor="Ada")
    before = service.db.get_findings("corruption-case")
    report_path, manifest_path = output / "case_report.json", output / "run_manifest.json"
    report, manifest = json.loads(report_path.read_text()), json.loads(manifest_path.read_text())
    finding = next(item for item in report["findings"] if item["finding_id"] == finding_id)
    if scenario in {"unlogged-accept", "contradictory-decision"}:
        finding.update(review_status="accepted", analyst_verified=True, review_actor="Invented actor", review_at="2026-11-07T01:00:00Z")
        finding["verification"] = finding["machine_verification"] or finding["verification"]
        report["summary"].update(analyst_accepted=1, analyst_rejected=0, analyst_unverified=len(report["findings"]) - 1, verified_finding_ids=[finding_id])
    elif scenario == "wrong-actor":
        finding["review_actor"] = "Invented actor"
    elif scenario == "wrong-note":
        finding["review_note"] = "Invented annotation"
    elif scenario == "wrong-count":
        report["summary"]["analyst_accepted"] = 99
    elif scenario == "wrong-verified-ids":
        report["summary"]["verified_finding_ids"] = ["unknown-finding"]
    else:
        entry = {"finding_id": "unknown-finding", "action": "accept", "actor": "Ada", "at": "2026-11-07T01:00:00Z", "note": "", "override": False}
        content = (json.dumps(entry) + "\n").encode()
        (output / "analyst_reviews.jsonl").write_bytes(content)
        manifest["analyst_reviews"] = {"log": "analyst_reviews.jsonl", "entries": 1, "sha256": hashlib.sha256(content).hexdigest(), "size_bytes": len(content)}
    report_path.write_text(json.dumps(report))
    manifest["output"]["sha256"] = canonical_report_sha256(report)
    manifest["artifacts"] = hash_output_files(output)
    write_run_manifest(manifest_path, manifest)
    verified = verify_run(manifest_path)
    assert verified["report_match"] is True and verified["artifacts_match"] is True
    assert verified["match"] is False and verified["reviews_match"] is False
    assert verified["errors"]
    with pytest.raises(SecurityError, match="integrity"):
        service.sync_case_report("corruption-case")
    assert service.db.get_findings("corruption-case") == before
    assert service.check_case_integrity("corruption-case")["match"] is False


def test_genuine_review_override_history_still_verifies_and_replays(database_backend, tmp_path):
    service = existing._case(database_backend, tmp_path)
    finding_id = service.db.get_findings("corruption-case")[0]["finding_id"]
    service.review_finding("corruption-case", finding_id=finding_id, decision="reject", actor="Ada", note="Initial decision")
    service.review_finding("corruption-case", finding_id=finding_id, decision="accept", actor="Bea", override=True, note="Rechecked evidence")
    service.review_finding("corruption-case", finding_id=finding_id, decision="annotate", actor="Cai", note="Later annotation")
    output = Path(service.require_case("corruption-case")["output_dir"])
    assert verify_run(output / "run_manifest.json")["match"] is True
    assert replay_manifest(output / "run_manifest.json")["match"] is True
    service.sync_case_report("corruption-case")
    assert service.check_case_integrity("corruption-case")["match"] is True


def test_replay_uses_the_checked_log_snapshot_if_source_is_changed_directly(database_backend, tmp_path, monkeypatch):
    import auto_forensics.replay as replay

    service = existing._case(database_backend, tmp_path)
    finding_id = service.db.get_findings("corruption-case")[0]["finding_id"]
    service.review_finding("corruption-case", finding_id=finding_id, decision="annotate", actor="Ada", note="Same annotation")
    output = Path(service.require_case("corruption-case")["output_dir"])
    log = output / "analyst_reviews.jsonl"
    original_bytes = log.read_bytes()
    original_run = replay.run_case
    def change_source_after_checks(config):
        report = original_run(config)
        record = json.loads(log.read_text())
        record["actor"] = "Bea"
        log.write_text(json.dumps(record) + "\n")
        return report
    monkeypatch.setattr(replay, "run_case", change_source_after_checks)
    destination = tmp_path / "replayed"
    assert replay.replay_manifest(output / "run_manifest.json", destination)["match"] is True
    assert (destination / "analyst_reviews.jsonl").read_bytes() == original_bytes
    assert verify_run(destination / "run_manifest.json")["match"] is True
    assert verify_run(output / "run_manifest.json")["match"] is False
