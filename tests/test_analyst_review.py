"""Analyst accept, reject, and annotate stay on the report through replay."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from auto_forensics.cli import main
from auto_forensics.pipeline import PipelineConfig, run_case
from auto_forensics.replay import replay_manifest
from auto_forensics.reviews import ANALYST_REVIEW_LOG, ReviewError, record_review


def _run(tmp_path: Path) -> Path:
    source = tmp_path / "evidence"
    source.mkdir()
    (source / "payload.bin").write_bytes(b"MZ powershell -nop -w hidden\n")
    output = tmp_path / "out"
    run_case(
        PipelineConfig(
            case_id="review-demo",
            input_dir=source,
            output_dir=output,
            enable_llama=True,
            llm_provider="mock",
        )
    )
    return output


def _report(output: Path) -> dict:
    return json.loads((output / "case_report.json").read_text(encoding="utf-8"))


def _section(markdown: str, title: str) -> str:
    for part in markdown.split("\n- ["):
        if title in part:
            return part
    raise AssertionError(title)


def test_review_records_who_and_when_and_a_reject_is_not_verified(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("AUTO_FORENSICS_OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("AUTO_FORENSICS_OPENAI_ENDPOINT", raising=False)
    output = _run(tmp_path)
    fresh = _report(output)
    assert fresh["summary"]["verified_finding_ids"] == []
    assert all(item["review_status"] == "unverified" for item in fresh["findings"])
    assert all(item["analyst_verified"] is False for item in fresh["findings"])
    finding = fresh["findings"][0]
    finding_id = finding["finding_id"]
    machine = finding["verification"]
    assert machine != "not verified"

    noted = record_review(
        output,
        finding_id=finding_id,
        decision="annotate",
        actor="Ada Analyst",
        note="Open the cited row before deciding.",
    )
    after_note = _report(output)
    noted_finding = next(item for item in after_note["findings"] if item["finding_id"] == finding_id)
    assert noted["action"] == "annotate"
    assert noted_finding["review_status"] == "unverified"
    assert noted_finding["analyst_verified"] is False
    assert noted_finding["review_note"] == "Open the cited row before deciding."

    accepted = record_review(
        output,
        finding_id=finding_id,
        decision="accept",
        actor="Ada Analyst",
    )
    after_accept = _report(output)
    accepted_finding = next(item for item in after_accept["findings"] if item["finding_id"] == finding_id)
    assert accepted_finding["review_status"] == "accepted"
    assert accepted_finding["analyst_verified"] is True
    assert accepted_finding["review_actor"] == "Ada Analyst"
    assert accepted_finding["review_at"] == accepted["at"]
    assert accepted_finding["verification"] == machine
    assert accepted_finding["review_note"] == "Open the cited row before deciding."
    assert after_accept["summary"]["verified_finding_ids"] == [finding_id]
    markdown = (output / "case_report.md").read_text(encoding="utf-8")
    assert "analyst-accepted" in _section(markdown, accepted_finding["title"])

    before_conflict = (output / "case_report.json").read_bytes()
    with pytest.raises(ReviewError, match="Ada Analyst"):
        record_review(
            output,
            finding_id=finding_id,
            decision="reject",
            actor="Bea Analyst",
            note="Disagree.",
        )
    assert (output / "case_report.json").read_bytes() == before_conflict

    rejected = record_review(
        output,
        finding_id=finding_id,
        decision="reject",
        actor="Bea Analyst",
        note="The cited row does not support the draft.",
        override=True,
    )
    final = _report(output)
    rejected_finding = next(item for item in final["findings"] if item["finding_id"] == finding_id)
    assert rejected_finding["review_status"] == "rejected"
    assert rejected_finding["analyst_verified"] is False
    assert rejected_finding["verification"] == "not verified"
    assert rejected_finding["machine_verification"] == machine
    assert rejected_finding["review_actor"] == "Bea Analyst"
    assert rejected_finding["review_at"] == rejected["at"]
    assert finding_id not in final["summary"]["verified_finding_ids"]
    section = _section((output / "case_report.md").read_text(encoding="utf-8"), rejected_finding["title"])
    assert "analyst-rejected" in section
    assert "Verification: not verified" in section
    assert "Verification: supported" not in section
    assert "Verification: score-based" not in section
    log = (output / ANALYST_REVIEW_LOG).read_text(encoding="utf-8").splitlines()
    assert [json.loads(line)["actor"] for line in log] == ["Ada Analyst", "Ada Analyst", "Bea Analyst"]
    assert json.loads(log[0])["action"] == "annotate"
    assert "Ada Analyst" in log[1]

    replay = replay_manifest(output / "run_manifest.json", output_dir=tmp_path / "replay")
    assert replay["match"] is True
    assert replay["review_error"] == ""
    replayed = _report(tmp_path / "replay")
    replayed_finding = next(item for item in replayed["findings"] if item["finding_id"] == finding_id)
    assert replayed_finding["review_status"] == "rejected"
    assert replayed_finding["analyst_verified"] is False
    assert replayed_finding["verification"] == "not verified"
    assert replayed_finding["review_actor"] == "Bea Analyst"
    assert replayed_finding["review_at"] == rejected_finding["review_at"]
    assert finding_id not in replayed["summary"]["verified_finding_ids"]


def test_review_command_accepts_a_finding_offline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]):
    monkeypatch.delenv("AUTO_FORENSICS_OPENAI_API_KEY", raising=False)
    output = _run(tmp_path)
    finding_id = _report(output)["findings"][0]["finding_id"]
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "auto-forensics",
            "review",
            "--output-dir",
            str(output),
            "--finding-id",
            finding_id,
            "--decision",
            "accept",
            "--actor",
            "Ada Analyst",
            "--note",
            "Confirmed offline.",
        ],
    )
    main()
    captured = json.loads(capsys.readouterr().out)
    assert captured["action"] == "accept"
    assert captured["actor"] == "Ada Analyst"
    stored = _report(output)["findings"][0]
    assert stored["finding_id"] == finding_id
    assert stored["review_status"] == "accepted"
    assert stored["analyst_verified"] is True
    assert stored["review_note"] == "Confirmed offline."
