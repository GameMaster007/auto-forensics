"""Analyst sign-off gate.

Every finding in the draft needs an accept or reject from a named
analyst. Decisions are appended to ``signoff.jsonl``; nothing in that
log is rewritten. A decision on a core finding is also recorded in the
core run's own custody log, so the core report shows it too.

``sign`` refuses while any finding is pending, or when the draft, the
decision log, or the evidence no longer match what was recorded.
``export`` refuses without a valid signature. Only accepted findings
reach the final report.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any

from auto_forensics.file_ops import atomic_write_text, directory_lock
from auto_forensics.manifest import hash_input_tree
from auto_forensics.models import utc_now_iso

from .coordinator import canonical_sha256, render_markdown
from .orchestrator import CUSTODY_FILE, DRAFT_JSON, MANIFEST_FILE, AutopilotError, read_json, write_json

SIGNOFF_LOG = "signoff.jsonl"
SIGNATURE_FILE = "signature.json"
FINAL_JSON = "final_report.json"
FINAL_MD = "final_report.md"
DECISIONS = {"accept", "reject"}
MAX_NOTE = 2000
MIN_FINGERPRINT = 12
SIGNING_KEY_ENV = "AUTO_FORENSICS_SIGNING_KEY"


def fingerprint(run_dir: Path) -> str:
    """SHA-256 of the run manifest file. Shown at ``start``; the analyst types it back at ``sign``.

    The manifest holds the draft and custody hashes, so anyone who swaps the
    draft must also rewrite the manifest, which changes this value. Keeping it
    outside the run folder (in notes, a ticket, the terminal) is what makes
    that visible.
    """
    return hashlib.sha256((run_dir.resolve() / MANIFEST_FILE).read_bytes()).hexdigest()


def _seal(body: dict[str, Any]) -> str | None:
    key = os.environ.get(SIGNING_KEY_ENV, "")
    if not key:
        return None
    return hmac.new(key.encode("utf-8"), canonical_sha256(body).encode("ascii"), hashlib.sha256).hexdigest()


def _clean(value: str, label: str, limit: int, required: bool = True) -> str:
    if not isinstance(value, str):
        raise AutopilotError(f"{label} must be text")
    text = " ".join(value.split())
    if required and not text:
        raise AutopilotError(f"{label} is required")
    if len(text) > limit:
        raise AutopilotError(f"{label} is longer than {limit} characters")
    if any(ord(ch) < 32 for ch in text):
        raise AutopilotError(f"{label} contains control characters")
    return text


def _load(run_dir: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    run_dir = run_dir.resolve()
    draft_path = run_dir / DRAFT_JSON
    manifest_path = run_dir / MANIFEST_FILE
    if not draft_path.is_file() or not manifest_path.is_file():
        raise AutopilotError("This folder has no autopilot draft; run 'start' first")
    draft = read_json(draft_path)
    manifest = read_json(manifest_path)
    if canonical_sha256(draft) != manifest.get("draft_sha256"):
        raise AutopilotError("The draft was changed after the run; it can no longer be signed")
    return draft, manifest


def read_log(run_dir: Path) -> list[dict[str, Any]]:
    path = run_dir / SIGNOFF_LOG
    if not path.is_file():
        return []
    entries = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except ValueError as exc:
            raise AutopilotError(f"signoff.jsonl line {number} is not valid JSON") from exc
        if not isinstance(entry, dict):
            raise AutopilotError(f"signoff.jsonl line {number} is not an object")
        entries.append(entry)
    return entries


def _check_entries(entries: list[dict[str, Any]]) -> None:
    for number, entry in enumerate(entries, start=1):
        if entry.get("decision") not in DECISIONS or not all(
            isinstance(entry.get(key), str) for key in ("finding_id", "actor", "note", "at", "draft_sha256")
        ):
            raise AutopilotError(f"signoff.jsonl entry {number} is malformed")


def latest_decisions(entries: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    for entry in entries:
        latest[str(entry.get("finding_id"))] = entry
    return latest


def status(run_dir: Path) -> dict[str, Any]:
    run_dir = run_dir.resolve()
    draft, _ = _load(run_dir)
    decided = latest_decisions(read_log(run_dir))
    ids = [f["finding_id"] for f in draft["findings"]]
    pending = [fid for fid in ids if fid not in decided]
    signature = None
    if (run_dir / SIGNATURE_FILE).is_file():
        signature = read_json(run_dir / SIGNATURE_FILE)
    by_id = {f["finding_id"]: f for f in draft["findings"]}
    return {
        "case_id": draft["case_id"],
        "pending_findings": [
            {
                "finding_id": fid,
                "severity": by_id[fid]["severity"],
                "title": by_id[fid]["title"],
                "cited_at": "; ".join(
                    c["source_file"] + (f" row {c['row']}" if c.get("row") else f" @{c.get('offset')}")
                    for c in by_id[fid]["citations"]
                ),
            }
            for fid in pending
        ],
        "total": len(ids),
        "accepted": sum(1 for fid in ids if decided.get(fid, {}).get("decision") == "accept"),
        "rejected": sum(1 for fid in ids if decided.get(fid, {}).get("decision") == "reject"),
        "pending": pending,
        "signed": signature is not None,
        "signed_by": signature.get("actor") if signature else None,
    }


def decide(
    run_dir: Path, *, finding_id: str, decision: str, actor: str, note: str = "", override: bool = False,
) -> dict[str, Any]:
    run_dir = run_dir.resolve()
    with directory_lock(run_dir):
        if (run_dir / SIGNATURE_FILE).exists():
            raise AutopilotError("This draft is already signed; decisions are closed")
        draft, manifest = _load(run_dir)
        decision = _clean(decision, "decision", 10).lower()
        if decision not in DECISIONS:
            raise AutopilotError("decision must be accept or reject")
        actor = _clean(actor, "actor", 120)
        note = _clean(note, "note", MAX_NOTE, required=decision == "reject")
        finding = next((f for f in draft["findings"] if f["finding_id"] == finding_id), None)
        if finding is None:
            raise AutopilotError(f"No finding with id {finding_id!r} in this draft")
        entries = read_log(run_dir)
        prior = latest_decisions(entries).get(finding_id)
        if prior and not override:
            raise AutopilotError(f"{prior['actor']} already set this finding to {prior['decision']} at {prior['at']}")
        if finding["worker"] == "core_pipeline":
            _record_core(run_dir, finding_id, decision, actor, note, override=bool(prior))
        entry = {
            "finding_id": finding_id,
            "decision": decision,
            "actor": actor,
            "note": note,
            "at": utc_now_iso(),
            "override": bool(prior),
            "draft_sha256": manifest["draft_sha256"],
        }
        previous = (run_dir / SIGNOFF_LOG).read_text(encoding="utf-8") if (run_dir / SIGNOFF_LOG).is_file() else ""
        atomic_write_text(run_dir / SIGNOFF_LOG, previous + json.dumps(entry, sort_keys=True) + "\n")
        return entry


def _record_core(run_dir: Path, finding_id: str, decision: str, actor: str, note: str, *, override: bool) -> None:
    from auto_forensics.reviews import ReviewError, record_review

    custody = read_json(run_dir / CUSTODY_FILE)
    try:
        record_review(run_dir / "core", finding_id=finding_id, decision=decision, actor=actor, note=note,
                      override=override, input_dir=Path(custody["evidence_dir"]))
    except ReviewError as exc:
        raise AutopilotError(f"The core run refused the decision: {exc}") from exc


def _check_evidence(run_dir: Path) -> dict[str, Any]:
    custody = read_json(run_dir / CUSTODY_FILE)
    evidence = Path(custody["evidence_dir"])
    if hash_input_tree(evidence) != custody["files"]:
        raise AutopilotError("The evidence no longer matches the custody record")
    return custody


def sign(run_dir: Path, *, actor: str, fingerprint_seen: str, statement: str = "") -> dict[str, Any]:
    run_dir = run_dir.resolve()
    with directory_lock(run_dir):
        if (run_dir / SIGNATURE_FILE).exists():
            raise AutopilotError("This draft is already signed")
        draft, manifest = _load(run_dir)
        seen = (fingerprint_seen or "").strip().lower()
        current = fingerprint(run_dir)
        if len(seen) < MIN_FINGERPRINT or not current.startswith(seen):
            raise AutopilotError("The run fingerprint does not match the one shown when the run finished; "
                                 "the draft or its manifest may have been replaced")
        actor = _clean(actor, "actor", 120)
        statement = _clean(statement, "statement", MAX_NOTE, required=False)
        custody = _check_evidence(run_dir)
        if canonical_sha256(custody) != manifest["custody_sha256"]:
            raise AutopilotError("The custody record was changed after the run")
        entries = read_log(run_dir)
        _check_entries(entries)
        decided = latest_decisions(entries)
        pending = [f["finding_id"] for f in draft["findings"] if f["finding_id"] not in decided]
        if pending:
            raise AutopilotError(f"{len(pending)} finding(s) still need a decision: {', '.join(pending[:5])}")
        if any(e.get("draft_sha256") != manifest["draft_sha256"] for e in entries):
            raise AutopilotError("A decision in the log was made on a different draft")
        log_text = (run_dir / SIGNOFF_LOG).read_text(encoding="utf-8") if entries else ""
        signature = {
            "case_id": draft["case_id"],
            "actor": actor,
            "statement": statement,
            "signed_at": utc_now_iso(),
            "draft_sha256": manifest["draft_sha256"],
            "custody_sha256": manifest["custody_sha256"],
            "signoff_log_sha256": canonical_sha256(log_text),
            "accepted": sum(1 for d in decided.values() if d["decision"] == "accept"),
            "rejected": sum(1 for d in decided.values() if d["decision"] == "reject"),
            "run_fingerprint": current,
        }
        seal = _seal(signature)
        signature["seal"] = {"method": "hmac-sha256", "value": seal} if seal else None
        write_json(run_dir / SIGNATURE_FILE, signature)
        return signature


def _check_signature(run_dir: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], str]:
    """Everything export relies on, re-checked; returns the decision log text that was checked."""
    if not (run_dir / SIGNATURE_FILE).is_file():
        raise AutopilotError("This draft is not signed; export is blocked until an analyst signs it")
    draft, manifest = _load(run_dir)
    signature = read_json(run_dir / SIGNATURE_FILE)
    if not isinstance(signature, dict):
        raise AutopilotError("signature.json is malformed")
    seal = signature.get("seal")
    body = {key: value for key, value in signature.items() if key != "seal"}
    if os.environ.get(SIGNING_KEY_ENV):
        expected = _seal(body)
        if not isinstance(seal, dict) or not hmac.compare_digest(str(seal.get("value")), str(expected)):
            raise AutopilotError("The signature seal does not verify with the configured signing key")
    if signature.get("run_fingerprint") != fingerprint(run_dir):
        raise AutopilotError("The run manifest changed after signing")
    if signature.get("draft_sha256") != manifest["draft_sha256"]:
        raise AutopilotError("The signature does not match this draft")
    custody = read_json(run_dir / CUSTODY_FILE)
    if not canonical_sha256(custody) == manifest["custody_sha256"] == signature.get("custody_sha256"):
        raise AutopilotError("The custody record changed after the run")
    log_text = (run_dir / SIGNOFF_LOG).read_text(encoding="utf-8") if (run_dir / SIGNOFF_LOG).is_file() else ""
    if signature.get("signoff_log_sha256") != canonical_sha256(log_text):
        raise AutopilotError("The decision log changed after signing")
    entries = [json.loads(line) for line in log_text.splitlines() if line.strip()]
    _check_entries(entries)
    decided = latest_decisions(entries)
    accepted = sum(1 for d in decided.values() if d["decision"] == "accept")
    rejected = sum(1 for d in decided.values() if d["decision"] == "reject")
    if (accepted, rejected) != (signature.get("accepted"), signature.get("rejected")):
        raise AutopilotError("The signature's decision counts do not match the decision log")
    if any(f["finding_id"] not in decided for f in draft["findings"]):
        raise AutopilotError("A finding in the draft has no decision")
    _check_evidence(run_dir)
    return draft, manifest, signature, log_text


def export(run_dir: Path, dest: Path) -> dict[str, Any]:
    run_dir = run_dir.resolve()
    with directory_lock(run_dir):
        return _export_locked(run_dir, dest)


def _export_locked(run_dir: Path, dest: Path) -> dict[str, Any]:
    draft, manifest, signature, log_text = _check_signature(run_dir)
    custody = read_json(run_dir / CUSTODY_FILE)
    dest = dest.resolve()
    if dest.is_relative_to(Path(custody["evidence_dir"]).resolve()):
        raise AutopilotError("Export destination must be outside the evidence directory")
    if dest == run_dir or dest.is_relative_to(run_dir):
        raise AutopilotError("Export destination must be outside the run folder")
    if (dest / FINAL_JSON).exists() or (dest / FINAL_MD).exists():
        raise AutopilotError("The export folder already holds a final report; choose a new folder")
    dest.mkdir(parents=True, exist_ok=True)
    decided = latest_decisions([json.loads(line) for line in log_text.splitlines() if line.strip()])
    accepted = []
    rejected = []
    for finding in draft["findings"]:
        entry = dict(finding)
        choice = decided[finding["finding_id"]]
        entry["decision"] = choice["decision"]
        entry["analyst"] = choice["actor"]
        entry["analyst_note"] = choice["note"]
        (accepted if choice["decision"] == "accept" else rejected).append(entry)
    final = dict(draft)
    final["status"] = f"SIGNED by {signature['actor']} at {signature['signed_at']}"
    final["findings"] = accepted
    final["rejected_findings"] = [
        {"finding_id": f["finding_id"], "title": f["title"], "analyst": f["analyst"], "analyst_note": f["analyst_note"]}
        for f in rejected
    ]
    final["headline"] = f"{len(accepted)} finding(s) accepted by the analyst; {len(rejected)} rejected."
    final["signature"] = signature
    write_json(dest / FINAL_JSON, final)
    atomic_write_text(dest / FINAL_MD, render_markdown(final, title="Signed report"))
    return final
