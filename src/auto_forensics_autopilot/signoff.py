"""Analyst sign-off gate.

Every finding in the draft needs an accept or reject from a named
analyst. Decisions are appended to ``signoff.jsonl``; nothing in that
log is rewritten. A decision on a core finding is also recorded in the
core run's own custody log, so the core report shows it too.

``sign`` refuses while any finding is pending, or when the draft, the
decision log, or the evidence no longer match what was recorded.
``export`` refuses without a valid signature. Only accepted findings
reach the final report, which is written as JSON, Markdown and one
self-contained HTML page for printing.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from contextlib import ExitStack
from pathlib import Path
from typing import Any, Callable

from auto_forensics.file_ops import atomic_write_text, directory_lock
from auto_forensics.manifest import hash_input_tree
from auto_forensics.models import utc_now_iso
from auto_forensics.security import SecurityError

from .coordinator import canonical_sha256, render_markdown
from .orchestrator import CUSTODY_FILE, DRAFT_JSON, MANIFEST_FILE, AutopilotError, read_json, write_json
from .report_html import render_html

SIGNOFF_LOG = "signoff.jsonl"
SIGNATURE_FILE = "signature.json"
FINAL_JSON = "final_report.json"
FINAL_MD = "final_report.md"
FINAL_HTML = "final_report.html"
DECISIONS = {"accept", "reject"}
MAX_NOTE = 2000
MIN_FINGERPRINT = 32
SIGNING_KEY_ENV = "AUTO_FORENSICS_SIGNING_KEY"


def fingerprint(run_dir: Path) -> str:
    """SHA-256 of the run manifest file. Shown at ``start``; the analyst types it back at ``sign``.

    The manifest holds the draft and custody hashes, so anyone who swaps the
    draft must also rewrite the manifest, which changes this value. Keeping it
    outside the run folder (in notes, a ticket, the terminal) is what makes
    that visible.
    """
    return hashlib.sha256((run_dir.resolve() / MANIFEST_FILE).read_bytes()).hexdigest()


def signature_fingerprint(run_dir: Path) -> str:
    """The fingerprint ``sign`` printed, read back from signature.json ('' if unsigned)."""
    path = run_dir.resolve() / SIGNATURE_FILE
    return str(read_json(path).get("signature_fingerprint", "")) if path.is_file() else ""


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
    return decide_many(run_dir, finding_ids=[finding_id], decision=decision, actor=actor, note=note,
                       override=override)[0]


def decide_many(
    run_dir: Path, *, finding_ids: list[str], decision: str, actor: str, note: str = "", override: bool = False,
) -> list[dict[str, Any]]:
    """Record the same decision on several findings: one log line each, in the order given.

    Everything that can be checked up front is checked before the first line
    is written. The core run and the evidence are verified once for the whole
    batch (under the run lock and the core run's own lock), not once per
    finding: hashing a large evidence folder for every finding made a batch
    of core findings take minutes. If a later finding is still refused, the
    lines already written stay, and the exception carries their ids in
    ``decided``.
    """
    run_dir = run_dir.resolve()
    with directory_lock(run_dir), ExitStack() as stack:
        if (run_dir / SIGNATURE_FILE).exists():
            raise AutopilotError("This draft is already signed; decisions are closed")
        draft, manifest = _load(run_dir)
        decision = _clean(decision, "decision", 10).lower()
        if decision not in DECISIONS:
            raise AutopilotError("decision must be accept or reject")
        actor = _clean(actor, "actor", 120)
        note = _clean(note, "note", MAX_NOTE, required=decision == "reject")
        by_id = {f["finding_id"]: f for f in draft["findings"]}
        ids = list(dict.fromkeys(finding_ids))
        if not ids:
            raise AutopilotError("Select at least one finding")
        for finding_id in ids:
            if finding_id not in by_id:
                raise AutopilotError(f"No finding with id {finding_id!r} in this draft")
        latest = latest_decisions(read_log(run_dir))
        if not override:
            for finding_id in ids:
                prior = latest.get(finding_id)
                if prior:
                    raise AutopilotError(
                        f"{prior['actor']} already set this finding to {prior['decision']} at {prior['at']}")
        core_dir = (run_dir / "core").resolve()
        log_path = run_dir / SIGNOFF_LOG
        log_text = log_path.read_text(encoding="utf-8") if log_path.is_file() else ""
        written: list[dict[str, Any]] = []
        try:
            if any(by_id[finding_id]["worker"] == "core_pipeline" for finding_id in ids):
                evidence = Path(read_json(run_dir / CUSTODY_FILE)["evidence_dir"])
                _core(lambda: stack.enter_context(directory_lock(core_dir)))
                _core(lambda: _verify_core_once(core_dir, evidence))
            for finding_id in ids:
                prior = latest.get(finding_id)
                if by_id[finding_id]["worker"] == "core_pipeline":
                    _core(lambda fid=finding_id, again=bool(prior): _record_core(
                        core_dir, fid, decision, actor, note, override=again))
                entry = {
                    "finding_id": finding_id,
                    "decision": decision,
                    "actor": actor,
                    "note": note,
                    "at": utc_now_iso(),
                    "override": bool(prior),
                    "draft_sha256": manifest["draft_sha256"],
                }
                # One atomic append per decision, so a crash loses at most the decision in flight.
                log_text += json.dumps(entry, sort_keys=True) + "\n"
                atomic_write_text(log_path, log_text)
                latest[finding_id] = entry
                written.append(entry)
        except Exception as exc:
            exc.decided = [entry["finding_id"] for entry in written]  # type: ignore[attr-defined]
            raise
        return written


def _core(action: Callable[[], Any]) -> Any:
    """Run one step against the core run; its refusals become ours, as ``record_review`` reports them."""
    from auto_forensics.reviews import ReviewError

    try:
        return action()
    except (ReviewError, SecurityError) as exc:
        raise AutopilotError(f"The core run refused the decision: {exc}") from exc


def _verify_core_once(core_dir: Path, evidence: Path) -> None:
    """The check ``reviews.record_review`` makes before every decision, made once for a batch."""
    from auto_forensics.integrity import verify_run
    from auto_forensics.manifest import read_run_manifest
    from auto_forensics.reviews import ReviewError
    from auto_forensics.version import __version__ as core_version

    if read_run_manifest(core_dir / "run_manifest.json").get("tool_version") != core_version:
        raise ReviewError("Review requires the tool version recorded in the manifest; no decision was recorded")
    if not verify_run(core_dir / "run_manifest.json", input_dir=evidence)["match"]:
        raise ReviewError("Run integrity check failed before review; no decision was recorded")


def _record_core(core_dir: Path, finding_id: str, decision: str, actor: str, note: str, *, override: bool) -> None:
    """Append one decision to the core run's own review log and republish its report.

    The caller holds the core run's lock and has verified the run and the
    evidence (``_verify_core_once``). ``_record_review`` is the core's own
    writer: the step ``record_review`` runs after that same verification.
    """
    from auto_forensics import reviews

    reviews._record_review(core_dir, finding_id=finding_id, decision=decision, actor=actor, note=note,
                           override=override, at=None)


def _check_evidence(run_dir: Path) -> dict[str, Any]:
    custody = read_json(run_dir / CUSTODY_FILE)
    evidence = Path(custody["evidence_dir"])
    if hash_input_tree(evidence) != custody["files"]:
        raise AutopilotError("The evidence no longer matches the custody record")
    return custody


def sign(run_dir: Path, *, actor: str, fingerprint_seen: str, statement: str = "",
         accept_gaps: bool = False) -> dict[str, Any]:
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
        failed = [a["name"] for a in draft.get("agents", []) if a.get("status") != "ok"]
        if failed and not accept_gaps:
            raise AutopilotError(f"Agent(s) did not finish cleanly: {', '.join(failed)}. Part of the evidence was not "
                                 "analysed; re-run, or sign with --accept-gaps to record that you accept the gap")
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
            "accepted_gaps": failed if accept_gaps else [],
        }
        seal = _seal(signature)
        signature["seal"] = {"method": "hmac-sha256", "value": seal} if seal else None
        signature["signature_fingerprint"] = canonical_sha256(signature)
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
    body = {key: value for key, value in signature.items() if key not in {"seal", "signature_fingerprint"}}
    if seal and not os.environ.get(SIGNING_KEY_ENV):
        raise AutopilotError("This signature is sealed; set the signing key to export it")
    if os.environ.get(SIGNING_KEY_ENV):
        expected = _seal(body)
        if not isinstance(seal, dict) or not hmac.compare_digest(str(seal.get("value")), str(expected)):
            raise AutopilotError("The signature seal does not verify with the configured signing key")
    unsigned = {key: value for key, value in signature.items() if key != "signature_fingerprint"}
    if signature.get("signature_fingerprint") != canonical_sha256(unsigned):
        raise AutopilotError("signature.json changed after signing")
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


def export(run_dir: Path, dest: Path, *, signature_seen: str) -> dict[str, Any]:
    """Write the final report. ``signature_seen`` is the signature fingerprint printed by ``sign``.

    Without a signing key the run folder cannot vouch for itself: anyone who
    can write to it can rewrite every file consistently. The fingerprint the
    analyst copied at signing time, kept outside the folder, is what catches that.
    """
    run_dir = run_dir.resolve()
    with directory_lock(run_dir):
        return _export_locked(run_dir, dest, signature_seen)


def _export_locked(run_dir: Path, dest: Path, signature_seen: str) -> dict[str, Any]:
    draft, manifest, signature, log_text = _check_signature(run_dir)
    seen = (signature_seen or "").strip().lower()
    if len(seen) < MIN_FINGERPRINT or not str(signature.get("signature_fingerprint", "")).startswith(seen):
        raise AutopilotError("The signature fingerprint does not match the one shown when the draft was signed")
    custody = read_json(run_dir / CUSTODY_FILE)
    dest = dest.resolve()
    if dest.is_relative_to(Path(custody["evidence_dir"]).resolve()):
        raise AutopilotError("Export destination must be outside the evidence directory")
    if dest == run_dir or dest.is_relative_to(run_dir):
        raise AutopilotError("Export destination must be outside the run folder")
    if any((dest / name).exists() for name in (FINAL_JSON, FINAL_MD, FINAL_HTML)):
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
    sealed = "sealed with the signing key" if signature.get("seal") else "unsealed (no signing key was set)"
    final["status"] = f"SIGNED by {signature['actor']} at {signature['signed_at']}, {sealed}"
    if signature.get("accepted_gaps"):
        final["status"] += f"; analyst accepted incomplete analysis by: {', '.join(signature['accepted_gaps'])}"
    final["findings"] = accepted
    final["rejected_findings"] = [
        {"finding_id": f["finding_id"], "title": f["title"], "analyst": f["analyst"], "analyst_note": f["analyst_note"]}
        for f in rejected
    ]
    final["headline"] = f"{len(accepted)} finding(s) accepted by the analyst; {len(rejected)} rejected."
    final["signature"] = signature
    # Render everything before writing anything, so a failure leaves no half-made export.
    markdown = render_markdown(final, title="Signed report")
    page = render_html(final, manifest)
    write_json(dest / FINAL_JSON, final)
    atomic_write_text(dest / FINAL_MD, markdown)
    atomic_write_text(dest / FINAL_HTML, page)
    return final
