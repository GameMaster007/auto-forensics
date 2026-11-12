"""One-click run: custody, triage, parallel agents, coordinated draft.

``start`` is the only entry point that writes a run. It refuses an
output directory inside the evidence, refuses to reuse a run directory,
and re-hashes the evidence after the agents finish. If any file changed,
no draft is published.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import platform
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable

from auto_forensics.artifacts import evtx_reader_name
from auto_forensics.case_store import MemoryCaseStore
from auto_forensics.file_ops import atomic_write_text, directory_lock
from auto_forensics.manifest import hash_input_tree
from auto_forensics.models import utc_now_iso
from auto_forensics.security import (
    IntegrityError,
    SecurityError,
    bounded_tree_paths,
    display_name,
    stays_in_tree,
    validate_case_id,
)
from auto_forensics.tools import ToolRegistry
from auto_forensics.version import __version__ as CORE_VERSION

from . import AUTOPILOT_VERSION
from .agents import AGENTS, MAX_SCAN_BYTES, AgentContext, AgentResult, agent_availability
from .coordinator import build_draft, canonical_sha256, merge_findings, render_markdown
from .triage import plan_agents, profile_evidence

CUSTODY_FILE = "custody.json"
TRIAGE_FILE = "triage.json"
DRAFT_JSON = "autopilot_draft.json"
DRAFT_MD = "autopilot_draft.md"
MANIFEST_FILE = "autopilot_manifest.json"
MAX_PARALLEL_AGENTS = 4
MAX_EVIDENCE_FILES = 10_000
PROGRESS_SECONDS = 0.25

# The five stages a run goes through, with the sentence shown to the person waiting.
STAGES: tuple[tuple[str, str], ...] = (
    ("hashing", "Fingerprinting every evidence file, so any later change can be detected."),
    ("planning", "Sorting the files by type and choosing which checks to run."),
    ("analysing", "Running the checks on the evidence."),
    ("checking", "Fingerprinting the evidence again to confirm nothing changed during the run."),
    ("writing", "Checking each finding against its source and writing the draft report."),
)
ProgressCallback = Callable[[dict[str, Any]], None]


class AutopilotError(SecurityError):
    """The run stopped. The message says why and what was not published."""


def inventory_map(rows: list[dict[str, Any]]) -> dict[str, str]:
    return {Path(row["path"]).as_posix(): str(row["sha256"]).lower() for row in rows}


def write_json(path: Path, data: Any) -> None:
    atomic_write_text(path, json.dumps(data, indent=2, sort_keys=True, ensure_ascii=True) + "\n")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


class _Progress:
    """Sends progress events to an optional listener. A listener that fails is ignored.

    Events are plain dicts with an ``event`` key:

    * ``stage``: ``stage``, ``stage_number``, ``stage_total``, ``stage_label``, and for
      the two hashing stages ``files_total`` and ``bytes_total``;
    * ``hash``: ``stage``, ``bytes_done``, ``bytes_total`` (a few times a second);
    * ``plan``: ``agents`` (``name`` and ``status`` ``waiting`` or ``skipped``), ``files_total``;
    * ``agent``: ``name`` and ``status`` (``running``, ``ok`` or ``failed``).
    """

    def __init__(self, callback: ProgressCallback | None) -> None:
        self.callback = callback
        self._last_hash = 0.0

    @property
    def active(self) -> bool:
        return self.callback is not None

    def emit(self, event: str, **fields: Any) -> None:
        if self.callback is None:
            return
        try:
            self.callback({"event": event, **fields})
        except Exception:  # noqa: BLE001, S110 - progress is a courtesy; it must never stop a run
            pass

    def stage(self, name: str, **fields: Any) -> None:
        number = next(index for index, (stage, _) in enumerate(STAGES, start=1) if stage == name)
        self.emit("stage", stage=name, stage_number=number, stage_total=len(STAGES),
                  stage_label=STAGES[number - 1][1], **fields)

    def hashed(self, stage: str, done: int, total: int, *, force: bool = False) -> None:
        if self.callback is None:
            return
        now = time.monotonic()
        if force or now - self._last_hash >= PROGRESS_SECONDS:
            self._last_hash = now
            self.emit("hash", stage=stage, bytes_done=done, bytes_total=max(total, done))


def _tree_size(root: Path) -> tuple[int, int]:
    """(files, bytes) under ``root`` from directory entries only; used for the progress bar."""
    files = size = 0
    try:
        for path in bounded_tree_paths(root):
            if stays_in_tree(path, root):
                files += 1
                size += path.stat().st_size
    except (OSError, SecurityError):
        pass  # the hashing pass that follows reports the real problem
    return files, size


def _hash_tree(evidence: Path, progress: _Progress, stage: str) -> list[dict[str, Any]]:
    """The evidence inventory. Without a listener this is the core's ``hash_input_tree``.

    With a listener it is the same walk, the same checks and the same rows,
    hashed here one megabyte at a time so the bytes done can be reported.
    ``tests/test_autopilot_web_api.py`` holds the two to identical output.
    """
    if not progress.active:
        return hash_input_tree(evidence)
    root = evidence.resolve()
    if not root.is_dir():
        raise SecurityError(f"Evidence directory does not exist: {evidence}")
    files, total = _tree_size(root)
    progress.stage(stage, files_total=files, bytes_total=total)
    rows: list[dict[str, Any]] = []
    done = 0
    for path in bounded_tree_paths(root):
        if not stays_in_tree(path, root):
            continue
        if len(rows) >= MAX_EVIDENCE_FILES:
            raise SecurityError(f"Evidence exceeds the manifest file limit ({MAX_EVIDENCE_FILES})")
        before = path.stat()
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
                done += len(chunk)
                progress.hashed(stage, done, total)
        after = path.stat()
        if not stays_in_tree(path, root) or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
        ):
            raise IntegrityError(f"Evidence changed while hashing: {path.relative_to(root)}")
        rows.append({"path": str(path.relative_to(root)), "sha256": digest.hexdigest().lower(),
                     "size_bytes": after.st_size})
    progress.hashed(stage, done, done, force=True)
    return sorted(rows, key=lambda row: row["path"])


def _check_paths(input_dir: Path, output_dir: Path) -> tuple[Path, Path]:
    evidence = input_dir.resolve()
    if not evidence.is_dir():
        raise AutopilotError(f"Evidence directory does not exist: {input_dir}")
    out = output_dir.resolve()
    if out == evidence or out.is_relative_to(evidence):
        raise AutopilotError("The output directory must be outside the evidence directory")
    if evidence.is_relative_to(out):
        raise AutopilotError("The evidence directory must not be inside the output directory")
    if out.exists() and any(out.iterdir()):
        raise AutopilotError("The output directory is not empty; use a new directory for each run")
    return evidence, out


class IntegrityAbort(AutopilotError):
    """An agent saw the evidence change; nothing is published."""


def _run_agent(name: str, ctx: AgentContext, store: MemoryCaseStore) -> AgentResult:
    tools = ToolRegistry(worker=name, store=store)
    started = time.monotonic()
    try:
        result = AGENTS[name]().run(ctx, store, tools)
    except IntegrityError as exc:
        raise IntegrityAbort(f"{name}: {exc}") from exc
    except SecurityError as exc:
        # Our own refusal text (for example a report the core will not publish).
        result = AgentResult(name, status="error", detail=f"SecurityError: {str(exc)[:200]}")
    except Exception as exc:  # noqa: BLE001 - an agent failure is recorded, not fatal
        # Only the type: a library message can quote evidence.
        result = AgentResult(name, status="error", detail=f"{type(exc).__name__} (see the run log)")
    result.notes["seconds"] = round(time.monotonic() - started, 3)
    return result


def start(
    *,
    input_dir: Path,
    output_dir: Path,
    case_id: str,
    actor: str | None = None,
    llm: str = "mock",
    llama_endpoint: str = "http://localhost:11434",
    llama_model: str = "llama3.1:8b",
    rules_dir: Path | None = None,
    only_agents: list[str] | None = None,
    progress: ProgressCallback | None = None,
) -> dict[str, Any]:
    """Run the whole autopilot and return the draft. Raises AutopilotError on refusal.

    ``progress`` is called with a dict at each stage change, a few times a
    second while hashing, and when each agent starts and ends (see
    ``_Progress``). It runs on the worker threads; an exception it raises is ignored.
    """
    validate_case_id(case_id)
    if llm not in {"off", "mock", "ollama"}:
        raise AutopilotError("llm must be off, mock, or ollama")
    evidence, out = _check_paths(input_dir, output_dir)
    with directory_lock(out):
        # Checked again under the lock: another start may have used this folder
        # between the first check and taking the lock.
        if out.exists() and any(out.iterdir()):
            raise AutopilotError("The output directory is not empty; use a new directory for each run")
        out.mkdir(parents=True, exist_ok=True)
        return _start_locked(evidence, out, case_id, actor, llm, llama_endpoint, llama_model, rules_dir,
                             only_agents, _Progress(progress))


def _start_locked(
    evidence: Path, out: Path, case_id: str, actor: str | None, llm: str,
    llama_endpoint: str, llama_model: str, rules_dir: Path | None, only_agents: list[str] | None,
    progress: _Progress,
) -> dict[str, Any]:
    # Stage 1: custody record before anything reads content.
    inventory_rows = _hash_tree(evidence, progress, "hashing")
    custody = {
        "case_id": case_id,
        "actor": (actor or _default_actor()).strip()[:120],
        "host": platform.node()[:120],
        "started_at": utc_now_iso(),
        "evidence_dir": str(evidence),
        "files": inventory_rows,
        "inventory_sha256": canonical_sha256(inventory_rows),
        "core_version": CORE_VERSION,
        "autopilot_version": AUTOPILOT_VERSION,
    }
    write_json(out / CUSTODY_FILE, custody)
    custody_sha256 = canonical_sha256(custody)

    # Stage 2: triage.
    progress.stage("planning", files_total=len(inventory_rows))
    profile = profile_evidence(evidence)
    plans = plan_agents(profile, agent_availability())
    if only_agents:
        unknown = sorted(set(only_agents) - set(AGENTS))
        if unknown:
            raise AutopilotError(f"Unknown agent(s): {', '.join(unknown)}")
        for plan in plans:
            if plan.run and plan.name not in only_agents:
                plan.run = False
                plan.reason = "not selected for this run"
    write_json(out / TRIAGE_FILE, {"profile": profile.to_dict(), "plan": [p.to_dict() for p in plans]})

    # Stage 3: agents in parallel, one shared store.
    store = MemoryCaseStore()
    ctx = AgentContext(case_id=case_id, input_dir=evidence, run_dir=out, profile=profile, llm=llm,
                       llama_endpoint=llama_endpoint, llama_model=llama_model, rules_dir=rules_dir,
                       inventory=inventory_map(inventory_rows))
    to_run = [p.name for p in plans if p.run and p.name in AGENTS]
    progress.emit("plan", files_total=len(inventory_rows),
                  agents=[{"name": p.name, "status": "waiting" if p.name in to_run else "skipped"} for p in plans])
    progress.stage("analysing")

    def run_one(name: str) -> AgentResult:
        progress.emit("agent", name=name, status="running")
        try:
            result = _run_agent(name, ctx, store)
        except BaseException:
            progress.emit("agent", name=name, status="failed")
            raise
        progress.emit("agent", name=name, status="ok" if result.status == "ok" else "failed")
        return result

    with ThreadPoolExecutor(max_workers=MAX_PARALLEL_AGENTS, thread_name_prefix="af-agent") as pool:
        results = list(pool.map(run_one, to_run))

    # Stage 4: evidence must be unchanged before anything is published.
    after_rows = _hash_tree(evidence, progress, "checking")
    if after_rows != inventory_rows:
        raise AutopilotError("Evidence changed during the run; no draft was published")

    # Stage 5: coordinate.
    progress.stage("writing")
    core_report = None
    core_path = out / "core" / "case_report.json"
    if core_path.is_file():
        core_report = read_json(core_path)
    inventory = inventory_map(inventory_rows)
    locate: dict[str, Path] = {}
    collisions: list[str] = []
    hostile = []
    extracted_dirs = {
        "archive": (out / "archives", "archives.json", lambda m: Path(m["folder"]) / m["extracted"]),
        "disk_image": (out / "disk", "disk_images.json", lambda m: Path(m["folder"]) / "files" / m["extracted"]),
    }
    extracted_dirs["disk_artifacts"] = extracted_dirs["disk_image"]  # whichever of the two ran first lists the copies
    for result in results:
        if result.name in {"injection_sentinel", "archive", "disk_image"}:
            hostile.extend(result.notes.get("files_flagged", []))
        if result.name in extracted_dirs and "members" in result.notes:
            base, listing, where = extracted_dirs[result.name]
            members = result.notes.pop("members", [])
            base.mkdir(exist_ok=True)
            write_json(base / listing, members)
            result.notes["members_extracted"] = len(members)
            for member in members:
                if member["cited_as"] in inventory:
                    # A real evidence file has this exact name; never let a member shadow it.
                    collisions.append(member["cited_as"])
                    continue
                inventory[member["cited_as"]] = member["sha256"]
                locate[member["cited_as"]] = base / where(member)
    findings, dropped = merge_findings(store.findings(), evidence, inventory, locate)
    gaps: list[dict[str, str]] = []
    for result in results:
        for rel in result.notes.get("files_truncated", []):
            gaps.append({"what": rel, "why": f"{result.name} scanned only the first {MAX_SCAN_BYTES // (1024 * 1024)} MB"})
        if result.status != "ok":
            gaps.append({"what": f"agent {result.name}", "why": f"agent status {result.status}"})
        for rel in result.notes.get("not_zip", []):
            gaps.append({"what": rel, "why": "archive is not a ZIP and was not opened"})
        gaps.extend(result.notes.pop("gaps", []))
    for name in profile.undecodable_names:
        gaps.append({"what": name, "why": "the file name is not valid text, so no check could read the file; "
                                          "it is fingerprinted in the custody record. Rename a copy and run again"})
    for name in collisions:
        gaps.append({"what": name, "why": "archive member has the same name as an evidence file; member not cited"})
    disk_plan = next((p for p in plans if p.name == "disk_image"), None)
    if disk_plan is not None and not disk_plan.run:
        for rel in profile.kinds.get("disk_image", []):
            gaps.append({"what": rel, "why": f"disk image was not opened ({disk_plan.reason}); "
                                             "or export it with Plaso first"})
    draft = build_draft(
        coverage_gaps=gaps,
        case_id=case_id,
        findings=findings,
        dropped=dropped,
        plan=[p.to_dict() for p in plans],
        agent_results=[r.to_dict() for r in results],
        hostile_files=hostile,
        core_report=core_report,
        custody_sha256=custody_sha256,
    )
    write_json(out / DRAFT_JSON, draft)
    atomic_write_text(out / DRAFT_MD, display_name(render_markdown(draft)))
    manifest = {
        "case_id": case_id,
        "finished_at": utc_now_iso(),
        "core_version": CORE_VERSION,
        "autopilot_version": AUTOPILOT_VERSION,
        "evtx_reader": evtx_reader_name(),
        "llm": llm,
        "llama_model": llama_model if llm == "ollama" else None,
        "custody_sha256": custody_sha256,
        "draft_sha256": canonical_sha256(draft),
        "agents": [r.to_dict() for r in results],
        "tool_calls": [call.to_dict() for call in store.tool_calls()],
        "workers": store.workers(),
    }
    core_manifest = out / "core" / "run_manifest.json"
    if core_manifest.is_file():
        manifest["core_manifest_sha256"] = canonical_sha256(read_json(core_manifest))
    write_json(out / MANIFEST_FILE, manifest)
    draft["run_fingerprint"] = hashlib.sha256((out / MANIFEST_FILE).read_bytes()).hexdigest()
    return draft


def _default_actor() -> str:
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001 - some containers have no passwd entry
        return os.environ.get("USER", "unknown")
