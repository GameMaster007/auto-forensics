"""One-click run: custody, triage, parallel agents, coordinated draft.

``start`` is the only entry point that writes a run. It refuses an
output directory inside the evidence, refuses to reuse a run directory,
and re-hashes the evidence after the agents finish. If any file changed,
no draft is published.
"""

from __future__ import annotations

import getpass
import json
import os
import platform
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from auto_forensics.artifacts import evtx_reader_name
from auto_forensics.case_store import MemoryCaseStore
from auto_forensics.file_ops import atomic_write_text, directory_lock
from auto_forensics.manifest import hash_input_tree
from auto_forensics.models import utc_now_iso
from auto_forensics.security import SecurityError, validate_case_id
from auto_forensics.tools import ToolRegistry
from auto_forensics.version import __version__ as CORE_VERSION

from . import AUTOPILOT_VERSION
from .agents import AGENTS, AgentContext, AgentResult, agent_availability
from .coordinator import build_draft, canonical_sha256, merge_findings, render_markdown
from .triage import plan_agents, profile_evidence

CUSTODY_FILE = "custody.json"
TRIAGE_FILE = "triage.json"
DRAFT_JSON = "autopilot_draft.json"
DRAFT_MD = "autopilot_draft.md"
MANIFEST_FILE = "autopilot_manifest.json"
MAX_PARALLEL_AGENTS = 4


class AutopilotError(SecurityError):
    """The run stopped. The message says why and what was not published."""


def inventory_map(rows: list[dict[str, Any]]) -> dict[str, str]:
    return {Path(row["path"]).as_posix(): str(row["sha256"]).lower() for row in rows}


def write_json(path: Path, data: Any) -> None:
    atomic_write_text(path, json.dumps(data, indent=2, sort_keys=True, ensure_ascii=True) + "\n")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


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


def _run_agent(name: str, ctx: AgentContext, store: MemoryCaseStore) -> AgentResult:
    tools = ToolRegistry(worker=name, store=store)
    started = time.monotonic()
    try:
        result = AGENTS[name]().run(ctx, store, tools)
    except Exception as exc:  # noqa: BLE001 - an agent failure is recorded, not fatal
        result = AgentResult(name, status="error", detail=f"{type(exc).__name__}: {str(exc)[:300]}")
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
) -> dict[str, Any]:
    """Run the whole autopilot and return the draft. Raises AutopilotError on refusal."""
    validate_case_id(case_id)
    if llm not in {"off", "mock", "ollama"}:
        raise AutopilotError("llm must be off, mock, or ollama")
    evidence, out = _check_paths(input_dir, output_dir)
    out.mkdir(parents=True, exist_ok=True)
    with directory_lock(out):
        return _start_locked(evidence, out, case_id, actor, llm, llama_endpoint, llama_model, rules_dir, only_agents)


def _start_locked(
    evidence: Path, out: Path, case_id: str, actor: str | None, llm: str,
    llama_endpoint: str, llama_model: str, rules_dir: Path | None, only_agents: list[str] | None,
) -> dict[str, Any]:
    # Stage 1: custody record before anything reads content.
    inventory_rows = hash_input_tree(evidence)
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
                       llama_endpoint=llama_endpoint, llama_model=llama_model, rules_dir=rules_dir)
    to_run = [p.name for p in plans if p.run and p.name in AGENTS]
    with ThreadPoolExecutor(max_workers=MAX_PARALLEL_AGENTS, thread_name_prefix="af-agent") as pool:
        results = list(pool.map(lambda name: _run_agent(name, ctx, store), to_run))

    # Stage 4: evidence must be unchanged before anything is published.
    after_rows = hash_input_tree(evidence)
    if after_rows != inventory_rows:
        raise AutopilotError("Evidence changed during the run; no draft was published")

    # Stage 5: coordinate.
    core_report = None
    core_path = out / "core" / "case_report.json"
    if core_path.is_file():
        core_report = read_json(core_path)
    findings, dropped = merge_findings(store.findings(), evidence, inventory_map(inventory_rows))
    hostile = []
    for result in results:
        if result.name == "injection_sentinel":
            hostile.extend(result.notes.get("files_flagged", []))
    draft = build_draft(
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
    atomic_write_text(out / DRAFT_MD, render_markdown(draft))
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
    return draft


def _default_actor() -> str:
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001 - some containers have no passwd entry
        return os.environ.get("USER", "unknown")
