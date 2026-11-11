"""Local review page for the autopilot.

    auto-forensics-autopilot serve [--workspace DIR] [--port 8765]

Runs on 127.0.0.1 only. Every API call needs the session token printed when
the server starts (the page reads it from the URL fragment, which browsers
never send to a server or in a Referer). Other websites in the same browser
cannot call the API: there is no CORS, the Host header must be the loopback
address, and requests without the token are refused.

Fingerprints come only from the server's memory, captured when a run finishes
or a draft is signed, and are never re-read from the run folder: a fingerprint
recomputed from files someone replaced would vouch for the replacement. The
page keeps offering them until the analyst confirms they copied them, and the
server window prints them too. The analyst types them back to sign and export.

Evidence-derived text is returned as JSON and the page sets it with
``textContent`` only; nothing from a case is inserted as HTML.
"""

from __future__ import annotations

import re
import secrets
import socket
import sys
import threading
import time
import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from auto_forensics.security import SecurityError

from . import signoff
from .orchestrator import DRAFT_JSON, MANIFEST_FILE, read_json, start

STATIC = Path(__file__).with_name("static")
RUN_ID = re.compile(r"^[A-Za-z0-9._-]{2,64}-\d{8}T\d{6}Z$")
CASE_ID = re.compile(r"^[A-Za-z0-9._-]{2,64}$")
MAX_BODY = 1024 * 1024
MAX_RUNNING = 2


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _say(message: str) -> None:
    print(message, flush=True)


class ReviewState:
    """Runs in one workspace, plus fingerprints held in memory for this session."""

    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace.expanduser().resolve()
        self.runs = self.workspace / "runs"
        self.exports = self.workspace / "exports"
        self.runs.mkdir(parents=True, exist_ok=True)
        self.exports.mkdir(parents=True, exist_ok=True)
        self.token = secrets.token_urlsafe(32)
        self.lock = threading.Lock()
        self.jobs: dict[str, dict[str, Any]] = {}
        # Fingerprints still waiting for the analyst to confirm they copied them.
        self.shown: dict[str, dict[str, str]] = {}

    def run_dir(self, run_id: str) -> Path:
        if not RUN_ID.fullmatch(run_id or ""):
            raise SecurityError("Unknown run")
        path = (self.runs / run_id).resolve()
        if path.parent != self.runs or not path.is_dir():
            raise SecurityError("Unknown run")
        return path

    def exported_to(self, run_id: str) -> Path | None:
        """Latest export folder of this run that holds a final report, or None."""
        found = sorted(p.parent for p in self.exports.glob(f"{run_id}-export-*/{signoff.FINAL_JSON}"))
        return found[-1] if found else None

    def list_runs(self) -> list[dict[str, Any]]:
        out = []
        for path in sorted(self.runs.iterdir(), reverse=True):
            if not RUN_ID.fullmatch(path.name) or not path.is_dir():
                continue
            job = self.jobs.get(path.name, {})
            entry: dict[str, Any] = {"run_id": path.name, "state": job.get("state", "done")}
            if job.get("state") in {"running", "failed"}:
                entry["error"] = job.get("error", "")
            elif (path / DRAFT_JSON).is_file() and (path / MANIFEST_FILE).is_file():
                try:
                    state = signoff.status(path)
                    entry.update(case_id=state["case_id"], total=state["total"], pending=len(state["pending"]),
                                 signed=state["signed"], exported=self.exported_to(path.name) is not None)
                except Exception as exc:  # noqa: BLE001 - one bad run must not hide the others
                    entry.update(state="error", error=f"run files could not be read ({type(exc).__name__})")
            else:
                entry["state"] = "incomplete"
            out.append(entry)
        return out

    def start_run(self, input_dir: str, case_id: str, actor: str, llm: str) -> str:
        if not CASE_ID.fullmatch(case_id or ""):
            raise SecurityError("Case ID must be 2-64 letters, numbers, dots, dashes or underscores")
        if llm not in {"off", "mock", "ollama"}:
            raise SecurityError("Model must be off, mock or ollama")
        # Explorer's "Copy as path" wraps the path in quotes.
        evidence = Path(input_dir.strip().strip('"').strip("'").strip()).expanduser()
        if not evidence.is_dir():
            raise SecurityError("The evidence folder does not exist")
        evidence = evidence.resolve()
        if evidence == self.workspace or evidence.is_relative_to(self.workspace) or self.workspace.is_relative_to(evidence):
            raise SecurityError("The evidence folder and the workspace must not contain each other")
        run_id = f"{case_id}-{_stamp()}"
        with self.lock:
            if sum(1 for j in self.jobs.values() if j.get("state") == "running") >= MAX_RUNNING:
                raise SecurityError(f"{MAX_RUNNING} runs are already going; wait for one to finish")
            if any(j.get("state") == "running" and j.get("case_id") == case_id for j in self.jobs.values()):
                raise SecurityError("This case is already running")
            if run_id in self.jobs or (self.runs / run_id).exists():
                raise SecurityError("A run for this case started this second; wait a moment and try again")
            self.jobs[run_id] = {"state": "running", "case_id": case_id, "started": time.time()}
        threading.Thread(target=self._run, args=(run_id, evidence, case_id, actor, llm), daemon=True).start()
        return run_id

    def _run(self, run_id: str, evidence: Path, case_id: str, actor: str, llm: str) -> None:
        try:
            draft = start(input_dir=evidence, output_dir=self.runs / run_id, case_id=case_id, actor=actor, llm=llm)
        except Exception as exc:  # noqa: BLE001 - reported on the page
            # Library messages can quote evidence; the page gets the type, this window the detail.
            _say(f"Run {run_id} failed: {type(exc).__name__}: {exc}")
            with self.lock:
                self.jobs[run_id] = {"state": "failed", "error": f"{type(exc).__name__} (details in the server window)"}
            return
        with self.lock:
            self.jobs[run_id] = {"state": "done"}
            self.shown[run_id] = {"run_fingerprint": draft["run_fingerprint"]}
        _say(f"Run {run_id} finished. Run fingerprint: {draft['run_fingerprint']}")

    def confirm_copied(self, run_id: str, kind: str) -> None:
        with self.lock:
            held = self.shown.get(run_id, {})
            held.pop(kind, None)
            if not held:
                self.shown.pop(run_id, None)

    def decide(self, run_id: str, ids: list[str], decision: str, actor: str, note: str, override: bool) -> list[str]:
        """Check every id first so a batch is not half-written for a foreseeable reason."""
        path = self.run_dir(run_id)
        draft = read_json(path / DRAFT_JSON)
        known = {f["finding_id"] for f in draft["findings"]}
        decided = signoff.latest_decisions(signoff.read_log(path))
        ids = list(dict.fromkeys(ids))
        if not ids:
            raise SecurityError("Select at least one finding")
        unknown = [i for i in ids if i not in known]
        if unknown:
            raise SecurityError(f"{len(unknown)} selected finding(s) are not in this draft")
        if not override:
            already = [i for i in ids if i in decided]
            if already:
                raise SecurityError(f"{len(already)} selected finding(s) already have a decision; "
                                    "tick 'Change an earlier decision' to replace them")
        done: list[str] = []
        try:
            for finding_id in ids:
                done.append(signoff.decide(path, finding_id=finding_id, decision=decision, actor=actor,
                                           note=note, override=override)["finding_id"])
        except SecurityError as exc:
            raise SecurityError(f"{len(done)} of {len(ids)} decided before this was refused: {exc}") from exc
        except Exception as exc:  # noqa: BLE001
            _say(f"Decide on {run_id} failed: {type(exc).__name__}: {exc}")
            raise SecurityError(f"{len(done)} of {len(ids)} decided before an error ({type(exc).__name__})") from exc
        return done


class StartBody(BaseModel):
    input_dir: str = Field(max_length=4096)
    case_id: str = Field(max_length=64)
    actor: str = Field(max_length=120)
    llm: str = "mock"


class DecideBody(BaseModel):
    finding_ids: list[str] = Field(max_length=5000)
    decision: str
    actor: str = Field(max_length=120)
    note: str = Field(default="", max_length=2000)
    override: bool = False


class SignBody(BaseModel):
    actor: str = Field(max_length=120)
    fingerprint: str = Field(max_length=128)
    statement: str = Field(default="", max_length=2000)
    accept_gaps: bool = False


class ExportBody(BaseModel):
    signature: str = Field(max_length=128)


class CopiedBody(BaseModel):
    kind: str


def _error(status: int, message: str) -> Any:
    from fastapi import HTTPException

    return HTTPException(status_code=status, detail=message)


def create_app(state: ReviewState) -> Any:
    from fastapi import FastAPI, Request
    from fastapi.responses import FileResponse, JSONResponse

    app = FastAPI(title="Auto Forensics review", docs_url=None, redoc_url=None, openapi_url=None)
    token = state.token.encode("ascii")

    def refuse(status: int, message: str) -> Any:
        return JSONResponse({"detail": message}, status_code=status)

    @app.middleware("http")
    async def guard(request: Request, call_next: Any) -> Any:
        host = (request.headers.get("host") or "").split(":")[0]
        if host not in {"127.0.0.1", "localhost"}:
            return refuse(403, "This server only answers on 127.0.0.1")
        if request.url.path.startswith("/api/"):
            # Checked before the body is read, so no other page can make the server buffer anything.
            given = (request.headers.get("x-session-token") or "").encode("utf-8", "replace")
            if not secrets.compare_digest(given, token):
                return refuse(401, "Open the page from the link printed when the server started")
            if request.method == "POST":
                if (request.headers.get("content-type") or "").split(";")[0].strip() != "application/json":
                    return refuse(415, "Send JSON")
                length = request.headers.get("content-length")
                if length is None or not length.isdigit():
                    return refuse(411, "Content-Length is required")
                if int(length) > MAX_BODY:
                    return refuse(413, "Request too large")
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; "
            "font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/")
    def page() -> Any:
        return FileResponse(STATIC / "review.html", media_type="text/html")

    @app.get("/static/{name}")
    def asset(name: str) -> Any:
        allowed = {"review.css": "text/css", "review.js": "text/javascript"}
        if name not in allowed:
            raise _error(404, "Not found")
        return FileResponse(STATIC / name, media_type=allowed[name])

    @app.get("/api/runs")
    def runs() -> Any:
        return {"workspace": str(state.workspace), "runs": state.list_runs()}

    @app.post("/api/runs")
    def new_run(body: StartBody) -> Any:
        try:
            return {"run_id": state.start_run(body.input_dir, body.case_id.strip(), body.actor, body.llm)}
        except SecurityError as exc:
            raise _error(400, str(exc)[:300]) from exc

    @app.get("/api/runs/{run_id}")
    def run(run_id: str) -> Any:
        job = state.jobs.get(run_id, {})
        if job.get("state") == "running":
            return {"run_id": run_id, "state": "running"}
        if job.get("state") == "failed":
            return {"run_id": run_id, "state": "failed", "error": job.get("error", "")}
        try:
            path = state.run_dir(run_id)
            draft = read_json(path / DRAFT_JSON)
            status = signoff.status(path)
            decisions = signoff.latest_decisions(signoff.read_log(path))
            for finding in draft["findings"]:
                choice = decisions.get(finding["finding_id"]) or {}
                finding["decision"] = choice.get("decision") if choice.get("decision") in signoff.DECISIONS else "pending"
                finding["decided_by"] = str(choice.get("actor", ""))
                finding["note"] = str(choice.get("note", ""))
        except SecurityError as exc:
            raise _error(404, f"Run could not be opened: {str(exc)[:200]}") from exc
        except Exception as exc:  # noqa: BLE001
            raise _error(404, f"Run could not be opened: a run file is missing or malformed ({type(exc).__name__})") from exc
        exported = state.exported_to(run_id)
        with state.lock:
            held = dict(state.shown.get(run_id, {}))
        return {"run_id": run_id, "state": "done", "draft": draft, "status": status, "fingerprints": held,
                "final": {"folder": str(exported)} if exported else None}

    @app.post("/api/runs/{run_id}/copied")
    def copied(run_id: str, body: CopiedBody) -> Any:
        if body.kind not in {"run_fingerprint", "signature_fingerprint"}:
            raise _error(400, "Unknown fingerprint")
        state.confirm_copied(run_id, body.kind)
        return {"ok": True}

    @app.post("/api/runs/{run_id}/decide")
    def decide(run_id: str, body: DecideBody) -> Any:
        try:
            done = state.decide(run_id, body.finding_ids, body.decision, body.actor, body.note, body.override)
        except SecurityError as exc:
            raise _error(400, str(exc)[:400]) from exc
        except Exception as exc:  # noqa: BLE001
            raise _error(400, f"Run files could not be read ({type(exc).__name__})") from exc
        return {"decided": done}

    @app.post("/api/runs/{run_id}/sign")
    def sign(run_id: str, body: SignBody) -> Any:
        try:
            signature = signoff.sign(state.run_dir(run_id), actor=body.actor, fingerprint_seen=body.fingerprint,
                                     statement=body.statement, accept_gaps=body.accept_gaps)
        except SecurityError as exc:
            raise _error(400, str(exc)[:300]) from exc
        fp = signature["signature_fingerprint"]
        with state.lock:
            state.shown[run_id] = {"signature_fingerprint": fp}
        _say(f"Run {run_id} signed by {signature['actor']}. Signature fingerprint: {fp}")
        return {"signed_at": signature["signed_at"], "signature_fingerprint": fp, "sealed": bool(signature.get("seal"))}

    @app.post("/api/runs/{run_id}/export")
    def export(run_id: str, body: ExportBody) -> Any:
        try:
            path = state.run_dir(run_id)
            dest = state.exports / f"{run_id}-export-{_stamp()}"
            final = signoff.export(path, dest, signature_seen=body.signature)
        except SecurityError as exc:
            raise _error(400, str(exc)[:300]) from exc
        state.confirm_copied(run_id, "signature_fingerprint")
        _say(f"Run {run_id} exported to {dest}")
        return {"folder": str(dest), "headline": final["headline"], "status": final["status"]}

    return app


def serve(workspace: Path, port: int = 8765, open_browser: bool = True) -> int:
    import uvicorn

    # Bind first: if the port is taken, nothing is printed or opened that another program could read.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if sys.platform == "win32":
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    else:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("127.0.0.1", port))
    except OSError:
        sock.close()
        print(f"Port {port} is already in use. Close the other Auto Forensics window, or start with --port 8766.",
              file=sys.stderr)
        return 2
    sock.listen(64)
    state = ReviewState(workspace)
    url = f"http://127.0.0.1:{port}/#token={state.token}"
    print("Auto Forensics review page")
    print(f"  Workspace: {state.workspace}")
    print(f"  Open:      {url}")
    print("  Keep this window open while you work. Press Ctrl+C to stop.")
    print("  Fingerprints are printed here as well; keep them with your case notes.", flush=True)
    if open_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    server = uvicorn.Server(uvicorn.Config(create_app(state), log_level="warning"))
    server.run(sockets=[sock])
    return 0
