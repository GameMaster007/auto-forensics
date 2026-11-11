"""Local review page for the autopilot.

    auto-forensics-autopilot serve [--workspace DIR] [--port 8765]

Runs on 127.0.0.1 only. Every API call needs the session token printed when
the server starts (the page reads it from the URL fragment, which browsers
never send to a server or in a Referer). Other websites in the same browser
cannot call the API: there is no CORS, the Host header must be the loopback
address, and requests without the token are refused.

Fingerprints are shown once, from the server's memory, right after a run
finishes or a draft is signed, and never re-read from the run folder: a
fingerprint recomputed from files someone replaced would vouch for the
replacement. The analyst types them back to sign and to export.

Evidence-derived text is returned as JSON and the page sets it with
``textContent`` only; nothing from a case is inserted as HTML.
"""

from __future__ import annotations

import re
import secrets
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
        self.shown: dict[str, dict[str, str]] = {}

    def run_dir(self, run_id: str) -> Path:
        if not RUN_ID.fullmatch(run_id or ""):
            raise SecurityError("Unknown run")
        path = (self.runs / run_id).resolve()
        if path.parent != self.runs or not path.is_dir():
            raise SecurityError("Unknown run")
        return path

    def list_runs(self) -> list[dict[str, Any]]:
        out = []
        for path in sorted(self.runs.iterdir(), reverse=True):
            if not RUN_ID.fullmatch(path.name):
                continue
            job = self.jobs.get(path.name, {})
            entry: dict[str, Any] = {"run_id": path.name, "state": job.get("state", "done")}
            if (path / DRAFT_JSON).is_file() and (path / MANIFEST_FILE).is_file():
                try:
                    state = signoff.status(path)
                    entry.update(case_id=state["case_id"], total=state["total"], pending=len(state["pending"]),
                                 signed=state["signed"], exported=bool(job.get("exported")))
                except (SecurityError, ValueError, KeyError) as exc:
                    entry.update(state="error", error=str(exc)[:200])
            elif job.get("state") == "failed":
                entry["error"] = job.get("error", "")
            elif not job:
                entry["state"] = "incomplete"
            out.append(entry)
        return out

    def start_run(self, input_dir: str, case_id: str, actor: str, llm: str) -> str:
        if not CASE_ID.fullmatch(case_id or ""):
            raise SecurityError("Case ID must be 2-64 letters, numbers, dots, dashes or underscores")
        if llm not in {"off", "mock", "ollama"}:
            raise SecurityError("Model must be off, mock or ollama")
        evidence = Path(input_dir).expanduser()
        if not evidence.is_dir():
            raise SecurityError("The evidence folder does not exist")
        evidence = evidence.resolve()
        if evidence == self.workspace or evidence.is_relative_to(self.workspace) or self.workspace.is_relative_to(evidence):
            raise SecurityError("The evidence folder and the workspace must not contain each other")
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        run_id = f"{case_id}-{stamp}"
        with self.lock:
            if run_id in self.jobs or (self.runs / run_id).exists():
                raise SecurityError("A run for this case started this second; wait a moment and try again")
            self.jobs[run_id] = {"state": "running", "started": time.time()}
        threading.Thread(target=self._run, args=(run_id, evidence, case_id, actor, llm), daemon=True).start()
        return run_id

    def _run(self, run_id: str, evidence: Path, case_id: str, actor: str, llm: str) -> None:
        try:
            draft = start(input_dir=evidence, output_dir=self.runs / run_id, case_id=case_id, actor=actor, llm=llm)
            with self.lock:
                self.jobs[run_id] = {"state": "done"}
                self.shown[run_id] = {"run_fingerprint": draft["run_fingerprint"]}
        except Exception as exc:  # noqa: BLE001 - reported on the page
            with self.lock:
                self.jobs[run_id] = {"state": "failed", "error": f"{type(exc).__name__}: {str(exc)[:300]}"}


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


def _error(status: int, message: str) -> Any:
    from fastapi import HTTPException

    return HTTPException(status_code=status, detail=message)


def create_app(state: ReviewState) -> Any:
    from fastapi import Depends, FastAPI, Header, Request
    from fastapi.responses import FileResponse, JSONResponse

    app = FastAPI(title="Auto Forensics review", docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def guard(request: Request, call_next: Any) -> Any:
        host = (request.headers.get("host") or "").split(":")[0]
        if host not in {"127.0.0.1", "localhost"}:
            return JSONResponse({"detail": "This server only answers on 127.0.0.1"}, status_code=403)
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; "
            "font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    def need_token(x_session_token: str | None = Header(default=None, alias="X-Session-Token")) -> None:
        if not x_session_token or not secrets.compare_digest(x_session_token, state.token):
            raise _error(401, "Open the page from the link printed when the server started")

    def refused(exc: Exception) -> Any:
        return _error(400, str(exc)[:300])

    @app.get("/")
    def page() -> Any:
        return FileResponse(STATIC / "review.html", media_type="text/html")

    @app.get("/static/{name}")
    def asset(name: str) -> Any:
        allowed = {"review.css": "text/css", "review.js": "text/javascript"}
        if name not in allowed:
            raise _error(404, "Not found")
        return FileResponse(STATIC / name, media_type=allowed[name])

    @app.get("/api/runs", dependencies=[Depends(need_token)])
    def runs() -> Any:
        return {"workspace": str(state.workspace), "runs": state.list_runs()}

    @app.post("/api/runs", dependencies=[Depends(need_token)])
    def new_run(body: StartBody) -> Any:
        try:
            return {"run_id": state.start_run(body.input_dir, body.case_id.strip(), body.actor, body.llm)}
        except SecurityError as exc:
            raise refused(exc) from exc

    @app.get("/api/runs/{run_id}", dependencies=[Depends(need_token)])
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
        except (SecurityError, OSError, ValueError, KeyError) as exc:
            raise _error(404, f"Run could not be opened: {str(exc)[:200]}") from exc
        decisions = signoff.latest_decisions(signoff.read_log(path))
        for finding in draft["findings"]:
            choice = decisions.get(finding["finding_id"])
            finding["decision"] = choice["decision"] if choice else "pending"
            finding["decided_by"] = choice["actor"] if choice else ""
            finding["note"] = choice["note"] if choice else ""
        final = None
        exported = state.jobs.get(run_id, {}).get("exported")
        if exported and (Path(exported) / signoff.FINAL_JSON).is_file():
            final = {"folder": exported}
        return {"run_id": run_id, "state": "done", "draft": draft, "status": status,
                "shown_once": state.shown.pop(run_id, None), "final": final}

    @app.post("/api/runs/{run_id}/decide", dependencies=[Depends(need_token)])
    def decide(run_id: str, body: DecideBody) -> Any:
        done = []
        try:
            path = state.run_dir(run_id)
            for finding_id in dict.fromkeys(body.finding_ids):
                done.append(signoff.decide(path, finding_id=finding_id, decision=body.decision, actor=body.actor,
                                           note=body.note, override=body.override)["finding_id"])
        except SecurityError as exc:
            raise _error(400, f"{len(done)} decided before this was refused: {exc}") from exc
        return {"decided": done}

    @app.post("/api/runs/{run_id}/sign", dependencies=[Depends(need_token)])
    def sign(run_id: str, body: SignBody) -> Any:
        try:
            signature = signoff.sign(state.run_dir(run_id), actor=body.actor, fingerprint_seen=body.fingerprint,
                                     statement=body.statement, accept_gaps=body.accept_gaps)
        except SecurityError as exc:
            raise refused(exc) from exc
        return {"signed_at": signature["signed_at"], "signature_fingerprint": signature["signature_fingerprint"],
                "sealed": bool(signature.get("seal"))}

    @app.post("/api/runs/{run_id}/export", dependencies=[Depends(need_token)])
    def export(run_id: str, body: ExportBody) -> Any:
        try:
            path = state.run_dir(run_id)
            dest = state.exports / f"{run_id}-{datetime.now(timezone.utc).strftime('%H%M%S')}"
            final = signoff.export(path, dest, signature_seen=body.signature)
        except SecurityError as exc:
            raise refused(exc) from exc
        with state.lock:
            state.jobs.setdefault(run_id, {"state": "done"})["exported"] = str(dest)
        return {"folder": str(dest), "headline": final["headline"], "status": final["status"]}

    @app.get("/api/runs/{run_id}/final", dependencies=[Depends(need_token)])
    def final(run_id: str) -> Any:
        exported = state.jobs.get(run_id, {}).get("exported")
        if not exported:
            raise _error(404, "This run has not been exported in this session")
        return read_json(Path(exported) / signoff.FINAL_JSON)

    return app


def serve(workspace: Path, port: int = 8765, open_browser: bool = True) -> None:
    import uvicorn

    state = ReviewState(workspace)
    url = f"http://127.0.0.1:{port}/#token={state.token}"
    print("Auto Forensics review page")
    print(f"  Workspace: {state.workspace}")
    print(f"  Open:      {url}")
    print("  Keep this window open while you work. Press Ctrl+C to stop.")
    if open_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    uvicorn.run(create_app(state), host="127.0.0.1", port=port, log_level="warning")
