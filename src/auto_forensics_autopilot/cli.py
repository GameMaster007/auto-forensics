"""Command line for the autopilot plugin.

    auto-forensics-autopilot start  --input-dir EVIDENCE --output-dir RUN --case-id CASE
    auto-forensics-autopilot status --run-dir RUN
    auto-forensics-autopilot decide --run-dir RUN --finding-id ID --decision accept|reject --actor NAME [--note TEXT]
    auto-forensics-autopilot sign   --run-dir RUN --actor NAME
    auto-forensics-autopilot export --run-dir RUN --dest FOLDER
    auto-forensics-autopilot serve  [--workspace FOLDER] [--port 8765]   (point-and-click review page)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from auto_forensics.security import SecurityError

from . import signoff
from .agents import AGENTS
from .orchestrator import DRAFT_MD, start


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="auto-forensics-autopilot",
                                     description="One-click cited triage with a mandatory analyst sign-off.")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("start", help="Run triage, all agents, and the coordinator on an evidence folder.")
    run.add_argument("--input-dir", required=True, type=Path)
    run.add_argument("--output-dir", required=True, type=Path)
    run.add_argument("--case-id", required=True)
    run.add_argument("--actor", default=None, help="Who started the run (recorded in custody.json).")
    run.add_argument("--llm", choices=["off", "mock", "ollama"], default="mock")
    run.add_argument("--llama-endpoint", default="http://localhost:11434")
    run.add_argument("--llama-model", default="llama3.1:8b")
    run.add_argument("--rules-dir", type=Path, default=None, help="Folder of YARA/Sigma rules for the core pipeline.")
    run.add_argument("--agents", nargs="+", choices=sorted(AGENTS), default=None, help="Run only these agents.")

    stat = sub.add_parser("status", help="Show how many findings are decided and whether the draft is signed.")
    stat.add_argument("--run-dir", required=True, type=Path)
    stat.add_argument("--json", action="store_true", help="Also print the full status as JSON.")

    dec = sub.add_parser("decide", help="Accept or reject one finding.")
    dec.add_argument("--run-dir", required=True, type=Path)
    dec.add_argument("--finding-id", required=True, nargs="+",
                     help="One or more finding ids; each is decided and logged separately.")
    dec.add_argument("--decision", required=True, choices=sorted(signoff.DECISIONS))
    dec.add_argument("--actor", required=True)
    dec.add_argument("--note", default="", help="Reason. Required for reject.")
    dec.add_argument("--override", action="store_true", help="Replace an earlier decision. The old line stays.")

    sgn = sub.add_parser("sign", help="Sign the draft once every finding is decided.")
    sgn.add_argument("--run-dir", required=True, type=Path)
    sgn.add_argument("--actor", required=True)
    sgn.add_argument("--fingerprint", required=True,
                     help="The run fingerprint printed by 'start' (at least the first 32 characters).")
    sgn.add_argument("--statement", default="")
    sgn.add_argument("--accept-gaps", action="store_true",
                     help="Sign even though an agent failed; the gap is recorded in the signature and final report.")

    exp = sub.add_parser("export", help="Write the signed final report.")
    exp.add_argument("--run-dir", required=True, type=Path)
    exp.add_argument("--dest", required=True, type=Path)
    exp.add_argument("--signature", required=True,
                     help="The signature fingerprint printed by 'sign' (at least the first 32 characters).")

    srv = sub.add_parser("serve", help="Open the point-and-click review page in your browser.")
    srv.add_argument("--workspace", type=Path, default=Path.home() / "AutoForensicsRuns",
                     help="Where runs and exported reports are kept (default: AutoForensicsRuns in your home folder).")
    srv.add_argument("--port", type=int, default=8765)
    srv.add_argument("--no-browser", action="store_true", help="Print the link instead of opening the browser.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "serve":
        try:
            import fastapi  # noqa: F401
            import uvicorn  # noqa: F401

            from .web import serve
        except ImportError:
            print("The review page needs the server extra: pip install -e \".[server]\"", file=sys.stderr)
            return 2
        serve(args.workspace, port=args.port, open_browser=not args.no_browser)
        return 0
    try:
        if args.command == "start":
            draft = start(input_dir=args.input_dir, output_dir=args.output_dir, case_id=args.case_id,
                          actor=args.actor, llm=args.llm, llama_endpoint=args.llama_endpoint,
                          llama_model=args.llama_model, rules_dir=args.rules_dir, only_agents=args.agents)
            print(draft["headline"])
            if draft["hostile_files"]:
                print(f"Warning: {len(draft['hostile_files'])} file(s) contain text aimed at an AI analyst.")
            for agent in draft["agents"]:
                if agent["status"] != "ok":
                    print(f"Agent {agent['name']}: {agent['status']} {agent['detail']}".rstrip())
            print(f"Draft: {args.output_dir / DRAFT_MD}")
            print(f"Run fingerprint: {draft['run_fingerprint']}")
            print("Write the fingerprint down outside the run folder; you need it to sign.")
            print("Next: decide every finding, then sign.")
        elif args.command == "status":
            state = signoff.status(args.run_dir)
            print(f"Case {state['case_id']}: {state['accepted']} accepted, {state['rejected']} rejected, "
                  f"{len(state['pending'])} pending of {state['total']}."
                  + (f" Signed by {state['signed_by']}." if state["signed"] else ""))
            for item in state["pending_findings"]:
                print(f"  {item['finding_id']}  [{item['severity']}] {item['title']}  ({item['cited_at']})")
            if args.json:
                print(json.dumps(state, indent=2))
        elif args.command == "decide":
            for finding_id in dict.fromkeys(args.finding_id):
                entry = signoff.decide(args.run_dir, finding_id=finding_id, decision=args.decision,
                                       actor=args.actor, note=args.note, override=args.override)
                print(f"{entry['finding_id']}: {entry['decision']} by {entry['actor']}")
        elif args.command == "sign":
            sig = signoff.sign(args.run_dir, actor=args.actor, fingerprint_seen=args.fingerprint,
                               statement=args.statement, accept_gaps=args.accept_gaps)
            print(f"Signed by {sig['actor']} at {sig['signed_at']}: {sig['accepted']} accepted, {sig['rejected']} rejected.")
            print(f"Signature fingerprint: {sig['signature_fingerprint']}")
            print("Write it down outside the run folder; you need it to export.")
        elif args.command == "export":
            final = signoff.export(args.run_dir, args.dest, signature_seen=args.signature)
            print(final["headline"])
            print(f"Report: {args.dest / signoff.FINAL_MD}")
    except SecurityError as exc:
        print(f"Refused: {exc}", file=sys.stderr)
        return 2
    except (ValueError, KeyError, TypeError, OSError) as exc:
        # A corrupt or hand-edited run file: say so instead of printing a traceback.
        print(f"Refused: a run file is missing or malformed ({type(exc).__name__})", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
