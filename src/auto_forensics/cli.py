from __future__ import annotations

import argparse
import json
from pathlib import Path

from .api import main as api_main
from .config import AppConfig
from .pipeline import PipelineConfig, run_case
from .replay import replay_manifest
from .security import SecurityError
from .service import AutoForensicsService


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="auto-forensics",
        description="Draft cited forensic findings for an analyst to verify.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    init_case = sub.add_parser("init", help="Create or return a case workspace.")
    init_case.add_argument("--case-id", required=True, help="Unique case identifier.")

    list_cases = sub.add_parser("list", help="List known cases.")
    list_cases.add_argument("--json", action="store_true", help="Emit JSON output.")

    ingest = sub.add_parser("ingest", help="Ingest evidence directory into a case.")
    ingest.add_argument("--case-id", required=True, help="Case identifier.")
    ingest.add_argument("--source-dir", required=True, type=Path, help="Evidence source directory.")

    analyze = sub.add_parser("analyze", help="Run analysis for an initialized case.")
    analyze.add_argument("--case-id", required=True, help="Case identifier.")
    analyze.add_argument(
        "--disable-llama",
        action="store_true",
        help="Disable model workflow and rely on heuristic findings.",
    )
    _add_llm_argument(analyze)

    overview = sub.add_parser("overview", help="Show complete case overview from the database.")
    overview.add_argument("--case-id", required=True, help="Case identifier.")

    report = sub.add_parser("report", help="Print generated case report.")
    report.add_argument("--case-id", required=True, help="Case identifier.")
    report.add_argument("--format", choices=["json", "md", "html", "navigator", "stix"], default="json")

    serve = sub.add_parser("serve", help="Start API and dashboard server.")
    serve.add_argument("--host", default=None, help="Bind host, default from environment.")
    serve.add_argument("--port", default=None, type=int, help="Bind port, default from environment.")

    run = sub.add_parser("run", help="Run a full forensic analysis case.")
    run.add_argument("--case-id", required=True, help="Unique case identifier.")
    run.add_argument("--input-dir", required=True, type=Path, help="Input directory with artifacts.")
    run.add_argument("--output-dir", required=True, type=Path, help="Output directory for report files.")
    run.add_argument(
        "--llama-endpoint",
        default="http://localhost:11434",
        help="Ollama-compatible endpoint base URL.",
    )
    run.add_argument(
        "--llama-model",
        default="llama3.1:8b",
        help="Llama model name available in your endpoint.",
    )
    run.add_argument(
        "--disable-llama",
        action="store_true",
        help="Disable model workflow and rely on heuristic findings.",
    )
    _add_llm_argument(run)

    replay = sub.add_parser("replay", help="Re-run a manifest and compare input and report hashes.")
    replay.add_argument("manifest", type=Path, help="Path to run_manifest.json.")
    replay.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Directory for the replayed report. Defaults to a replay directory beside the manifest.",
    )

    export_case = sub.add_parser("export", help="Export case as signed zip archive.")
    export_case.add_argument("--case-id", required=True, help="Case identifier.")
    export_case.add_argument("--dest", required=True, type=Path, help="Destination zip file path.")

    import_case = sub.add_parser("import", help="Import case from signed zip archive.")
    import_case.add_argument("--archive", required=True, type=Path, help="Archive zip path.")
    import_case.add_argument("--case-id", default=None, help="Optional case ID override.")

    migrate = sub.add_parser("migrate", help="Run or inspect database migrations.")
    migrate.add_argument("--status", action="store_true", help="Show migration status without applying.")

    enrich = sub.add_parser("enrich", help="Run or inspect asynchronous IOC enrichment jobs.")
    enrich.add_argument("--case-id", required=True, help="Case identifier.")
    enrich.add_argument("--status", action="store_true", help="Show enrichment job status only.")

    jobs = sub.add_parser("jobs", help="List case analysis/enrichment jobs.")
    jobs.add_argument("--case-id", required=True, help="Case identifier.")
    jobs.add_argument("--type", choices=["analysis", "enrichment"], default=None, help="Optional job type filter.")
    jobs.add_argument("--limit", type=int, default=100, help="Maximum number of jobs to return.")

    cleanup_jobs = sub.add_parser("cleanup-jobs", help="Delete job history older than retention days.")
    cleanup_jobs.add_argument("--retention-days", type=int, default=None, help="Override configured retention window.")
    return parser


def _add_llm_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--llm",
        choices=["mock", "ollama", "off"],
        default=None,
        help="mock is offline and needs no API key. ollama calls a local endpoint. off uses heuristics only.",
    )


def _llm_choice(args: argparse.Namespace) -> tuple[bool, str | None]:
    """Return ``(enable_llama, provider)`` for analyze and run."""
    if args.disable_llama or args.llm == "off":
        return False, "off"
    if args.llm in {"mock", "ollama"}:
        return True, args.llm
    return True, None


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    config = AppConfig.from_env()
    service: AutoForensicsService | None = None

    def ensure_service() -> AutoForensicsService:
        nonlocal service
        if service is None:
            service = AutoForensicsService(config)
        return service

    try:
        if args.command == "init":
            print(json.dumps(ensure_service().create_case(args.case_id), indent=2))
            return

        if args.command == "list":
            cases = ensure_service().list_cases()
            if args.json:
                print(json.dumps(cases, indent=2))
            else:
                for c in cases:
                    print(f"{c['case_id']}\t{c['status']}\t{c['updated_at']}")
            return

        if args.command == "ingest":
            print(json.dumps(ensure_service().ingest_case(args.case_id, args.source_dir), indent=2))
            return

        if args.command == "analyze":
            enabled, provider = _llm_choice(args)
            result = ensure_service().analyze_case(
                args.case_id,
                enable_llama=enabled,
                llm_provider=provider,
            )
            print(json.dumps(result, indent=2))
            return

        if args.command == "overview":
            print(json.dumps(ensure_service().case_overview(args.case_id), indent=2))
            return

        if args.command == "report":
            print(ensure_service().get_report(args.case_id, fmt=args.format))
            return

        if args.command == "serve":
            if args.host:
                config.host = args.host
            if args.port:
                config.port = args.port
            api_main(config)
            return

        if args.command == "export":
            result = ensure_service().export_case_archive(args.case_id, args.dest)
            print(json.dumps(result, indent=2))
            return

        if args.command == "import":
            result = ensure_service().import_case_archive(args.archive, case_id_override=args.case_id)
            print(json.dumps(result, indent=2))
            return

        if args.command == "migrate":
            if args.status:
                print(json.dumps(ensure_service().db_migration_status(), indent=2))
            else:
                print(json.dumps(ensure_service().run_db_migrations(), indent=2))
            return

        if args.command == "enrich":
            if args.status:
                print(json.dumps(ensure_service().get_case_enrichment_status(args.case_id), indent=2))
            else:
                print(json.dumps(ensure_service().enrich_case_iocs_async(args.case_id), indent=2))
            return

        if args.command == "jobs":
            print(
                json.dumps(
                    ensure_service().case_job_history(args.case_id, job_type=args.type, limit=args.limit),
                    indent=2,
                )
            )
            return

        if args.command == "cleanup-jobs":
            print(json.dumps(ensure_service().cleanup_job_history(retention_days=args.retention_days), indent=2))
            return

        if args.command == "run":
            enabled, provider = _llm_choice(args)
            cfg = PipelineConfig(
                case_id=args.case_id,
                input_dir=args.input_dir,
                output_dir=args.output_dir,
                enable_llama=enabled,
                llama_endpoint=args.llama_endpoint,
                llama_model=args.llama_model,
                rules_dir=config.rules_dir,
                sigma_rules_dir=config.sigma_rules_dir,
                attack_stix_path=config.attack_stix_path,
                openai_compatible_endpoint=config.openai_compatible_endpoint,
                openai_api_key=config.openai_api_key,
                llm_provider=provider,
            )
            report_obj = run_case(cfg)
            print(json.dumps(report_obj.to_dict(), indent=2))
            return

        if args.command == "replay":
            result = replay_manifest(args.manifest, output_dir=args.output_dir)
            print(json.dumps(result, indent=2))
            if not result["match"]:
                raise SystemExit(1)
            return
    except SecurityError as exc:
        raise SystemExit(f"Security validation failed: {exc}") from exc

    raise SystemExit(f"Unknown command: {args.command}")


if __name__ == "__main__":
    main()
