# Product Guidelines

## Core Principles
1. **Security First:** Maintain strict access controls, path validation, and constant-time secrets handling. Ensure all inputs are strictly validated.
2. **Speed and Efficiency:** Fast background ingestion and processing are crucial for high-priority incidents.
3. **Extensibility:** Utilize the flexible plugin architecture to support diverse forensic artifacts seamlessly.
4. **Reliability:** Graceful handling of missing model endpoints or partial evidence parsing without blocking the primary workflow.

## User Experience (UX)
1. **CLI Experience:** Commands should be intuitive and composable. Use standard flags (`--json`, `--case-id`) to align with ecosystem norms. Provide clear progress output for long-running ingestion.
2. **Dashboard UI:** Clean, minimalist browser-based interface focused on critical path actions (triage, analyze, enrich). Prioritize readable status bars and filtering for large timelines.

## Prose & Documentation Style
- Professional, objective, and precise language.
- Clear step-by-step instructions for setup and plugin development.
- Documentation must always reflect the current API endpoint definitions and capability lists.