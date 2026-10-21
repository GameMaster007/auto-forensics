"""Worker boundary for a later orchestrator.

A worker reads a case store and may call tools only through a
``ToolRegistry``. This module defines that shape. It does not schedule
workers, and it does not run more than the existing pipeline.

``run_case`` is the body of the only worker that exists today. Its
name is ``pipeline``. Findings it commits use that name. Another
worker can later call ``CaseStore.add_findings`` with a different name
without changing the finding or citation types.
"""

from __future__ import annotations

from typing import Protocol

from .case_store import CaseStore
from .tools import ToolRegistry

PIPELINE_WORKER = "pipeline"


class Worker(Protocol):
    """One drafter. An orchestrator would call ``run`` once per worker."""

    name: str

    def run(self, store: CaseStore, tools: ToolRegistry) -> None:
        """Draft into ``store``, calling tools only through ``tools``."""
