"""In-run case store shared by workers.

This is not the SQLite database. ``DatabaseBackend`` remains the
durable case record used by the service. ``CaseStore`` is the object a
worker writes into while a run is in progress: findings and the tool
log. ``MemoryCaseStore`` holds that state for the single ``pipeline``
worker that runs today.

A later change can back the same methods with ``DatabaseBackend``.
That adapter is not written here, because ``run_case`` does not open
the database and the service saves the finished report afterwards.
"""

from __future__ import annotations

from typing import Protocol

from .models import Finding
from .tools import ToolCall


class CaseStore(Protocol):
    """What a worker needs from the case it is drafting into."""

    def add_findings(self, worker: str, findings: list[Finding]) -> None:
        """Record findings as submitted by ``worker``.

        The store sets ``Finding.worker``. A model response cannot
        choose that name.
        """

    def findings(self) -> list[Finding]:
        """Return findings in the order they were added."""

    def log_tool_call(self, call: ToolCall) -> None:
        """Append one tool-call record."""

    def tool_calls(self) -> list[ToolCall]:
        """Return tool calls in order."""

    def workers(self) -> list[str]:
        """Return worker names in the order they first wrote to the store."""


class MemoryCaseStore:
    """Process-local case store for one run."""

    def __init__(self) -> None:
        self._findings: list[Finding] = []
        self._calls: list[ToolCall] = []
        self._workers: list[str] = []

    def add_findings(self, worker: str, findings: list[Finding]) -> None:
        self._remember(worker)
        for finding in findings:
            finding.worker = worker
            self._findings.append(finding)

    def findings(self) -> list[Finding]:
        return list(self._findings)

    def log_tool_call(self, call: ToolCall) -> None:
        self._remember(call.worker)
        self._calls.append(call)

    def tool_calls(self) -> list[ToolCall]:
        return list(self._calls)

    def workers(self) -> list[str]:
        return list(self._workers)

    def _remember(self, worker: str) -> None:
        if worker not in self._workers:
            self._workers.append(worker)
