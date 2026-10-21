"""Allow-listed tools a worker is permitted to call.

A worker does not import arbitrary helpers and hope they are safe to
run. It names a tool, and the registry runs it only if that name was
allow-listed for this run. Every attempt, including a denied name, is
appended to the case store so the run manifest can show it.

The record stores the tool name, the worker, and a status. It does not
store evidence text, prompts, or API keys. ``PluginRegistry`` is a
different mechanism: it loads parsers and detectors. This registry is
the gate for worker actions.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Callable, Protocol

from .security import SecurityError


@dataclass(slots=True)
class ToolCall:
    """One attempt to use an allow-listed tool."""

    worker: str
    tool: str
    status: str
    detail: str = ""

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


class ToolLog(Protocol):
    """The part of a case store that records tool calls."""

    def log_tool_call(self, call: ToolCall) -> None:
        """Append one tool call."""


class ToolRegistry:
    """Run named callables and log each attempt."""

    def __init__(self, worker: str, store: ToolLog | None = None):
        self.worker = worker
        self.store = store
        self._allowed: dict[str, Callable[..., Any]] = {}
        self.calls: list[ToolCall] = []

    def allow(self, name: str, fn: Callable[..., Any]) -> None:
        """Permit ``name`` to call ``fn``. A second registration replaces the first."""
        self._allowed[name] = fn

    def call(self, name: str, *args: Any, **kwargs: Any) -> Any:
        """Run an allow-listed tool. Denied and failed attempts are logged first."""
        if name not in self._allowed:
            self._record(name, "denied", "not allow-listed")
            raise SecurityError(f"Tool is not allow-listed: {name}")
        try:
            result = self._allowed[name](*args, **kwargs)
        except Exception as exc:
            self._record(name, "error", type(exc).__name__)
            raise
        self._record(name, "ok", "")
        return result

    def _record(self, tool: str, status: str, detail: str) -> None:
        call = ToolCall(worker=self.worker, tool=tool, status=status, detail=detail)
        self.calls.append(call)
        if self.store is not None:
            self.store.log_tool_call(call)
