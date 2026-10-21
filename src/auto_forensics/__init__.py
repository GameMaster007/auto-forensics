"""Cited triage drafts for digital-forensics learners.

Findings are drafts. A finding is written into a report only when it
cites an ingested artifact, and an analyst is expected to verify it.
"""

from .pipeline import run_case
from .service import AutoForensicsService
from .version import __version__

__all__ = ["AutoForensicsService", "__version__", "run_case"]
