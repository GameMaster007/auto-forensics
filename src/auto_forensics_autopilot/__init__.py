"""Autopilot plugin for Auto Forensics.

One command takes an evidence directory to a cited draft. The core
``auto_forensics`` pipeline stays the only code that writes the case
report. The autopilot adds:

* triage: profile the evidence and choose which agents run;
* specialist agents that run in parallel and submit cited findings;
* a coordinator that merges findings into a draft without reading
  evidence text;
* a sign-off gate: nothing is exported until an analyst has decided
  every finding and signed the draft.

The core works without this package. Remove it and the core still runs.
"""

from __future__ import annotations

AUTOPILOT_VERSION = "0.1.0"

__all__ = ["AUTOPILOT_VERSION"]
