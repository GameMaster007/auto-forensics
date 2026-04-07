"""TUI screens for Auto Forensics."""

from __future__ import annotations

from .dashboard import DashboardScreen
from .cases import CasesScreen
from .case_detail import CaseDetailScreen
from .analysis import AnalysisScreen
from .settings import SettingsScreen

__all__ = [
    "DashboardScreen",
    "CasesScreen",
    "CaseDetailScreen",
    "AnalysisScreen",
    "SettingsScreen",
]
