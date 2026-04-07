"""Tests for TUI module."""

from __future__ import annotations

import pytest

# Skip all tests if textual is not installed
textual = pytest.importorskip("textual")

from auto_forensics.tui import ForensicsTUIApp


def test_tui_app_imports() -> None:
    """Verify TUI app can be imported."""
    assert ForensicsTUIApp is not None


def test_tui_app_creation() -> None:
    """Verify TUI app can be instantiated."""
    from auto_forensics.config import AppConfig

    config = AppConfig.from_env()
    app = ForensicsTUIApp(config=config)
    assert app is not None


def test_tui_widgets_import() -> None:
    """Verify TUI widgets can be imported."""
    from auto_forensics.tui.widgets import (
        CustomHeader,
        CaseCard,
        ProgressCard,
        FilterBar,
        ConfirmationModal,
        StatsPanel,
    )

    assert CustomHeader is not None
    assert CaseCard is not None
    assert ProgressCard is not None
    assert FilterBar is not None
    assert ConfirmationModal is not None
    assert StatsPanel is not None


def test_tui_screens_import() -> None:
    """Verify TUI screens can be imported."""
    from auto_forensics.tui.screens import (
        DashboardScreen,
        CasesScreen,
        CaseDetailScreen,
        AnalysisScreen,
        SettingsScreen,
    )

    assert DashboardScreen is not None
    assert CasesScreen is not None
    assert CaseDetailScreen is not None
    assert AnalysisScreen is not None
    assert SettingsScreen is not None


def test_case_card_creation() -> None:
    """Test CaseCard widget creation."""
    from auto_forensics.tui.widgets import CaseCard

    card = CaseCard(
        case_id="test-case-001",
        status="ready",
        artifact_count=5,
        finding_count=2,
        ioc_count=3,
    )
    assert card.case_id == "test-case-001"
    assert card.status == "ready"
    assert card.artifact_count == 5


def test_progress_card_creation() -> None:
    """Test ProgressCard widget creation."""
    from auto_forensics.tui.widgets import ProgressCard

    card = ProgressCard(
        job_id="job-001",
        case_id="test-case-001",
        job_type="analysis",
    )
    assert card.job_id == "job-001"
    assert card.case_id == "test-case-001"
    assert card.job_type == "analysis"


def test_confirmation_modal_creation() -> None:
    """Test ConfirmationModal creation."""
    from auto_forensics.tui.widgets import ConfirmationModal

    modal = ConfirmationModal(
        title="Test",
        message="Are you sure?",
    )
    assert modal.title == "Test"
    assert modal.message == "Are you sure?"


def test_stats_panel_creation() -> None:
    """Test StatsPanel widget creation."""
    from auto_forensics.tui.widgets import StatsPanel

    panel = StatsPanel()
    assert panel.total_cases == 0
    assert panel.active_cases == 0

    # Test update
    panel.total_cases = 10
    assert panel.total_cases == 10
