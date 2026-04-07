"""Tests for BrowserHistoryArtifactParser and related helpers."""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_chrome_db(tmp_path: Path) -> Path:
    db = tmp_path / "History"
    con = sqlite3.connect(str(db))
    con.execute(
        "CREATE TABLE urls (id INTEGER, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER)"
    )
    # Chrome epoch: 2024-01-01T00:00:00Z => unix 1704067200 => chrome = (1704067200 + 11644473600) * 1e6
    chrome_ts = (1704067200 + 11_644_473_600) * 1_000_000
    con.execute(
        "INSERT INTO urls VALUES (1, 'https://example.com', 'Example', 3, ?)",
        (chrome_ts,),
    )
    con.commit()
    con.close()
    return db


def _make_firefox_db(tmp_path: Path) -> Path:
    db = tmp_path / "places.sqlite"
    con = sqlite3.connect(str(db))
    con.execute(
        "CREATE TABLE moz_places (id INTEGER, url TEXT, title TEXT, visit_count INTEGER, last_visit_date INTEGER)"
    )
    # Firefox: microseconds since Unix epoch for 2024-01-01T00:00:00Z
    ff_ts = 1704067200 * 1_000_000
    con.execute(
        "INSERT INTO moz_places VALUES (1, 'https://firefox.example.com', 'Firefox Example', 5, ?)",
        (ff_ts,),
    )
    con.commit()
    con.close()
    return db


def _make_unknown_db(tmp_path: Path) -> Path:
    db = tmp_path / "unknown.db"
    con = sqlite3.connect(str(db))
    con.execute("CREATE TABLE foo (bar TEXT)")
    con.commit()
    con.close()
    return db


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_chrome_schema_detection(tmp_path):
    from auto_forensics.artifacts import load_browser_history_artifacts

    db = _make_chrome_db(tmp_path)
    events = load_browser_history_artifacts(db)
    assert len(events) >= 1
    ev = events[0]
    assert ev.event_type == "web_visit"
    assert "example.com" in ev.description
    assert ev.metadata.get("browser") == "chrome_edge"
    assert ev.metadata.get("attack_technique_id") == "T1217"


def test_firefox_schema_detection(tmp_path):
    from auto_forensics.artifacts import load_browser_history_artifacts

    db = _make_firefox_db(tmp_path)
    events = load_browser_history_artifacts(db)
    assert len(events) >= 1
    ev = events[0]
    assert ev.event_type == "web_visit"
    assert "firefox.example.com" in ev.description
    assert ev.metadata.get("browser") == "firefox"
    assert ev.metadata.get("attack_technique_id") == "T1217"


def test_unknown_schema_returns_empty(tmp_path):
    from auto_forensics.artifacts import load_browser_history_artifacts

    db = _make_unknown_db(tmp_path)
    events = load_browser_history_artifacts(db)
    assert events == []


def test_parser_opens_read_only(tmp_path):
    """The parser must not modify the source file (mtime unchanged after parse)."""
    import time
    from auto_forensics.artifacts import load_browser_history_artifacts

    db = _make_chrome_db(tmp_path)
    mtime_before = db.stat().st_mtime
    time.sleep(0.05)
    load_browser_history_artifacts(db)
    mtime_after = db.stat().st_mtime
    assert mtime_before == mtime_after


def test_chrome_epoch_to_iso_known_value():
    from auto_forensics.artifacts import _chrome_epoch_to_iso

    # Chrome epoch 13_000_000_000_000_000 µs
    # unix_µs = 13_000_000_000_000_000 - 11_644_473_600_000_000 = 1_355_526_400_000_000
    # unix_s  = 1_355_526_400  =>  2012-12-14T23:06:40Z
    chrome_ts = 13_000_000_000_000_000
    result = _chrome_epoch_to_iso(chrome_ts)
    assert result is not None
    assert result.startswith("2012-12-14")


def test_browser_parser_registered_in_defaults():
    from auto_forensics.plugins import ArtifactParserRegistry

    reg = ArtifactParserRegistry()
    reg.register_defaults()
    parser = reg.parser_for_suffix(".sqlite")
    assert parser is not None
    assert parser.name == "browser-history-artifact-parser"

    parser_by_name = reg.parser_for_name("History")
    assert parser_by_name is not None
    assert parser_by_name.name == "browser-history-artifact-parser"


def test_is_supported_artifact_sqlite():
    from auto_forensics.security import is_supported_artifact

    assert is_supported_artifact(Path("x.sqlite")) is True


def test_is_supported_artifact_db():
    from auto_forensics.security import is_supported_artifact

    assert is_supported_artifact(Path("x.db")) is True
