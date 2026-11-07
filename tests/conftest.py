import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


@pytest.fixture
def offline_enrichment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Exercise the enrichment job without contacting a live threat service."""
    monkeypatch.setattr(
        "auto_forensics.ioc_enrichment._request_json",
        lambda *args, **kwargs: {"query_status": "hash_not_found"},
    )
