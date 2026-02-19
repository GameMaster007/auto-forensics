from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest

from auto_forensics.db_sqlalchemy import SQLAlchemyDatabase


def test_postgres_backend_optional_smoke():
    url = os.getenv("AUTO_FORENSICS_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("AUTO_FORENSICS_TEST_POSTGRES_URL not set")

    db = SQLAlchemyDatabase(url)
    case_id = f"pg-{uuid.uuid4().hex[:10]}"
    cwd = Path(os.getcwd())
    db.create_case(case_id, evidence_dir=cwd, output_dir=cwd)
    case = db.get_case(case_id)

    assert case is not None
    assert case["case_id"] == case_id
