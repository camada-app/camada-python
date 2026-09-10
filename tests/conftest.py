# Shared fixtures. The golden snapshot containers live in the camada-core sibling checkout
# (copied verbatim from edge-analyst, the format owner); the suite fails by name when they
# are missing rather than skipping, the same stance the web/mkt drift guards take.
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

FIXTURES = Path(os.environ.get("CAMADA_FIXTURES_DIR") or Path(__file__).resolve().parents[2] / "camada-core" / "test" / "fixtures")


def fixture_path(rel: str) -> Path:
    p = FIXTURES / rel
    if not p.exists():
        raise AssertionError(f"golden fixture missing: {p} (no camada-core checkout? set CAMADA_FIXTURES_DIR)")
    return p


def read_bin(rel: str) -> bytes:
    return fixture_path(rel).read_bytes()


def read_json(rel: str) -> Any:
    return json.loads(fixture_path(rel).read_text())


@pytest.fixture(scope="session")
def fixtures() -> Path:
    return fixture_path(".")
