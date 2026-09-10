# The first-party beacon is @camada/browser's auto build, vendored as a string so the package
# has no runtime file reads. It must be byte-for-byte the sibling's dist/auto.global.js; the
# test fails by name (never skips) when that checkout or its build is missing.
from __future__ import annotations

import hashlib
import os
from pathlib import Path

from camada.beacon_js import BEACON_JS, BEACON_SHA256, BEACON_VERSION

DIST = Path(os.environ.get("CAMADA_BROWSER_DIST") or Path(__file__).resolve().parents[2] / "camada-browser" / "dist" / "auto.global.js")


def test_vendored_beacon_matches_the_sibling_build() -> None:
    assert DIST.exists(), f"beacon build missing: {DIST} (run npm run build in camada-browser, or set CAMADA_BROWSER_DIST)"
    src = DIST.read_text()
    assert BEACON_JS == src, "run scripts/sync_beacon.py to re-vendor @camada/browser"
    assert BEACON_SHA256 == hashlib.sha256(src.encode()).hexdigest()


def test_beacon_names_its_own_version_and_posts_to_fp() -> None:
    assert f'"{BEACON_VERSION}"' in BEACON_JS
    assert "@camada/browser" in BEACON_JS
    assert '"fp"' in BEACON_JS   # derives the POST target from the script URL's final segment
