# The SDK's wire identity (SDK-03): x-camada-sdk: @camada/python/<version>. One literal in
# version.py is the single source the build reads and every sibling drift guard parses.
import re
from importlib.metadata import version

# edge-analyst src/freshness.js SDK_RE: anything else is silently dropped from sdk_versions.
ANALYST_SDK_RE = re.compile(r"^@?[a-z0-9._-]+(/[a-z0-9._-]+)?/\d+\.\d+\.\d+[a-z0-9.-]*$", re.I)


def test_installed_metadata_matches_the_literal() -> None:
    from camada.version import __version__

    assert version("camada") == __version__


def test_sdk_id_is_the_family_wire_identity() -> None:
    from camada.version import SDK_ID, __version__

    assert SDK_ID == f"@camada/python/{__version__}"
    assert ANALYST_SDK_RE.match(SDK_ID)
    assert len(SDK_ID) <= 64
