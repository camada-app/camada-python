# C6 sdk-conformance v3: the language-neutral cases every server SDK runs (camada-core test/fixtures/ip/resolve.json,
# redact/referer.json and redact/query.json), so the XFF-port (0vho), peer-first cidrs (yfc6) and Referer/query-scrub
# (ijsa) semantics cannot drift from core. A missing fixture fails by name at collection; no case is skipped.
from __future__ import annotations

import json
from typing import Any

import pytest

from camada.events.build import RequestInfo, build_wire_event
from camada.ip import resolve_client_ip

from .conftest import read_json

IP = read_json("ip/resolve.json")
REFERER = read_json("redact/referer.json")
QUERY = read_json("redact/query.json")


def test_fixtures_are_v3_and_not_empty() -> None:
    assert IP["version"] == 3 and REFERER["version"] == 3 and QUERY["version"] == 3
    assert IP["cases"] and REFERER["cases"] and QUERY["cases"]


@pytest.mark.parametrize("case", IP["cases"], ids=[c["id"] for c in IP["cases"]])
def test_resolve_client_ip(case: dict[str, Any]) -> None:
    assert case["config"] in IP["configs"], case["config"]
    cfg = IP["configs"][case["config"]]
    assert resolve_client_ip(case["peer"], case["xff"], cfg) == case["expect"]


@pytest.mark.parametrize("case", REFERER["cases"], ids=[c["id"] for c in REFERER["cases"]])
def test_referer_redaction(case: dict[str, Any]) -> None:
    headers = [("User-Agent", "ua")] + ([("Referer", case["referer"])] if case["referer"] is not None else [])
    info = RequestInfo(method="GET", host="x.test", path="/api/me", query="", headers=headers, ip="1.2.3.4", http_version="1.1")
    ev = build_wire_event(info, tap="sdk-python", rid="r")
    assert ev["ref"] == case["ref"]
    wire = json.dumps(ev)
    for secret in case.get("absent", []):
        assert secret not in wire


@pytest.mark.parametrize("case", QUERY["cases"], ids=[c["id"] for c in QUERY["cases"]])
def test_query_redaction(case: dict[str, Any]) -> None:
    info = RequestInfo(method="GET", host="x.test", path="/api/me", query=case["query"], headers=[("User-Agent", "ua")], ip="1.2.3.4", http_version="1.1")
    ev = build_wire_event(info, tap="sdk-python", rid="r")
    assert ev["q"] == case["q"]
    wire = json.dumps(ev)
    for secret in case.get("absent", []):
        assert secret not in wire
