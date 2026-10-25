# regex-limit v1 (camada-all-2pap): customer `matches` regexes are bounded at match time. The vectors live in the
# camada-core sibling checkout (like blk5); the sha pin below is the drift guard every suite shares.
from __future__ import annotations

import hashlib
from typing import Any

import pytest

from camada.snapshot import parse, paths
from camada.snapshot.match import Matcher, MatchInput
from camada.snapshot.paths import MATCH_BUDGET_MS, MAX_MATCH_INPUT, REQUEST_REGEX_BUDGET_MS

from .conftest import fixture_path, read_json
from .test_parse import rules_snapshot

REGEX_LIMIT_VECTORS_SHA256 = "44af7e734bbb7a0b69186a2534f20fce61a60683704a65a05165c667fe057397"
REL = "regex-limit/regex-limit-vectors.json"
V = read_json(REL)


def value(v: Any) -> str:
    if isinstance(v, dict):
        return v.get("prefix", "") + v["repeat"] * v["times"] + v.get("suffix", "")
    return str(v)


def matcher(*rules: dict[str, Any]) -> Matcher:
    return rules_snapshot(list(rules))


def hits(rule: dict[str, Any], **inp: Any) -> bool:
    return matcher(rule).match(MatchInput(**{k: value(v) for k, v in inp.items()})).rule == rule["id"]


def test_vectors_pin_and_constants() -> None:
    assert hashlib.sha256(fixture_path(REL).read_bytes()).hexdigest() == REGEX_LIMIT_VECTORS_SHA256
    c = V["constants"]
    assert (MATCH_BUDGET_MS, REQUEST_REGEX_BUDGET_MS, MAX_MATCH_INPUT) == (c["MATCH_BUDGET_MS"], c["REQUEST_REGEX_BUDGET_MS"], c["MAX_MATCH_INPUT"])


@pytest.mark.parametrize("row", V["over_limit"], ids=lambda r: r["id"])
def test_over_limit(row: dict[str, Any]) -> None:
    assert hits(row["rule"], **row["input"]) is row["hit"]["budget"], row["why"]


@pytest.mark.parametrize("row", V["refused"], ids=lambda r: r["id"])
def test_refused_keep_native_answer(row: dict[str, Any]) -> None:
    rule = {**V["refused_rule"], "conds": [{"f": "ua", "op": "matches", "v": row["pattern"]}]}
    del rule["field"]
    for case in row["cases"]:
        assert hits(rule, ip="8.8.8.8", ua=case["ua"]) is case["hit"]["native"], case["ua"]


def test_request_budget_is_spent_across_rules() -> None:
    p = V["over_limit"][1]["rule"]["conds"][0]["v"]
    slow = [{"id": f"cr_00000000000{i}", "action": "skip", "conds": [{"f": "ua", "op": "matches", "v": p}]} for i in range(3)]
    late = {"id": "cr_0000000000ff", "action": "block", "conds": [{"f": "ua", "op": "matches", "v": "^b"}]}
    inp = MatchInput(ip="8.8.8.8", ua="a" * 2048)
    assert matcher(late).match(inp).rule is None   # alone, ^b misses
    # two timeouts spend the 100 ms; the third skip rule and the block rule answer on_error without running
    assert matcher(*slow, late).match(inp).rule == late["id"]


def test_no_walk_only_per_match_limit() -> None:
    rx = parse.compile_regex(V["over_limit"][0]["rule"]["conds"][0]["v"])
    assert rx is not None
    for _ in range(4):   # no budget accumulates outside a walk: each call still runs (and times out)
        assert paths.regex_hit(rx, "a" * 2048, True) is True
        assert paths.regex_hit(rx, "a" * 2048, False) is False
    assert getattr(paths._budget, "left", None) is None


MEMORY_ERROR_PATTERN = r"^(?:(?=(?<m>b*a){2,}(?:b+(?=\1b*))+(?=[ab]?b*))+?(?=\1\b[b]*)\1)$"   # camada-all-nrdh


@pytest.mark.parametrize("exc", [MemoryError, RuntimeError, RecursionError])
def test_regex_runtime_error_answers_on_error(exc: type[BaseException]) -> None:
    class Boom:
        def search(self, s: str, timeout: float) -> None:
            raise exc()

    assert paths.regex_hit(Boom(), "aaba", True) is True  # type: ignore[arg-type]
    assert paths.regex_hit(Boom(), "aaba", False) is False  # type: ignore[arg-type]


def test_memory_error_pattern_answers_on_error() -> None:
    import regex

    rx = regex.compile(MEMORY_ERROR_PATTERN)
    with pytest.raises(MemoryError) as err:   # the unbounded search raises; the 50 ms limit usually times out first
        rx.search("aaba")

    class Unbounded:   # regex_hit's search without the limit: the failure mode the ticket saw (replays the one real error)
        def search(self, s: str, timeout: float) -> object:
            raise err.value

    assert paths.regex_hit(Unbounded(), "aaba", True) is True  # type: ignore[arg-type]
    assert paths.regex_hit(Unbounded(), "aaba", False) is False  # type: ignore[arg-type]
