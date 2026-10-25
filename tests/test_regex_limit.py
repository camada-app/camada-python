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

REGEX_LIMIT_VECTORS_SHA256 = "ec076bfb26f12f0f90ffa42bb7b975c6f905afdfe01ba2caeedf6295dd533696"
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


# camada-all-zpbv: a stored `matches` value that is empty or not a string never matches (no str() coercion).
@pytest.mark.parametrize("v", [123, 0, True, None, {"x": 1}, ["^/a"], [123], ""])
@pytest.mark.parametrize("f", ["ua", "path", "header"])
@pytest.mark.parametrize("over", [False, True])
def test_empty_or_non_string_matches_never_matches(v: Any, f: str, over: bool) -> None:
    s = "123 None 0 True null true [object Object] {'x': 1} [^/a] [123]"   # every coerced form of the values
    big = "a" * (MAX_MATCH_INPUT + 1)
    cond: dict[str, Any] = {"f": f, "op": "matches", "v": v, **({"name": "x-h"} if f == "header" else {})}
    ua = f"{s} {big}" if over and f == "ua" else s
    path = f"/a/123/None/0/True/{big}" if over and f == "path" else "/a/123/None/0/True"
    hv = f"{s} {big}" if over and f == "header" else s
    inp = MatchInput(ip="8.8.8.8", ua=ua, path=path, header=lambda n: hv)
    assert not matcher({"id": "cr_b", "action": "block", "conds": [cond]}).match(inp).block
    r = matcher({"id": "cr_s", "action": "skip", "conds": [cond]},
                {"id": "cr_blk", "action": "block", "conds": [{"f": "ip", "op": "is_not", "v": "1.1.1.1"}]}).match(inp)
    assert not r.allowed and r.rule == "cr_blk"
