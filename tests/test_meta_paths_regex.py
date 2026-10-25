# Meta pathsRegex goes through the path `matches` predicate, inside the request's regex budget (camada-all-rvuh).
from __future__ import annotations

from camada.snapshot import paths
from camada.snapshot.match import Matcher, MatchInput
from camada.snapshot.parse import parse_snapshot

from .test_parse import container


def meta_matcher(patterns: list[str], rules: list[dict] | None = None) -> Matcher:
    meta = {"version": "v", "pathsRegex": patterns, "rules": rules or []}
    return Matcher(parse_snapshot(container(0x424C4B35, []), meta))


def test_meta_paths_regex_is_case_insensitive() -> None:
    m = meta_matcher(["^/DUMP$"])
    assert m.match(MatchInput(path="/dump")).reason == "path"
    assert m.match(MatchInput(path="/dumpx")).block is False


def test_meta_paths_regex_refused_pattern_never_matches() -> None:
    m = meta_matcher(["(?>a)", "(?<=a"])
    assert m.match(MatchInput(path="/a")).block is False
    assert m.match(MatchInput(path="/aa")).block is False
    m = meta_matcher([None, 5])   # type: ignore[list-item]  # non-strings never match
    assert m.match(MatchInput(path="/none")).block is False
    assert m.match(MatchInput(path="/5")).block is False


def test_meta_paths_regex_over_cap_path_blocks() -> None:
    m = meta_matcher(["^/never$"])
    over = m.match(MatchInput(path="/" + "a" * paths.MAX_MATCH_INPUT))   # one unit over the cap
    assert over.block is True and over.reason == "path"
    assert m.match(MatchInput(path="/" + "a" * (paths.MAX_MATCH_INPUT - 1))).block is False


def test_meta_paths_regex_shares_the_walk_budget() -> None:
    rules = [{"id": "h", "action": "block", "conds": [{"f": "header", "op": "is", "name": "x-spend", "v": "never"}]}]
    m = meta_matcher(["^/never$"], rules)

    def spend(_: str) -> None:
        paths._budget.left = 0   # the walk's budget is spent, then the rule misses

    spent = m.match(MatchInput(path="/x", header=spend))
    assert spent.block is True and spent.reason == "path"
    assert m.match(MatchInput(path="/x", header=lambda _: None)).block is False
