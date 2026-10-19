# Container handling the golden cases do not reach: malformed input, the advisory version byte,
# and the rule-compilation rules (drop, never guess).
from __future__ import annotations

import struct
from typing import Any

import pytest

from camada.snapshot.match import Matcher, MatchInput
from camada.snapshot.parse import compile_regex, parse_snapshot

from .conftest import read_bin, read_json

V4 = read_bin("blk3/v4-basic.bin")
V4_META = read_json("blk3/v4-basic.meta.json")


def container(magic: int, sections: list[tuple[int, list[int]]]) -> bytes:
    """A tiny BLK container: header then the sections back to back."""
    k = len(sections)
    header = [magic, k]
    off = 2 + k * 3
    body: list[int] = []
    for t, words in sections:
        header += [t, off, len(words)]
        body += words
        off += len(words)
    return struct.pack(f"<{len(header) + len(body)}I", *header, *body)


def test_bad_magic_and_truncation_raise() -> None:
    with pytest.raises(ValueError):
        parse_snapshot(b"nope", {"version": "1"})
    with pytest.raises(ValueError):
        parse_snapshot(struct.pack("<2I", 0x424C4B35, 3), {"version": "1"})            # claims 3 sections, has none
    with pytest.raises(ValueError):
        parse_snapshot(struct.pack("<5I", 0x424C4B35, 1, 10, 5, 100), {"version": "1"})   # section runs past the end


def test_unaligned_tail_is_dropped_not_fatal() -> None:
    snap = parse_snapshot(V4 + b"\x01", V4_META)
    assert snap.format == 4


def test_bytearray_and_memoryview_inputs() -> None:
    for b in (bytearray(V4), memoryview(V4)):
        assert Matcher(parse_snapshot(b, V4_META)).match(MatchInput(ip="203.0.113.66")).reason == "ip4"


def test_v3_magic_still_reads_v4_sections() -> None:
    # the version byte is advisory: an allow range under a BLK3 magic still allows
    n = (192 << 24) | (0 << 16) | (2 << 8) | 20
    bin3 = container(0x424C4B33, [(10, [n, n])])
    r = Matcher(parse_snapshot(bin3, {"version": "x"})).match(MatchInput(ip="192.0.2.20"))
    assert r.allowed and r.reason == "ip4"
    assert parse_snapshot(bin3, {"version": "x"}).format == 3


def rules_snapshot(rules: list[dict[str, Any]], sections: list[tuple[int, list[int]]] | None = None) -> Matcher:
    return Matcher(parse_snapshot(container(0x424C4B35, sections or []), {"version": "v", "rules": rules}))


def test_unknown_action_and_empty_rules_are_dropped() -> None:
    m = rules_snapshot([
        {"id": "a", "action": "teleport", "conds": [{"f": "path", "op": "is", "v": "/x"}]},
        {"id": "b", "action": "block", "conds": []},
        {"id": "c", "action": "block", "conds": [{"f": "path", "op": "is", "v": "/x"}]},
    ])
    assert [r.id for r in m.snap.rules] == ["c"]
    assert m.match(MatchInput(path="/x")).rule == "c"


def test_regex_python_rejects_never_matches_and_never_raises() -> None:
    m = rules_snapshot([{"id": "bad", "action": "block", "conds": [{"f": "path", "op": "matches", "v": "(?<=a"}]}])
    assert m.match(MatchInput(path="/a")).block is False
    m2 = Matcher(parse_snapshot(container(0x424C4B35, []), {"version": "v", "pathsRegex": ["(?<=a", "^/dump$"]}))
    assert m2.match(MatchInput(path="/dump")).reason == "path"


def test_asn_conditions_compare_as_strings_and_unanswerable_fields_never_fire() -> None:
    m = rules_snapshot([
        {"id": "asn", "action": "block", "conds": [{"f": "asn", "op": "is_in", "v": [14061, "7922"]}]},
        {"id": "cc", "action": "block", "conds": [{"f": "country", "op": "is_not", "v": "US"}]},
    ])
    assert m.match(MatchInput(asn=14061)).rule == "asn"
    assert m.match(MatchInput(asn=7922)).rule == "asn"
    assert m.match(MatchInput(asn=1)).rule is None         # country unanswerable: is_not stays false
    assert m.match(MatchInput(country="BR")).rule == "cc"


def test_header_getter_that_raises_or_returns_junk_reads_as_absent() -> None:
    m = rules_snapshot([{"id": "h", "action": "block", "conds": [{"f": "header", "op": "is", "name": "X-Api-Key", "v": "k"}]}])

    def boom(_: str) -> str | None:
        raise RuntimeError("app bug")

    assert m.match(MatchInput(header=boom)).block is False
    assert m.match(MatchInput(header=lambda n: 42 if n == "x-api-key" else None)).block is False  # type: ignore[arg-type,return-value]
    assert m.match(MatchInput(header=lambda n: "k" if n == "x-api-key" else None)).rule == "h"


def test_two_ip_conditions_consume_two_section_pairs_in_order() -> None:
    a = (10 << 24) | 1
    b = (10 << 24) | 2
    m = rules_snapshot(
        [{"id": "r", "action": "block", "conds": [{"f": "ip", "op": "is_in", "set": True}, {"f": "ip", "op": "not_in", "set": True}]}],
        [(14, [0, a, a]), (15, [0]), (14, [0, b, b]), (15, [0])],
    )
    assert m.match(MatchInput(ip="10.0.0.1")).rule == "r"       # in the first, not in the second
    assert m.match(MatchInput(ip="10.0.0.2")).rule is None      # not in the first


def test_js_regex_spellings_are_translated() -> None:
    m = rules_snapshot([{"id": "ver", "action": "block", "conds": [{"f": "path", "op": "matches", "v": r"^/api/(?<ver>v\d+)/"}]}])
    assert m.match(MatchInput(path="/api/v2/dump")).rule == "ver"
    assert m.match(MatchInput(path="/api/v٣/dump")).rule is None   # \d is ASCII, as JS reads it
    m2 = rules_snapshot([{"id": "any", "action": "block", "conds": [{"f": "ua", "op": "matches", "v": r"^a[^]b$"}]}])
    assert m2.match(MatchInput(ua="a\nb")).rule is None   # the control char is stripped first (regex-cap-sdk S2): "ab"
    assert m2.match(MatchInput(ua="aXb")).rule == "any"
    assert m2.match(MatchInput(ua="ab")).rule is None
    rx = compile_regex(r"^a[^]b\cJ$")
    assert rx is not None and rx.search("a\nb\n") is not None


def test_one_matcher_serves_concurrent_requests_without_crosstalk() -> None:
    import threading
    import time

    a = (10 << 24) | 1
    m = rules_snapshot(
        [{"id": "r", "action": "block", "conds": [{"f": "header", "op": "is", "name": "x-a", "v": "1"}, {"f": "ip", "op": "is_in", "set": True}]}],
        [(14, [0, a, a]), (15, [0])],
    )

    def header(_: str) -> str:
        time.sleep(0)   # hand the GIL to the other request between the header read and the ip check
        return "1"

    wrong = [0, 0]

    def hammer(slot: int, ip: str, expect: bool) -> None:
        for _ in range(1500):
            if m.match(MatchInput(ip=ip, header=header)).block is not expect:
                wrong[slot] += 1

    ts = [threading.Thread(target=hammer, args=(0, "10.0.0.1", True)), threading.Thread(target=hammer, args=(1, "10.0.0.2", False))]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert wrong == [0, 0]


# ---------- regex-cap-sdk v1: the `matches` input cap and control-character rules ----------

def _ua_rules(action: str, pattern: str = "^x") -> Matcher:
    return rules_snapshot([{"id": "r", "action": action, "conds": [{"f": "ua", "op": "matches", "v": pattern}]}])


@pytest.mark.parametrize("action", ["block", "challenge", "warn"])
def test_matches_over_cap_is_a_hit_for_deny_rules(action: str) -> None:
    m = _ua_rules(action)
    assert m.match(MatchInput(ua="a" * 2048)).rule is None        # at the cap: the regex runs and misses
    assert m.match(MatchInput(ua="a" * 2049)).rule == "r"         # over: never truncated, never run


def test_matches_over_cap_is_a_miss_for_skip_rules() -> None:
    m = rules_snapshot([
        {"id": "s", "action": "skip", "conds": [{"f": "ua", "op": "matches", "v": "^x"}]},
        {"id": "b", "action": "block", "conds": [{"f": "ua", "op": "contains", "v": "x"}]},
    ])
    assert m.match(MatchInput(ua="x" * 2048)).rule == "s"
    assert m.match(MatchInput(ua="x" * 2049)).rule == "b"


def test_cap_unit_is_utf16_code_units() -> None:
    m = _ua_rules("block")
    assert m.match(MatchInput(ua="é" * 2048)).rule is None        # bytes would be 4096
    assert m.match(MatchInput(ua="😀" * 1024)).rule is None       # 2048 units
    assert m.match(MatchInput(ua="😀" * 1025)).rule == "r"        # 2050 units, 1025 code points
    assert m.match(MatchInput(ua="\ud800" * 2048)).rule is None   # a lone surrogate counts 1
    assert m.match(MatchInput(ua="\ud800" * 2049)).rule == "r"


def test_control_chars_are_deleted_from_ua_and_header_before_matches() -> None:
    m = rules_snapshot([
        {"id": "ua", "action": "warn", "conds": [{"f": "ua", "op": "matches", "v": "Scrapy/[0-9]"}]},
        {"id": "h", "action": "block", "conds": [{"f": "header", "op": "matches", "name": "x-v", "v": "^1\\.2$"}]},
    ])
    assert m.match(MatchInput(ua="Scrapy\t/2.11")).rule == "ua"
    assert m.match(MatchInput(ua="Scr\x00apy/2\x7f.1")).rule == "ua"
    assert m.match(MatchInput(header=lambda n: "1\x7f.2\n" if n == "x-v" else None)).rule == "h"
    # strip before measuring: 2048 units plus a TAB is at the cap
    m2 = _ua_rules("block")
    assert m2.match(MatchInput(ua="a" * 2048 + "\t")).rule is None
    # contains keeps reading the raw value
    m3 = rules_snapshot([{"id": "c", "action": "block", "conds": [{"f": "ua", "op": "contains", "v": "curl/"}]}])
    assert m3.match(MatchInput(ua="cu\x00rl/8")).rule is None


def test_present_ua_that_strips_to_empty_still_runs_the_regex() -> None:
    m = _ua_rules("block", "^$")
    assert m.match(MatchInput(ua="\t\n")).rule == "r"
    assert m.match(MatchInput(ua="")).rule is None                 # absent stays absent


def test_path_matches_cap_deny_and_skip() -> None:
    m = rules_snapshot([
        {"id": "s", "action": "skip", "conds": [{"f": "path", "op": "matches", "v": "^/static-mirror/"}]},
        {"id": "b", "action": "block", "conds": [{"f": "path", "op": "matches", "v": "^/api/v[0-9]+/dump$"}]},
    ])
    assert m.match(MatchInput(path="/static-mirror/" + "a" * 2033)).rule == "s"
    assert m.match(MatchInput(path="/static-mirror/" + "a" * 2034)).rule == "b"
    assert m.match(MatchInput(path="/x/" + "a" * 2045)).rule is None
    assert m.match(MatchInput(path="/x/" + "a" * 2046)).rule == "b"
    assert m.match(MatchInput(path="/x?" + "q" * 3000)).rule is None            # after the query cut
    assert m.match(MatchInput(path="/" + "%61" * 700)).rule == "b"              # raw form over the cap
    assert m.match(MatchInput(path="/static-mirror/" + "%61" * 700)).rule == "s"  # skip ignores raw
    assert m.match(MatchInput(path="/static-mirror/" + "./" * 1100 + "x")).rule == "b"
    assert m.match(MatchInput(path="/" + "é" * 400)).rule == "b"                # lit/full are 2401 units
    assert m.match(MatchInput(path="/api/v2/dump\n")).rule is None              # raw LF becomes %0a
    assert m.match(MatchInput(path="/api/v2/dump%0A")).rule is None
