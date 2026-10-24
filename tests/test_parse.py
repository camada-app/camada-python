# Container handling the golden cases do not reach: malformed input, the advisory version byte,
# and the rule-compilation rules (drop, never guess).
from __future__ import annotations

import struct
import time
import warnings
from typing import Any

import pytest

from camada.snapshot.match import Matcher, MatchInput
from camada.snapshot.parse import _JS_BRACE, _js_to_re, _scan_groups, compile_regex, parse_snapshot

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
    assert m2.match(MatchInput(ua="a\nb")).rule == "any"   # v3 (S5): a deny also tests the raw value, where [^] eats the LF
    assert m2.match(MatchInput(ua="aXb")).rule == "any"
    assert m2.match(MatchInput(ua="ab")).rule is None
    rx = compile_regex(r"^a[^]b\cJ$")
    assert rx is not None and rx.search("a\nb\n") is not None


@pytest.mark.parametrize(
    ("pattern", "text", "not_text"),
    [
        ("a{,3}", "a{,3}", "aa"),
        ("a{,}", "a{,}", "aaa"),
        ("a{1,3}", "aaa", None),
        ("[{,3}]", ",", None),
        ("\\{,3}", "{,3}", None),
    ],
)
def test_non_js_brace_is_text_not_a_bound(pattern: str, text: str, not_text: str | None) -> None:
    rx = compile_regex(pattern)
    assert rx is not None and rx.fullmatch(text)
    assert not_text is None or not rx.fullmatch(not_text)


@pytest.mark.parametrize(
    ("pattern", "text", "expect"),
    [
        ("^admin$", "admin\n", False), ("^admin$", "admin", True), ("^a[$]$", "a$", True), (r"^a\$$", "a$", True),
        (r"^\p{L}$", "p{L}", True), (r"^\p{L}$", "A", False),
        (r"^\x{41}$", "A", False), (r"^\x{2}$", "xx", True),
        (r"^\u{41}$", "A", False), (r"^\u{2}$", "uu", True),
        (r"^\o{101}$", "A", False), (r"^\o{2}$", "oo", True),
        (r"^\g{1}$", "g", True), (r"^\g{1}$", "gg", False),
        (r"^\Qa.b$", "Qa.b", True), (r"^\Qa.b$", "Qaxb", True),
        (r"^a{2}?$", "", False), (r"^a{2}?$", "aa", True),
        (r"^\A\z$", "Az", True), (r"^\e$", "e", True), (r"^\h$", "h", True), (r"^\N$", "N", True),
        (r"^\x4$", "x4", True), (r"^\x41$", "A", True), ("^A$", "A", True),
        (r"^\u0041$", "A", True), (r"^\S[\s\S]\x4", "a b\x04", False), (r"^\S\x4", "ax4", True), (r"\u41", "u41", True), (r"^\k$", "k", True),
        (r"^[\B]$", "B", True), (r"^[\p]$", "p", True), (r"^[\b]$", "\b", True),
        (r"^\d\w\s\b", "1a ", False), (r"^\d\w\s", "1a ", True),
        (r"^\c1$", "\\c1", True), (r"^\c$", "\\c", True), (r"^\v$", "\v", True), (r"^\v$", "\n", False),
        (r"^[\c1]$", "\u0011", True), (r"^[\c1]$", "1", False), (r"^[\c_]$", "\u001f", True), (r"^[\cA]$", "\u0001", True),
        (r"^[\c*]$", "\\", True), (r"^[\c*]$", "c", True), (r"^[\c*]$", "*", True), (r"^[\c*]$", "j", False),
        (r"^[\c]$", "c", True), (r"^\c_$", "\\c_", True),
        (r"^[\s-\c1-x]$", "a", False), (r"^[\s-\c-x]$", "d", True), (r"^[\cé]$", "\t", False), (r"^[\cé]$", "é", True),
    ],
)
def test_js_identity_escapes_and_dollar(pattern: str, text: str, expect: bool) -> None:
    rx = compile_regex(pattern)
    assert rx is not None and (rx.search(text) is not None) is expect


def test_non_js_brace_does_not_blow_up_the_search() -> None:
    import time

    rx = compile_regex(".{,2000}.{,2000}.{,2000}!")
    assert rx is not None
    t0 = time.perf_counter()
    assert rx.search("a" * 2048) is None
    assert time.perf_counter() - t0 < 0.1


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
    # v3 (S5): raw 2049 is over the cap, so a deny rule hits on the raw value even though stripped is at the cap
    m2 = _ua_rules("block")
    assert m2.match(MatchInput(ua="a" * 2048 + "\t")).rule == "r"
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


# ---------- regex-cap-sdk v3 S5: two-value rule for control characters ----------


def _skip_then_block(skip_pat: str, field: str = "ua", name: str | None = None) -> Matcher:
    cond: dict[str, Any] = {"f": field, "op": "matches", "v": skip_pat}
    if name:
        cond["name"] = name
    other: dict[str, Any] = {"f": field, "op": "contains", "v": "x"}
    if name:
        other["name"] = name
    return rules_snapshot([
        {"id": "s", "action": "skip", "conds": [cond]},
        {"id": "b", "action": "block", "conds": [other]},
    ])


def test_s5_deny_pattern_targeting_a_control_char_hits_the_raw_value() -> None:
    assert _ua_rules("block", r"\t").match(MatchInput(ua="a\tb")).rule == "r"
    h = rules_snapshot([{"id": "h", "action": "block", "conds": [{"f": "header", "op": "matches", "name": "x-v", "v": r"\t"}]}])
    assert h.match(MatchInput(header=lambda n: "a\tb" if n == "x-v" else None)).rule == "h"


def test_s5_deny_still_meets_the_stripped_value() -> None:
    assert _ua_rules("block", "sqlmap").match(MatchInput(ua="sql\tmap")).rule == "r"
    h = rules_snapshot([{"id": "h", "action": "block", "conds": [{"f": "header", "op": "matches", "name": "x-v", "v": "sqlmap"}]}])
    assert h.match(MatchInput(header=lambda n: "sql\tmap" if n == "x-v" else None)).rule == "h"


def test_s5_skip_is_a_miss_with_control_chars_and_a_hit_when_clean() -> None:
    m = _skip_then_block("^partner-[a-z]+$")
    assert m.match(MatchInput(ua="x partner-acme")).rule == "b"
    assert _skip_then_block("^partner-[a-z]+x?$").match(MatchInput(ua="partner-acme\n")).rule is None
    ms = rules_snapshot([
        {"id": "s", "action": "skip", "conds": [{"f": "ua", "op": "matches", "v": "^partner-[a-z]+$"}]},
        {"id": "b", "action": "block", "conds": [{"f": "ua", "op": "contains", "v": "partner"}]},
    ])
    assert ms.match(MatchInput(ua="partner-acme")).rule == "s"
    assert ms.match(MatchInput(ua="partner-acme\n")).rule == "b"
    hs = rules_snapshot([
        {"id": "s", "action": "skip", "conds": [{"f": "header", "op": "matches", "name": "x-p", "v": "^partner-[a-z]+$"}]},
        {"id": "b", "action": "block", "conds": [{"f": "header", "op": "contains", "name": "x-p", "v": "partner"}]},
    ])
    assert hs.match(MatchInput(header=lambda n: "partner-acme" if n == "x-p" else None)).rule == "s"
    assert hs.match(MatchInput(header=lambda n: "partner-acme\n" if n == "x-p" else None)).rule == "b"


def test_s5_raw_over_cap_but_stripped_under_cap_deny_hits_skip_misses() -> None:
    v = "a" * 2048 + "\t"
    assert _ua_rules("block", "^b").match(MatchInput(ua=v)).rule == "r"
    ms = rules_snapshot([
        {"id": "s", "action": "skip", "conds": [{"f": "ua", "op": "matches", "v": "^a+$"}]},
        {"id": "b", "action": "block", "conds": [{"f": "ua", "op": "contains", "v": "a"}]},
    ])
    assert ms.match(MatchInput(ua="a" * 2048)).rule == "s"
    assert ms.match(MatchInput(ua=v)).rule == "b"


@pytest.mark.parametrize(
    ("pattern", "text", "expect"),
    [
        ("^.$", "\r", False), ("^.$", " ", False), ("^.$", " ", False), ("^.$", "\n", False), ("^.$", "a", True),
        (r"^\.$", ".", True), ("^[.]$", ".", True), ("^[.]$", "a", False),
        ("[]a]", "a", False), ("[]a]", "]", False), ("[]a]", "a]", False),
        ("^[^]x]$", "qx]", True), ("a[]*b", "ab", True), ("a[]b", "ab", False), ("^[^]$", "\n", True),
        (r"^\s$", " ", True), (r"^\s$", "﻿", True), (r"^\s$", " ", True), (r"^\s$", "a", False),
        (r"^\S$", " ", False), (r"^\S$", "　", False), (r"^\S$", "a", True),
        (r"^[a\s]$", " ", True), (r"^[a\s]$", "a", True), (r"^[a\s]$", "b", False),
        (r"^[^a\s]$", " ", False), (r"^[^a\s]$", "b", True), (r"^[^a\s]$", "a", False),
        (r"^[a-\sz]$", "-", True), (r"^[a-\sz]$", "m", False), (r"^[a\s-z]$", "-", True), (r"^[a\s-z]$", "m", False),
        (r"^[\s-\cA-z]$", "b", False), (r"^[\s-\101-z]$", "b", False), (r"^[\s-\cA-z]$", "-", True),
        (r"^[\s\S]$", "\n", True), (r"^[^\s\S]$", "a", False),
        (r"^[\s-a-z]$", "b", False), (r"^[\s-a-z]$", "-", True), (r"^[\s-a-z]$", "z", True),
        (r"^[\s^]$", "^", True), (r"^[\s^]$", " ", True), (r"^[\S]$", " ", False), (r"^[\S1]$", "1", True),
        (r"^\s$", " ", True), (r"^\S$", " ", False),
        (r"^\s$", "\u2028", True), (r"^\S$", "\u2028", False),
        # an astral char is one char here, two UTF-16 units in JS (accepted gap, camada-all-vuvo)
        ("^.$", "\U0001F600", True), ("^..$", "\U0001F600", False), ("^[^a]$", "\U0001F600", True),
        (r"^\S$", "\U0001F600", True), ("^a.*b$", "a\U0001F600b", True),
    ],
)
def test_js_dot_empty_class_and_unicode_space(pattern: str, text: str, expect: bool) -> None:
    rx = compile_regex(pattern)
    assert rx is not None and (rx.search(text) is not None) is expect


@pytest.mark.parametrize(
    ("pattern", "text", "expect"),
    [
        ("^a{1,99999999999}$", "a", True), ("^a{1,99999999999}$", "b", False),
        ("^a{99999999999}$", "a", False), ("^a{99999999999,}$", "a", False),
        ("^(?:ab){1,99999999999}$", "abab", True), ("^(?:ab){1,99999999999}$", "aba", False),
        ("^a{2,3}$", "aa", True), ("^a{2,3}$", "a", False), ("^a{2,3}$", "aaaa", False),
        ("^(?:a|){99999999999}$", "", True), ("^(?:a?){99999999999}$", "", True),
        ("^a{1," + "9" * 5000 + "}$", "a", True), ("^a{70000}$", "a", False), ("^a{65535}$", "a", False),
        ("^a{" + "0" * 5000 + "1}$", "a", True), ("^a{1," + "0" * 5000 + "2}$", "aa", True),
        ("^a{65535}$", "a" * 65535, True), ("^a{70000}$", "a" * 65535, True),
    ],
)
def test_quantifier_bound_above_limit_is_clamped(pattern: str, text: str, expect: bool) -> None:
    rx = compile_regex(pattern)
    assert rx is not None and (rx.search(text) is not None) is expect


def test_quantifier_bound_emits_clamped_limit() -> None:
    assert "{65535}" in _js_to_re("^(?:a|){99999999999}$")
    assert "{65535}" in _js_to_re("^a{65535}$") and "{65536}" not in _js_to_re("^a{65536}$")


@pytest.mark.parametrize("pattern", ["a{70000,65535}", "a{99999999999,99999999998}", "a{3,2}", "a{" + "0" * 5000 + "3,2}"])
def test_quantifier_min_above_max_is_rejected(pattern: str) -> None:
    assert compile_regex(pattern) is None


def test_quantifier_brace_without_close_does_not_backtrack() -> None:
    assert _JS_BRACE.match("{" + "1" * 20000, 0) is None


@pytest.mark.parametrize("pattern", [r"[a\s-", r"[\s-"])
def test_unterminated_class_after_s_dash_fails_open(pattern: str) -> None:
    assert compile_regex(pattern) is None


def test_js_class_with_space_does_not_backtrack_exponentially() -> None:
    rx = compile_regex(r"^[ \s]+x")
    assert rx is not None and rx.search(" " * 3000) is None


def test_named_backreference() -> None:
    rx = compile_regex(r"(?<n>a)\k<n>")
    assert rx is not None and rx.fullmatch("aa") is not None and rx.fullmatch("ab") is None


def test_literal_bracket_in_class_compiles_without_warning() -> None:
    rx = compile_regex("[[:alpha:]]")   # JS: the class {[ : a l p h} then a literal `]`
    assert rx is not None and rx.search("b") is None
    assert rx.search("a]") is not None and rx.search(":]") is not None


@pytest.mark.parametrize(
    ("pattern", "matches"),
    [
        ("[a&&b]", "&ab"), ("[a||b]", "ab|"), ("[a~~b]", "ab~"), ("[&&&]", "&"),
        ("[!--]", "".join(map(chr, range(33, 46)))), ("[+--]", "+,-"), ("[a-c--]", "-abc"),
        ("[--a]", "".join(map(chr, range(45, 98)))), (r"[\cA--]", "".join(map(chr, range(1, 46)))),
    ],
)
def test_doubled_class_operator_chars_are_members_without_a_warning(pattern: str, matches: str) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        rx = compile_regex(pattern)
    assert rx is not None
    assert "".join(chr(c) for c in range(127) if rx.fullmatch(chr(c))) == "".join(sorted(matches))


def test_class_with_pipe_alternation_chars_compiles_without_warning() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        rx = compile_regex(r"[a|\s|b]")
    assert rx is not None
    assert all(rx.search(c) for c in "|a ") and rx.search("x") is None


@pytest.mark.parametrize(
    ("pattern", "text", "hit"),
    [
        (r"[(?<]\k<n>", "(k<n>", True),   # `(?<` inside a class is no group: `\k` is the letter k
        (r"\(?<n>\k<n>", "(<n>k<n>", True),   # escaped paren: no named group either
        (r"\(?<n>\k<n>", "<n>k<n>", True),
        (r"[^](?<n>a)\k<n>", "xaa", True),
        (r"[](?<n>a)\k<n>", "aa", False),
    ],
)
def test_named_mode_needs_a_real_group(pattern: str, text: str, hit: bool) -> None:
    rx = compile_regex(pattern)
    assert rx is not None and (rx.search(text) is not None) is hit


@pytest.mark.parametrize(
    "pattern",
    [
        r"^(?:(?<n>a)|b)+\k<n>$", r"(?:(a)|b)+\1", r"(?:(a)?b)*\1", r"(?:(a)|b){1,2}\1", r"(?<!(a))\1",   # a repeating ancestor / lookbehind
        r"(?<=(a)\1)b", r"(?<=([ab]){2})\1", r"(?<=(a))\1", r"(?<=\1(a))b", r"(?<m>)|\k<n>",
        r"(a)*\1", r"(a)*x\1", r"(a){0,2}x\1", r"(b*)*x\1", r"(b|)*x\1", r"(a?){0,2}x\1", r"(?<m>b*)*x\k<m>", r"(b*)*\1",   # the group repeats
        r"(?:(?=(a)))?a\1", r"(?=(a))?a\1", r"(?=(a)){0,1}a\1", r"(?<a>x)(?=(?<b>y))?y\k<b>", r"(?:(?=(a))x?)?a\1",   # empty iteration keeps a capture
        "(a)?" * 100 + r"x\100",   # `re` reads \100 as octal
    ],
)
def test_backreference_to_a_maybe_unset_group_fails_open(pattern: str) -> None:
    assert compile_regex(pattern) is None


@pytest.mark.parametrize(
    ("pattern", "text", "hit"),   # answers from node: an unset group (or a forward / self reference) reads empty
    [
        (r"^(a)?x\1$", "x", True), (r"^(a)?x\1$", "axa", True), (r"^(a)?x\1$", "ax", False), (r"^(?:b|\k<n>(?<n>b))$", "b", True),
        (r"^(?:(a)|b)\1$", "aa", True), (r"^(?:(a)|b)\1$", "b", True), (r"^(?:(a)|b)\1$", "ba", False), (r"^(?:(a)|b)\1$", "a", False),
        (r"^(?<q>[\"'])?x\k<q>$", "x", True), (r"^(?<q>[\"'])?x\k<q>$", '"x"', True), (r"^(?<q>[\"'])?x\k<q>$", "\"x", False),
        (r"^(?<q>[\"'])?x\k<q>$", "'x'", True), (r"^(?<q>[\"'])?x\k<q>$", "'x\"", False),
        (r"^\1(a)$", "a", True), (r"^\1(a)$", "aa", False), (r"^(a\1)$", "a", True), (r"^(?:\1(a))+$", "aa", True),
        (r"^\k<n>(?<n>a)$", "a", True), (r"^(a)|b\1$", "b", True), (r"^(?!(a))\1b$", "b", True),
        (r"^(a){00}x\1$", "x", True), (r"^(?:(a))?\1$", "", True), (r"^(?:(a)\1|b)$", "b", True),
    ],
)
def test_backreference_to_a_maybe_unset_group_reads_empty(pattern: str, text: str, hit: bool) -> None:
    rx = compile_regex(pattern)
    assert rx is not None and (rx.search(text) is not None) is hit


def test_fail_open_rules_leave_plain_lookahead_and_group_99_compiled() -> None:
    assert (rx := compile_regex(r"(?=(a))a\1")) is not None and rx.fullmatch("aa")   # node: true
    assert (rx := compile_regex("(a)?" * 99 + r"x\99")) is not None and rx.fullmatch("a" * 99 + "xa")   # node: true


def test_run_of_k_openers_is_linear_literal_text() -> None:
    # no named group: `\k<` is the letter k, so the text is literal; each name scan stops at the next `<` (was quadratic)
    assert (rx := compile_regex("\\k<" * 20000 + ">")) is not None
    assert compile_regex("\\k<" * 3 + ">").search("k<k<k<>") is not None
    assert rx.search("x") is None


def test_run_of_group_openers_is_linear() -> None:
    compile_regex("(?<" * 20000 + ">\\1")   # None is fine; the name scan stops at the next `<` (was quadratic)


@pytest.mark.parametrize("core", ["(a)?", "(a)"])
def test_deep_nesting_with_many_references_scans_in_linear_time(core: str) -> None:
    d = 4000
    t = time.perf_counter()
    _scan_groups("(?:" * d + core + ")" * d + "\\1" * d)   # was O(depth * references): ~1 s
    assert time.perf_counter() - t < 0.5


@pytest.mark.parametrize(
    ("pattern", "yes", "no"),
    [
        (r"(a|b)\1", ["aa", "bb"], ["ab"]),
        (r"(a)+\1", ["aaa"], ["a"]),
        (r"(?:(a)\1)+", ["aaaa"], ["aaa"]),
        (r"(?<n>a)\k<n>", ["aa"], ["ab"]),
        (r"(a){1,2}\1", ["aaa"], ["a"]),
        (r"[\1](a)", ["\x01a"], ["aa", "1a"]),   # class escape, no backreference
    ],
)
def test_backreference_to_a_captured_group_still_compiles(pattern: str, yes: list[str], no: list[str]) -> None:
    rx = compile_regex(pattern)
    assert rx is not None
    assert all(rx.fullmatch(t) for t in yes) and not any(rx.fullmatch(t) for t in no)


def test_out_of_range_numeric_escape_is_no_backreference() -> None:
    assert compile_regex(r"\2(a)") is None   # `re` rejects the octal-looking escape, as before; the scan adds no verdict


def test_deeply_nested_groups_fail_open() -> None:
    assert compile_regex("(?:" * 1000 + "a" + ")" * 1000) is None
