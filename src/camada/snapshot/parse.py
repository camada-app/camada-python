"""BLK snapshot parser (v3, v4, v5), ported from @camada/core src/snapshot/parse.ts, itself a
port of edge-analyst src/blocklist.js load() (the reference implementation).

Container: sectioned little-endian uint32 —
  [0] magic 0x424c4b3<version>   [1] section count K
  K x [type, offset(words), length(words)]   then the sections.
Types: 1 V4_STARTS  2 V4_ENDS  3 V4_IDX16  4 V4_BM24  5 V6_STARTS  6 V6_ENDS  7 V6_BM24
       8 ASN_BM  9 ASN_EXTRA.
v4 (contracts §A3) adds two side lists as INTERLEAVED range pairs:
       10 ALLOW_V4  11 ALLOW_V6  12 CHALLENGE_V4  13 CHALLENGE_V6
  *_V4: [start, end, …] (2 words per range, sorted by start)
  *_V6: [s0,s1,s2,s3, e0,e1,e2,e3, …] (8 words per range, big-endian word order, sorted by start)
v5 (contracts §D3) adds the tenant's ordered custom rules, which run BEFORE the three sides:
       14 RULE_V4  15 RULE_V6   — repeated, word 0 = the rule's index into meta.rules, then range
  pairs exactly as 10/11. One 14 + one 15 per `ip` condition, in condition order (an empty half
  still ships its index word), so a rule with two ip conditions reads two pairs.
Meta travels separately: { version, country[], tls[], pathsExact[], pathsPrefix[], pathsRegex[],
                           allow?: side, challenge?: side, rules?: [] } with side = { asn[], country[], pathsExact[], pathsPrefix[] }.
The version byte is advisory: sections 10-15 are read whenever they are present.

A Uint32Array is a `memoryview` cast to 'I': zero-copy, native-endian, so the parser refuses a
big-endian platform rather than match garbage. Python ints are unbounded, so every `>>> 0` of
the original is simply absent.
"""
from __future__ import annotations

import re
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..ipparse import Words

Bits = memoryview   # a uint32 view: memoryview.cast('I')

_FORMATS = {0x424C4B33: 3, 0x424C4B34: 4, 0x424C4B35: 5}
_EMPTY: Bits = memoryview(b"").cast("I")
_ACTIONS = frozenset({"skip", "block", "challenge", "warn"})


def _zeros(n: int) -> Bits:
    return memoryview(bytes(4 * n)).cast("I")


def _words(binary: bytes | bytearray | memoryview) -> Bits:
    if sys.byteorder != "little":
        raise ValueError("camada: big-endian platforms are not supported")
    mv = memoryview(binary)
    if mv.ndim != 1 or mv.itemsize != 1:
        mv = memoryview(mv.tobytes())
    usable = len(mv) - (len(mv) % 4)   # a trailing partial word is dropped, as the Uint32Array view does
    return mv[:usable].cast("I")


@dataclass(slots=True)
class RangeSet:
    """A v4 side list. `empty` short-circuits the matcher on the (common) v3 snapshot."""

    r4: Bits            # interleaved [start, end]
    r6: Bits            # interleaved [4-word start, 4-word end]
    n6: int             # range count in r6
    asn: frozenset[int]
    country: frozenset[str]
    paths_exact: frozenset[str]
    paths_prefix: frozenset[str]
    empty: bool


@dataclass(slots=True)
class RuleRequest:
    """The request a compiled condition reads. `ip6` is the parsed address words, or None."""

    n4: int = -1                        # IPv4 as uint32, or -1 when this request has no IPv4 address
    ip6: Words | None = None
    asn: int | None = None
    country: str | None = None
    tlsx: str | None = None
    path: str = "/"                     # already query-stripped
    ua: str | None = None
    header: Callable[[str], str | None] | None = None   # called with an already lower-cased name; absent where the tap cannot read headers


RuleCond = Callable[[RuleRequest], bool]


@dataclass(slots=True)
class CompiledRule:
    id: str
    action: str
    conds: list[RuleCond]


@dataclass(slots=True)
class Snapshot:
    version: str
    format: int                         # what the container's version byte claimed
    s4: Bits
    e4: Bits
    idx4: Bits
    bm4: Bits
    s6: Bits
    e6: Bits
    n6: int
    bm6: Bits
    asn_bm: Bits
    asn_extra: Bits
    country: frozenset[str]
    tls: frozenset[str]
    paths_exact: frozenset[str]
    paths_prefix: frozenset[str]
    paths_regex: list[re.Pattern[str]]
    allow: RangeSet
    challenge: RangeSet
    rules: list[CompiledRule] = field(default_factory=list)   # v5 only; empty on v3/v4, and the matcher then skips them


def _range_set(r4: Bits, r6: Bits, m: dict[str, Any] | None) -> RangeSet:
    m = m or {}
    asn = frozenset(int(a) for a in m.get("asn") or [])
    country = frozenset(m.get("country") or [])
    exact = frozenset(m.get("pathsExact") or [])
    prefix = frozenset(m.get("pathsPrefix") or [])
    empty = len(r4) == 0 and len(r6) == 0 and not asn and not country and not exact and not prefix
    return RangeSet(r4, r6, len(r6) >> 3, asn, country, exact, prefix, empty)


def in_range4(r: Bits, n: int) -> bool:
    """Binary search over interleaved [start, end] uint32 pairs sorted by start."""
    lo, hi = 0, (len(r) >> 1) - 1
    if hi < 0:
        return False
    while lo < hi:
        m = (lo + hi + 1) >> 1
        if r[m * 2] <= n:
            lo = m
        else:
            hi = m - 1
    return bool(r[lo * 2] <= n <= r[lo * 2 + 1])


def _cmp_words(a: Bits, o: int, w: Words) -> int:
    """Compares the 4 words at a[o..o+3] against the address words."""
    for k in range(4):
        x, y = a[o + k], w[k]
        if x != y:
            return -1 if x < y else 1
    return 0


def in_range6(r: Bits, n: int, w: Words) -> bool:
    """Binary search over an interleaved [4-word start, 4-word end] side section."""
    if n < 1:
        return False
    lo, hi = 0, n - 1
    while lo < hi:
        m = (lo + hi + 1) >> 1
        if _cmp_words(r, m * 8, w) <= 0:
            lo = m
        else:
            hi = m - 1
    o = lo * 8
    return _cmp_words(r, o, w) <= 0 and _cmp_words(r, o + 4, w) >= 0


def compile_regex(pattern: str) -> re.Pattern[str] | None:
    r"""A pattern this runtime rejects never matches, and never throws (fail open). Patterns are
    authored as JS regexes (the analyst validates them with `new RegExp`), so the JS spellings
    `re` refuses are translated first — see _js_to_re — and ASCII mode keeps \d \w \b as JS reads them."""
    try:
        return re.compile(_js_to_re(pattern), re.ASCII)
    except (re.error, TypeError, ValueError, OverflowError):
        return None


def _js_to_re(pattern: str) -> str:
    r"""The JS-only spellings a tenant is likely to author: `(?<name>` -> `(?P<name>`, `[^]` (any
    char) -> `[\s\S]`, `\cX` -> the control character. Anything else `re` rejects still fails open."""
    out: list[str] = []
    i, n, in_class = 0, len(pattern), False
    while i < n:
        ch = pattern[i]
        if ch == "\\" and i + 1 < n:
            nxt = pattern[i + 1]
            if nxt == "c" and i + 2 < n and pattern[i + 2].isalpha():
                out.append(re.escape(chr(ord(pattern[i + 2].upper()) - 64)))
                i += 3
                continue
            out.append(pattern[i : i + 2])
            i += 2
            continue
        if in_class:
            in_class = ch != "]"
        elif ch == "[":
            if pattern.startswith("[^]", i):
                out.append("[\\s\\S]")
                i += 3
                continue
            in_class = True
        elif ch == "(" and pattern.startswith("(?<", i) and not pattern.startswith(("(?<=", "(?<!"), i):
            out.append("(?P<")
            i += 3
            continue
        out.append(ch)
        i += 1
    return "".join(out)


# ---------- custom rules (v5) ----------


def _field_value(f: str, r: RuleRequest) -> str | None:
    """The string one condition reads, or None when this request cannot answer the field.
    `header` is not here: it needs the condition's own name, so _compile_cond builds its reader."""
    if f == "asn":
        return None if r.asn is None else str(r.asn)
    if f == "country":
        return r.country or None
    if f == "tlsx":
        return r.tlsx or None
    if f == "path":
        return r.path
    if f == "ua":
        return r.ua or None
    return None   # an entity-plane field (bot.verified, rule): never true here


def _compile_cond(c: dict[str, Any], sets: list[tuple[Bits, Bits]]) -> RuleCond:
    """One condition -> a predicate. `sets` yields this rule's (v4, v6) section pair per ip
    condition, in condition order, so an ip condition consumes the next one."""
    f, op = str(c.get("f", "")), str(c.get("op", ""))
    negate = op in ("is_not", "not_in")
    # A header condition reads the request through the caller's getter. The name is lower-cased
    # once, here; a tap that cannot read headers (no getter) and a header the request does not
    # carry are both None, and None is false for every op — the rule simply does not fire (fail
    # open, §A4). The getter is app code: one that raises, or answers something other than a
    # str, is read as "no header" rather than allowed to take the whole match() down.
    read: Callable[[RuleRequest], str | None]
    if f == "header":
        hname = str(c.get("name") or "").lower()

        def read(r: RuleRequest) -> str | None:
            if not hname or r.header is None:
                return None
            try:
                v = r.header(hname)
            except Exception:
                return None
            return v if isinstance(v, str) else None
    else:

        def read(r: RuleRequest) -> str | None:
            return _field_value(f, r)

    if f == "ip":
        p4, p6 = sets.pop(0) if sets else (_EMPTY, _EMPTY)
        n6 = len(p6) >> 3

        def ip_cond(r: RuleRequest) -> bool:
            if r.n4 < 0 and r.ip6 is None:
                return False   # no address: false for every op, negatives included
            hit = (r.n4 >= 0 and in_range4(p4, r.n4)) or (r.ip6 is not None and in_range6(p6, n6, r.ip6))
            return (not hit) if negate else hit

        return ip_cond
    raw = c.get("v")
    values = [str(x) for x in raw] if isinstance(raw, list) else [str(raw)]
    if op == "matches":
        rx = compile_regex(values[0])

        def matches(r: RuleRequest) -> bool:
            v = read(r)
            return v is not None and rx is not None and rx.search(v) is not None

        return matches
    if op == "contains":
        needle = values[0]
        return lambda r: (v := read(r)) is not None and needle in v
    if op == "starts_with":
        prefix = values[0]
        return lambda r: (v := read(r)) is not None and v.startswith(prefix)
    members = frozenset(values)   # is | is_not | is_in | not_in

    def membership(r: RuleRequest) -> bool:
        v = read(r)
        if v is None:
            return False
        return (v not in members) if negate else (v in members)

    return membership


def _compile_rules(meta: dict[str, Any], v4s: list[Bits], v6s: list[Bits]) -> list[CompiledRule]:
    """meta.rules + the repeated 14/15 sections -> predicates, in evaluation order. A rule this SDK
    cannot compile (unknown action, no conditions) is dropped rather than guessed at."""
    out: list[CompiledRule] = []
    for i, r in enumerate(meta.get("rules") or []):
        action = str(r.get("action", ""))
        if action not in _ACTIONS:
            continue   # an action this SDK does not know: ignore the rule rather than guess
        v4 = [s for s in v4s if s[0] == i]
        v6 = [s for s in v6s if s[0] == i]
        sets = [(v4[k][1:] if k < len(v4) else _EMPTY, v6[k][1:] if k < len(v6) else _EMPTY) for k in range(max(len(v4), len(v6)))]
        try:
            conds = [_compile_cond(c, sets) for c in (r.get("conds") or [])]
        except Exception:
            continue   # a malformed rule is dropped, never enforced
        if conds:   # a rule with no conditions would match everything
            out.append(CompiledRule(str(r.get("id", "")), action, conds))
    return out


def parse_snapshot(binary: bytes | bytearray | memoryview, meta: dict[str, Any]) -> Snapshot:
    """Parses a BLK container + meta into a Snapshot. Raises on a malformed container — callers
    keep the previous snapshot, exactly like the edge collector does."""
    u = _words(binary)
    fmt = _FORMATS.get(u[0]) if len(u) >= 2 else None
    if not fmt:
        raise ValueError("camada: not a BLK3 snapshot")
    count = u[1]
    sec: dict[int, Bits] = {}
    rule4: list[Bits] = []
    rule6: list[Bits] = []
    if len(u) < 2 + count * 3:
        raise ValueError("camada: truncated BLK3 header")
    for i in range(count):
        t, off, ln = u[2 + i * 3], u[3 + i * 3], u[4 + i * 3]
        if off + ln > len(u):
            raise ValueError("camada: truncated BLK3 section")
        s = u[off : off + ln]
        if t == 14:
            rule4.append(s)   # repeated, one per ip condition: kept in container order
        elif t == 15:
            rule6.append(s)
        else:
            sec[t] = s
    s6 = sec.get(5, _EMPTY)
    return Snapshot(
        version=str(meta.get("version", "")),
        format=fmt,
        s4=sec.get(1, _EMPTY), e4=sec.get(2, _EMPTY), idx4=sec.get(3) or _zeros(65537), bm4=sec.get(4) or _zeros(524288),
        s6=s6, e6=sec.get(6, _EMPTY), n6=len(s6) // 4, bm6=sec.get(7) or _zeros(524288),
        asn_bm=sec.get(8) or _zeros(131072), asn_extra=sec.get(9, _EMPTY),
        country=frozenset(meta.get("country") or []),
        tls=frozenset(meta.get("tls") or []),
        paths_exact=frozenset(meta.get("pathsExact") or []),
        paths_prefix=frozenset(meta.get("pathsPrefix") or []),
        paths_regex=[rx for rx in (compile_regex(p) for p in meta.get("pathsRegex") or []) if rx is not None],
        allow=_range_set(sec.get(10, _EMPTY), sec.get(11, _EMPTY), meta.get("allow")),
        challenge=_range_set(sec.get(12, _EMPTY), sec.get(13, _EMPTY), meta.get("challenge")),
        rules=_compile_rules(meta, rule4, rule6),
    )
