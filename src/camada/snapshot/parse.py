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

import regex

from ..ipparse import Words
from .paths import PathForms, canon_path, dir_key, over_cap, path_hit, path_pred, regex_hit

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
    paths: PathForms = ("/", "/", "/")  # (raw with the query cut, lit, full): see snapshot/paths.py
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
    paths_regex: list[regex.Pattern[str]]
    allow: RangeSet
    challenge: RangeSet
    rules: list[CompiledRule] = field(default_factory=list)   # v5 only; empty on v3/v4, and the matcher then skips them


def _range_set(r4: Bits, r6: Bits, m: dict[str, Any] | None) -> RangeSet:
    m = m or {}
    asn = frozenset(int(a) for a in m.get("asn") or [])
    country = frozenset(m.get("country") or [])
    exact = frozenset(canon_path(p) for p in m.get("pathsExact") or [])   # canonical, once (§D3 "Path matching")
    prefix = frozenset(dir_key(p) for p in m.get("pathsPrefix") or [])
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


def compile_regex(pattern: str, flags: int = 0) -> regex.Pattern[str] | None:
    r"""A pattern this runtime rejects never matches, and never throws (fail open). Patterns are
    authored as JS regexes (the analyst validates them with `new RegExp`), so the JS spellings
    `regex` refuses are translated first — see _js_to_re — and ASCII mode keeps \d \w \b as JS reads them.
    An astral char is one code point here and two UTF-16 units in JS, so `.`, `[^a]` and `\S` count it
    once (an accepted gap, camada-all-vuvo). A backreference to a group that may not have captured on that pass
    reads empty in JS and fails in `re`: _scan_groups marks it for a translation that reads empty too, or (a repeating
    ancestor, where JS resets the capture per iteration) fails open.
    A `(?` or `(*` group JS lacks (`(?i)`, `(?>`, `(?#`, `(*FAIL)`, ...) fails open: JS rejects it or V8 mis-evaluates it (camada-all-lsl8).
    A repeat of 1000+ of an empty group, `b(){65535}c`, fails open: `regex` takes minutes to compile it (camada-all-fe5v).
    Callers pass regex flags (regex.IGNORECASE), not re's."""
    try:
        scan = _scan_groups(pattern)
        if scan[1]:
            return None
        return regex.compile(_js_to_re(pattern, scan), regex.ASCII | regex.V0 | flags)
    except Exception:   # regex.error, RecursionError (deeply nested groups), and what regex leaks, e.g. KeyError on `(?V1)`
        return None


_JS_BRACE = re.compile(r"\{([0-9]+)(?:(,)([0-9]*))?\}")   # optional group: no quadratic backtrack on `{11...` sans `}`
_RE_MAX_BOUND = 65535   # same as camada-php: above any path or header a request carries (pathsRegex runs uncapped)
_JS_ESCAPE = re.compile(r"[bdDfnrsStvwW]|x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}")   # the letter escapes JS reads without `u`
_JS_ATOM = re.compile(r"\\(?:c[A-Za-z0-9_]|x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|[0-3][0-7]{0,2}|[4-7][0-7]?|[^c])|[\s\S]")   # one class atom
_JS_NON_GROUP = re.compile(r"\((?:\*|\?(?![:=!<]))")   # a `(?` or `(*` opening none of the JS forms `(?:` `(?=` `(?!` `(?<`
_JS_EMPTY_GROUP = re.compile(r"\([()]*\)\Z")   # the text so far ends in a group of nothing but groups: `()`, `(())`
_JS_NAMED_GROUP = re.compile(r"\(\?<(?![=!])")
_JS_BACKREF = re.compile(r"\\k<([^<>]+)>")   # a JS name holds no `<` or `>`: linear on a run of `\k<`
_JS_REF = re.compile(r"\\(?:k<([^<>]+)>|([1-9][0-9]*))")   # a named or numbered backreference: group 1 or 2
_JS_HAS_REF = re.compile(r"\\[1-9k]")
_JS_WS = r"\t-\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"   # JS \s; re.ASCII's is ASCII-only
_JS_DOT = r"[^\n\r\u2028\u2029]"
_JS_SPACE = {"s": f"[{_JS_WS}]", "S": f"[^{_JS_WS}]"}


_HEADER = re.compile(r"\(\?(?:<[=!]|<[^<>]*>|[A-Za-z-]*:|[=!])")   # a group opener, bounded: lookbehind, name, flags, lookahead


@dataclass(slots=True)
class _Frame:
    parent: int
    alt: bool = False   # has a `|`
    min0: bool = False   # min-0 quantified
    neg: bool = False   # negative lookaround
    lb: bool = False   # lookbehind (positive or negative)
    end: int = -1   # index of its `)`, -1 while open
    rep: bool = False   # repeat-quantified (`+` `*` `{n,}` `{n}` n>1 `{n,m}` m>1)
    la: bool = False   # positive lookahead (a negative one never keeps a capture)
    solid: bool = False   # the current alternation branch holds an atom that must consume input
    nullable: bool = False   # the body can match empty (a branch with no such atom, or a lookaround)


_Scan = tuple[bool, bool, dict[int, tuple[int, bool]]]
_JS_ESC = re.compile(r"\\(?:c[A-Za-z]|x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|0[0-7]{0,2}|[\s\S])")   # one escape, as long as JS reads it


def _min0_at(pattern: str, j: int) -> bool:
    """Does the text at j open a min-0 quantifier (`?`, `*`, `{0}` `{0,}` `{0,m}`)?"""
    if pattern.startswith(("?", "*"), j):
        return True
    b = _JS_BRACE.match(pattern, j) if pattern.startswith("{", j) else None
    return b is not None and not b[1].strip("0")


def _scan_groups(pattern: str) -> _Scan:
    r"""(a real `(?<name>` group exists, the pattern must fail open, {reference index: (its end index, True for a conditional
    `(?(g)\g)`, False for `(?:)`)}): one escape- and class-aware walk (a class opens at an unescaped `[`, `[` is literal inside, the first
    unescaped `]` closes it). JS reads a reference to an unset group as empty. A reference whose group is still open at
    the reference (forward or self) is always empty: False. One whose group sits under a min-0 quantifier or a negative
    lookaround (itself or any ancestor), or lies in an alternation branch (an ancestor or the top level has a `|`), may
    be unset: True. Fail open instead when the group or an ancestor repeats (JS resets captures per iteration, `re` keeps them, and
    a repeating group that matches empty overwrites its capture in `re` where JS rejects that iteration), when the group is
    inside a positive lookahead (JS rejects an empty optional iteration and tries paths in another order, a lookahead keeps its first),
    or for any backward numbered reference past group 99, rewritten or not (`re` reads `\100` as octal).
    A backreference inside a lookbehind, or to a group with a lookbehind ancestor, also diverges: JS matches a lookbehind right
    to left (so "closed before the reference" is backwards there, and a quantified group keeps its leftmost repetition).
    With named groups present, a `\k<name>` that names no group is a JS SyntaxError, so it fails open. Frames are created
    in `(` order, so one forward pass gives each its inherited flags and every reference is classified in O(1).
    A plain reference (group closed before it) also fails open when the group or an ancestor that closes before the reference
    repeats and can match empty: JS rejects an empty iteration once the minimum is met and keeps the previous capture, `re`
    takes it and overwrites the capture with ''. The same walk tracks per frame whether the current branch holds an atom that
    must consume input (`solid`: a literal, `.`, a class or a letter escape not followed by a min-0 quantifier, or a
    non-nullable group) and whether the body can match empty (`nullable`: a branch without one, or a lookaround). Anything unsure
    counts as nullable, which only fails open; a reference inside the repeating frame reads its own iteration's capture and stays."""
    if not _JS_HAS_REF.search(pattern):
        return False, False, {}   # nothing reads the names or can diverge without a reference
    frames = [_Frame(-1)]
    stack = [0]
    groups: list[tuple[int, str | None]] = []   # (frame, name) in `(` order
    marks: dict[int, tuple[int, bool]] = {}
    refs: list[tuple[str, bool, int, int, int]] = []   # (name or number, is a name, index, end, enclosing frame)
    i, n, in_class, named = 0, len(pattern), False, False
    quiet = 0   # chars before this index (a group header, a `\k<name>`) are no atoms
    while i < n:
        ch = pattern[i]
        if ch == "\\":
            if in_class:
                i += 2
                continue
            if m := _JS_REF.match(pattern, i):
                refs.append((m[1] or m[2], m[1] is not None, i, m.end(), stack[-1]))
                if pattern[i + 1] == "k":
                    quiet = m.end()   # the name may hold structure chars the walk must still see
                    i += 2
                else:
                    i = m.end()
                continue
            em = _JS_ESC.match(pattern, i)
            j = em.end() if em else n
            if em and em[0] not in ("\\b", "\\B", "\\c", "\\k") and not _min0_at(pattern, j):
                frames[stack[-1]].solid = True
            i = j
            continue
        if in_class:
            in_class = ch != "]"
            if not in_class and not _min0_at(pattern, i + 1):
                frames[stack[-1]].solid = True
        elif ch == "[":
            in_class = True
        elif ch == "(":
            q = pattern.startswith("?", i + 1)
            cap = not q or (pattern.startswith("<", i + 2) and pattern[i + 3 : i + 4] not in ("=", "!"))
            if q and cap:
                named = True
            frames.append(_Frame(stack[-1], neg=pattern.startswith(("?!", "?<!"), i + 1),
                                 lb=pattern.startswith(("?<=", "?<!"), i + 1), la=pattern.startswith("?=", i + 1)))
            stack.append(len(frames) - 1)
            gm = _GROUP_NAME.match(pattern, i) if q and cap else None
            quiet = m.end() if (m := _HEADER.match(pattern, i)) else i + (3 if q else 1)   # the header is no atom
            if cap:
                groups.append((len(frames) - 1, (gm[1] if gm else None) if q else None))
        elif ch == "|":
            fr = frames[stack[-1]]
            fr.alt = True
            fr.nullable |= not fr.solid
            fr.solid = False
        elif ch == ")" and len(stack) > 1:
            fr = frames[stack.pop()]
            fr.end = i
            b = _JS_BRACE.match(pattern, i + 1)
            fr.min0 = _min0_at(pattern, i + 1)
            fr.rep = pattern.startswith(("+", "*"), i + 1) or (b is not None and (b[2] and not b[3] or _num(b[3] or b[1]) > (1, "1")))
            fr.nullable = fr.nullable or not fr.solid or fr.neg or fr.lb or fr.la
            if not fr.nullable and not fr.min0:
                frames[fr.parent].solid = True
        elif ch not in "^$)?*+" and i >= quiet:
            if ch == "{" and (b := _JS_BRACE.match(pattern, i)):   # a quantifier, no atom
                i = b.end()
                continue
            if not _min0_at(pattern, i + 1):
                frames[stack[-1]].solid = True
        i += 1
    # per frame: a lookbehind at or above, may be unset, a strict ancestor repeats, a positive lookahead at or above
    in_lb, unset, rep_above, in_la, rn = [False], [False], [False], [False], [-1]   # rn: end of the nearest repeating nullable frame
    for fr in frames[1:]:
        p = frames[fr.parent]
        in_lb.append(fr.lb or in_lb[fr.parent])
        unset.append(fr.min0 or fr.neg or p.alt or unset[fr.parent])
        rep_above.append(p.rep or rep_above[fr.parent])
        in_la.append(fr.la or in_la[fr.parent])
        rn.append(fr.end if fr.rep and fr.nullable else rn[fr.parent])
    names = {g[1]: k for k, g in enumerate(groups) if g[1] is not None}
    for ref, is_name, at, end, home in refs:
        if is_name:
            k = names.get(ref)
            if k is None and named:
                return named, True, {}
        else:
            k = int(ref) - 1 if len(ref) < 8 and int(ref) <= len(groups) else None   # past the count it is an octal or identity escape
            if k is None and len(ref) > 2 and 10 <= int(ref[:2]) <= len(groups) and not _OCTAL3.match(ref):
                return named, True, {}   # JS reads `\108` as octal `\10` + "8", `re` as group 10 + "8"
        if k is None:
            continue
        g = groups[k][0]
        if in_lb[home] or in_lb[g]:
            return named, True, {}
        if not 0 <= frames[g].end < at:
            marks[at] = end, False
        elif not is_name and k > 98 or 0 <= rn[g] < at:
            return named, True, {}
        elif unset[g]:
            if rep_above[g] or frames[g].rep or in_la[g]:
                return named, True, {}
            marks[at] = end, True
    return named, False, marks


_OCTAL3 = re.compile(r"[0-3][0-7][0-7]")   # `re` reads three octal digits as an octal escape, as JS does
_GROUP_NAME = re.compile(r"\(\?<([^<>]*)>")   # bounded: each attempt stops at the next `<`


def _num(d: str) -> tuple[int, str]:
    d = d.lstrip("0") or "0"
    return len(d), d   # orders like the integer without int(), which refuses a huge digit string


_MAX_NUM = _num(str(_RE_MAX_BOUND))


def _js_to_re(pattern: str, scan: _Scan | None = None) -> str:
    r"""The JS-only spellings a tenant is likely to author: `(?<name>` -> `(?P<name>`, `\k<name>` -> `(?P=name)`, `[^]` (any
    char) -> `[\s\S]`, `\cX` -> the control character, a `{` that is no JS quantifier (`{,3}`,
    `{ 1}`) -> `\{` (JS reads it as text, `re` as a bound), and `$` outside a class -> `\Z` (JS `$` never
    matches before a trailing newline). `\<letter>` outside JS's escape set is the bare letter, as JS reads it
    without `u` (`\p{L}` is "p{L}", `\A` is "A"). `.` outside a class excludes \n \r U+2028 U+2029 as in JS; `[]`
    never matches (`(?!)`) and a `]` outside a class is text; `\s`/`\S` are JS's Unicode whitespace (inside a class
    they become a union with the rest of it, and a `-` beside one stays a literal dash). Anything else `re` rejects still fails open."""
    out: list[str] = []
    i, n, in_class = 0, len(pattern), False
    start, neg, pulled, pulled_end, solo_end = 0, False, [], -1, -1   # the open class: its `[` index in out, negation, \s/\S pulled out
    rng = 0   # in a class: 0 no atom to start a range, 1 an atom that can, 2 a range dash awaiting its end
    named, _, marks = scan or _scan_groups(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "\\" and i + 1 < n:
            nxt = pattern[i + 1]
            # Annex B: inside a class `\c` also takes a digit or `_`
            cc = pattern[i + 2 : i + 3]
            if nxt == "c" and cc and (cc.isascii() and cc.isalpha() or in_class and cc in "0123456789_"):
                if in_class:
                    rng = 0 if rng == 2 else 1
                out.append(re.escape(chr(ord(cc.upper()) % 32)))
                i += 3
                continue
            if nxt in "sS":
                if in_class:
                    pulled.append(_JS_SPACE[nxt])
                    pulled_end = i + 2
                    rng = 0
                else:
                    out.append(_JS_SPACE[nxt])
                i += 2
                continue
            if mark := marks.get(i):   # a reference to an unset group reads empty in JS
                end, cond = mark
                ref = pattern[i:end]
                name = ref[3:-1] if nxt == "k" else ref[1:]
                out.append((f"(?({name})(?P={name}))" if nxt == "k" else f"(?({name})\\{name})") if cond else "(?:)")
                i = end
                continue
            if nxt == "k" and named and not in_class and (m := _JS_BACKREF.match(pattern, i)):   # `\k<name>` -> `(?P=name)`
                out.append(f"(?P={m[1]})")
                i = m.end()
                continue
            kept = (not (nxt.isascii() and nxt.isalpha()) or _JS_ESCAPE.match(pattern, i + 1) is not None
                    or (nxt == "B" and not in_class) or (nxt == "k" and named))
            rng = 0 if rng == 2 else 1
            out.append(pattern[i : i + 2] if kept else "\\\\c" if nxt == "c" else nxt)   # JS reads `\c` before a non-letter as text
            i += 2
            continue
        if in_class:
            if ch != "]":
                dash = ch == "-" and (i in (pulled_end, solo_end) or pattern.startswith(("\\s", "\\S"), i + 1))
                if dash and i == pulled_end:   # JS reads the atom after that dash as standalone: a dash right after it is text too
                    m = _JS_ATOM.match(pattern, i + 1)
                    solo_end = m.end() if m else i + 2   # the pattern always matches: a dash is followed by an atom
                if dash:
                    rng = 0
                elif ch == "-":
                    # a doubled `-` reads as a set difference to re: escape the literal one, or the range end
                    dash = rng == 2 or (rng == 0 and pattern.startswith("-", i + 1))
                    rng = 2 if rng == 1 else 1 if dash and rng == 0 else 0
                elif not (neg and len(out) == start + 1 and ch == "^"):
                    rng = 0 if rng == 2 else 1
                    if ch in "&|~" and out[-1] == ch:   # `&&` `||` `~~` read as a set operator
                        dash = True
                out.append("\\" + ch if dash else "\\[" if ch == "[" else ch)   # a literal `[` would read as a nested set
            elif len(set(pulled)) == 2:   # \s and \S together: any char
                out[start:] = ["(?!)" if neg else "[\\s\\S]"]
                in_class = False
            elif pulled:
                body = "".join(out[start + 1 + neg :])
                body = "\\" * body.startswith("^") + body   # `[\s^]` is not a negated class
                alts = ([f"[{body}]"] if body else []) + pulled
                u = "|".join(alts)   # a lookahead, so a char matches one way only (no ReDoS)
                out[start:] = [f"(?:(?{'!' if neg else '='}{u})[\\s\\S])" if neg or len(alts) > 1 else u]
                in_class = False
            else:
                out.append("]")
                in_class = False
            i += 1
            continue
        if ch in "].":
            out.append("\\]" if ch == "]" else _JS_DOT)
            i += 1
            continue
        if ch == "[":
            if pattern.startswith("[^]", i):
                out.append("[\\s\\S]")
                i += 3
                continue
            if pattern.startswith("[]", i):
                out.append("(?!)")
                i += 2
                continue
            rng = 0
            in_class, start, neg, pulled = True, len(out), pattern.startswith("^", i + 1), []
            out.append("[")
            i += 1
            continue
        if ch == "(" and _JS_NON_GROUP.match(pattern, i):
            raise ValueError("non-JS group")   # compile_regex fails open: JS rejects it or the engine gives it a meaning (camada-all-lsl8)
        if ch == "(" and _JS_NAMED_GROUP.match(pattern, i):
            out.append("(?P<")
            i += 3
            continue
        elif ch == "$":
            out.append("\\Z")
            i += 1
            continue
        elif ch == "{" and (brace := _JS_BRACE.match(pattern, i)):
            lo, comma, hi = brace.groups()
            lo_n, hi_n = _num(lo), (_num(hi) if hi else None)
            if len(lo_n[1]) > 3 and _JS_EMPTY_GROUP.search(pattern, 0, i):
                raise ValueError("huge repeat of an empty group")   # fail open: `regex` compiles `b(){65535}c` in minutes (camada-all-fe5v)
            if hi_n is not None and lo_n > hi_n:
                out.append(brace[0])   # m > n is a JS SyntaxError: leave it so re rejects it too
            else:
                lo = str(_RE_MAX_BOUND) if lo_n > _MAX_NUM else lo_n[1]   # stripped: re's int() refuses >4300 digits
                hi = "" if hi_n is None or hi_n > _MAX_NUM else hi_n[1]   # an upper bound past it never binds a real input, so drop it
                out.append(f"{{{lo}{comma or ''}{hi}}}")
            i = brace.end()
            continue
        elif ch == "{":
            out.append("\\{")
            i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


# ---------- custom rules (v5) ----------

_CTL = re.compile(r"[\x00-\x1f\x7f]")


def _field_value(f: str, r: RuleRequest) -> str | None:
    """The string one condition reads, or None when this request cannot answer the field.
    `header` is not here: it needs the condition's own name, so _compile_cond builds its reader."""
    if f == "asn":
        return None if r.asn is None else str(r.asn)
    if f == "country":
        return r.country or None
    if f == "tlsx":
        return r.tlsx or None
    if f == "ua":
        return r.ua or None
    return None   # an entity-plane field (bot.verified, rule): never true here


def compile_path_regex(pattern: str) -> regex.Pattern[str] | None:
    """A path regex runs case-insensitively (§D3 "Path matching")."""
    return compile_regex(pattern, regex.IGNORECASE)


def _compile_cond(c: dict[str, Any], sets: list[tuple[Bits, Bits]], deny: bool = True) -> RuleCond:
    """One condition -> a predicate. `sets` yields this rule's (v4, v6) section pair per ip
    condition, in condition order, so an ip condition consumes the next one. `deny` is false for a
    skip rule: its path conditions need every canonical spelling to match, a block's any one."""
    f, op = str(c.get("f", "")), str(c.get("op", ""))
    if f == "path":   # every path op reads the canonical forms, never _field_value
        pv = c.get("v")
        pred = path_pred(op, [str(x) for x in pv] if isinstance(pv, list) else [str(pv)], compile_path_regex, deny)
        return lambda r: path_hit(pred, r.paths, deny)
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

        strip = f in ("ua", "header")

        def matches(r: RuleRequest) -> bool:
            v = read(r)
            if v is None or rx is None:
                return False
            # regex-cap-sdk S1: never truncate (a needle pushed past the cap would fail a deny rule open)
            def f(s: str) -> bool:
                return deny if over_cap(s) else regex_hit(rx, s, deny)

            if not strip:
                return f(v)
            stripped, n = _CTL.subn("", v)   # one scan (S5): engines disagree on control chars ($ before \n)
            if n == 0:
                return f(v)
            # S5: control chars never widen a skip and never neuter a deny regex
            return deny and (f(v) or f(stripped))

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
            conds = [_compile_cond(c, sets, action != "skip") for c in (r.get("conds") or [])]
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
        paths_exact=frozenset(canon_path(p) for p in meta.get("pathsExact") or []),
        paths_prefix=frozenset(dir_key(p) for p in meta.get("pathsPrefix") or []),
        paths_regex=[rx for rx in (compile_path_regex(p) for p in meta.get("pathsRegex") or []) if rx is not None],
        allow=_range_set(sec.get(10, _EMPTY), sec.get(11, _EMPTY), meta.get("allow")),
        challenge=_range_set(sec.get(12, _EMPTY), sec.get(13, _EMPTY), meta.get("challenge")),
        rules=_compile_rules(meta, rule4, rule6),
    )
