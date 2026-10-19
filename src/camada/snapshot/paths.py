# Path canonicalisation (contracts §D3 "Path matching"), ported byte for byte from edge-analyst
# src/blocklist.js canonPath / pathForms / pathHit / pathPred.
#
# A path rule must catch every spelling a framework would route to the same handler, so both sides of a
# comparison are canonicalised: query cut at ? or #; %XX decoded when it is printable ASCII other than / and %
# (so %2F never becomes a separator, and decoding stays one pass); every other byte, raw non-ASCII included,
# written as lower-case %xx of its UTF-8; ASCII lower-cased; each segment cut at its first ; (servlet path
# parameters); empty segments dropped (// and the trailing slash); and . / .. resolved — the `full` form. The
# `lit` form skips that last step, for a router that sends /locked/../x to the /locked handler unresolved. A
# block, challenge or warn fires when the raw path, `lit` or `full` matches; a skip or an allow entry needs
# `lit` AND `full` to match, so /public/../admin can never borrow /public/'s exemption. Path regexes are
# case-insensitive. A rule value goes through the same function once, at load.
from __future__ import annotations

import re
from collections.abc import Callable, Collection, Sequence

MAX_MATCH_INPUT = 2048   # regex-cap-sdk v1: the longest value a `matches` regex is run on, in UTF-16 code units

PathForms = tuple[str, str, str]   # (raw with the query cut, lit, full)
PathPred = Callable[[str], bool]

_HEX = "0123456789abcdef"
_HEXV = {c: int(chr(c), 16) for c in b"0123456789abcdefABCDEF"}
# already canonical: the common case skips the byte walk
_LONE_SURROGATE = re.compile("[\ud800-\udfff]")   # a str holds a surrogate code point only when it is unpaired
_CANON = re.compile(r"(?:/(?!\.\.?(?:/|$))[a-z0-9\-._~!$&'()*+,=:@]+)+")


_CTL_PATH = re.compile(r"[\x00-\x1f\x7f]")


def utf16_len(v: str) -> int:
    """Length in UTF-16 code units (what edge's `v.length` counts): an astral code point is 2."""
    if v.isascii():
        return len(v)
    return len(v) + sum(1 for ch in v if ord(ch) > 0xFFFF)


def over_cap(v: str) -> bool:
    return utf16_len(v) > MAX_MATCH_INPUT


def _strip_query(raw: str | None) -> str:
    p = raw or "/"
    q = len(p)
    for ch in "?#":
        i = p.find(ch)
        if i != -1 and i < q:
            q = i
    return p[:q]


def _is_canon(p: str) -> bool:
    return p == "/" or _CANON.fullmatch(p) is not None


def canon_path(raw: str | None, dots: bool = True) -> str:
    p = _strip_query(raw)
    if _is_canon(p):
        return p
    b = _LONE_SURROGATE.sub("\ufffd", p).encode("utf-8")   # as JS TextEncoder: a lone surrogate is U+FFFD
    n = len(b)
    out: list[str] = []
    i = 0
    while i < n:
        c = b[i]
        if c == 37 and i + 2 < n and b[i + 1] in _HEXV and b[i + 2] in _HEXV:
            c = _HEXV[b[i + 1]] * 16 + _HEXV[b[i + 2]]
            i += 2
            if c == 47:
                out.append("%2f")
                i += 1
                continue
        if c < 0x21 or c > 0x7E or c == 37:
            out.append("%" + _HEX[c >> 4] + _HEX[c & 15])
        else:
            out.append(chr(c + 32 if 65 <= c <= 90 else c))
        i += 1
    segs: list[str] = []
    for seg in "".join(out).split("/"):
        k = seg.find(";")
        if k != -1:
            seg = seg[:k]
        if not seg or (dots and seg == "."):
            continue
        if dots and seg == "..":
            if segs:
                segs.pop()
            continue
        segs.append(seg)
    return "/" + "/".join(segs)


def path_forms(raw: str | None) -> PathForms:
    """(raw with the query cut, lit, full) for one request path."""
    p = _strip_query(raw)
    if _is_canon(p):
        return (p, p, p)
    lit, full = canon_path(p, False), canon_path(p, True)
    # a decoded path (WSGI PATH_INFO) may carry a raw control character: spell it %xx as canon_path does
    return (_CTL_PATH.sub(lambda m: f"%{ord(m.group()):02x}", p), lit, full)


def _dir(p: str) -> str:
    return p if p.endswith("/") else p + "/"


def dir_key(v: str) -> str:
    """A prefix entry or a starts_with value ending in / -> its canonical directory key ('/' stays '/')."""
    return _dir(canon_path(v))


def prefixed(prefixes: Collection[str], path: str) -> bool:
    """Walks '/' boundaries: /a/b tries /, /a/, /a/b/."""
    d = _dir(path)
    i = 0
    while i != -1:
        if d[: i + 1] in prefixes:
            return True
        i = d.find("/", i + 1)
    return False


def path_hit(pred: PathPred, forms: PathForms, deny: bool) -> bool:
    """deny (block/challenge/warn) = any spelling; allow/skip = both canonical forms."""
    if deny:
        return pred(forms[0]) or pred(forms[1]) or pred(forms[2])
    return pred(forms[1]) and pred(forms[2])


def path_pred(
    op: str, values: Sequence[str], compile_regex: Callable[[str], re.Pattern[str] | None], deny: bool = True
) -> PathPred:
    """One path condition -> a predicate over a single path form. `compile_regex` is the caller's
    JS-regex translation, already case-insensitive. A `matches` form over MAX_MATCH_INPUT never runs
    the regex: it answers `deny` (a hit for block/challenge/warn, a miss for skip)."""
    if op == "matches":
        rx = compile_regex(values[0])
        return lambda p: rx is not None and (deny if over_cap(p) else rx.search(p) is not None)
    if op == "starts_with":
        v = values[0]
        key = dir_key(v) if v.endswith("/") else canon_path(v)
        return lambda p: _dir(p).startswith(key)
    members = frozenset(canon_path(v) for v in values)
    return lambda p: p in members
