# Matcher: sub-millisecond checks over a parsed Snapshot, ported from @camada/core
# src/snapshot/match.ts (itself from edge-analyst src/blocklist.js). Matching is fully
# synchronous and allocation-light; the per-instance scratch of the original is unnecessary
# here because the parsed address travels as a tuple.
#
# Outcome order is contract (contracts §D3, fixtures pin it): the tenant's ordered custom rules
# first (first match wins, the order IS the precedence), then allow -> block -> challenge.
# Within each side the axis order is ip4 -> ip6 -> asn -> country -> tls -> path.
# At the SDK position only ip, path, ua and the request headers are usually known;
# asn/country/tlsx entries and conditions then simply never match — that is the documented,
# honest enforcement scope (fail open, never guess).
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ..ipparse import Words, parse_ip4, parse_ip6
from .parse import CompiledRule, RangeSet, RuleRequest, Snapshot, in_range4, in_range6


@dataclass(slots=True)
class MatchInput:
    ip: str | None = None
    asn: int | None = None
    country: str | None = None
    tlsx: str | None = None
    path: str | None = None
    ua: str | None = None                                   # v5 rules read it; the three sides never do
    header: Callable[[str], str | None] | None = None       # v5 header conditions read it, always with a lower-cased name


@dataclass(slots=True, frozen=True)
class MatchResult:
    block: bool = False
    challenge: bool = False
    allowed: bool = False           # true for skip (which absorbed the old allow) and for the allow side
    warn: bool = False
    action: str | None = None       # the action of the rule that decided, None when a side did
    rule: str | None = None         # the rule id, present only when reason is 'rule'
    reason: str | None = None       # ip4 | ip6 | asn | country | tls | path | rule | cold
    version: str | None = None


def clean_path(raw: str | None) -> str:
    p = raw or "/"
    q = p.find("?")
    return p if q == -1 else p[:q]


def _prefix_hit(prefixes: frozenset[str], path: str) -> bool:
    """Walks every '/'-terminated ancestor of `path`, the way the block side does."""
    i = path.find("/", 1)
    while i != -1:
        if path[: i + 1] in prefixes:
            return True
        i = path.find("/", i + 1)
    return False


def _rule_result(rule: CompiledRule, version: str) -> MatchResult:
    """A rule decided this request (§D3): at most one of allowed / block / challenge / warn is
    true, `reason` is 'rule', and `rule` names the id the adapters stamp on the event."""
    a = rule.action
    return MatchResult(
        block=a == "block", challenge=a == "challenge", allowed=a == "skip", warn=a == "warn",
        action=a, rule=rule.id, reason="rule", version=version,
    )


class Matcher:
    __slots__ = ("snap", "_req")

    def __init__(self, snap: Snapshot) -> None:
        self.snap = snap
        self._req = RuleRequest()   # scratch: filled per match(), read only inside the rule loop

    def _blocked4(self, n: int) -> bool:
        s = self.snap
        b = n >> 8
        if (s.bm4[b >> 5] >> (b & 31)) & 1 == 0:
            return False
        hi = n >> 16
        left, right = s.idx4[hi], s.idx4[hi + 1] - 1
        if left > 0:
            left -= 1
        if right < left:
            return False
        s4 = s.s4
        while left < right:
            m = (left + right + 1) >> 1
            if s4[m] <= n:
                left = m
            else:
                right = m - 1
        return bool(s4[left] <= n <= s.e4[left])

    def _blocked6(self, w: Words) -> bool:
        s = self.snap
        b = w[0] >> 8
        if (s.bm6[b >> 5] >> (b & 31)) & 1 == 0:
            return False
        left, right = 0, s.n6 - 1
        if right < 0:
            return False
        s6 = s.s6
        while left < right:
            m = (left + right + 1) >> 1
            o = m * 4
            if (s6[o], s6[o + 1], s6[o + 2], s6[o + 3]) <= w:
                left = m
            else:
                right = m - 1
        o = left * 4
        e6 = s.e6
        return (s6[o], s6[o + 1], s6[o + 2], s6[o + 3]) <= w <= (e6[o], e6[o + 1], e6[o + 2], e6[o + 3])

    def _blocked_asn(self, asn: int) -> bool:
        s = self.snap
        if asn < 4194304:
            return (s.asn_bm[asn >> 5] >> (asn & 31)) & 1 != 0
        extra = s.asn_extra
        left, right = 0, len(extra) - 1
        while left <= right:
            m = (left + right) >> 1
            v = extra[m]
            if v == asn:
                return True
            if v < asn:
                left = m + 1
            else:
                right = m - 1
        return False

    def _blocked_path(self, path: str) -> bool:
        s = self.snap
        if path in s.paths_exact:
            return True
        if s.paths_prefix and _prefix_hit(s.paths_prefix, path):
            return True
        return any(rx.search(path) for rx in s.paths_regex)

    def _block_side(self, i: MatchInput, n4: int, w: Words | None) -> str | None:
        """The block side: v3 sections plus the top-level meta."""
        s = self.snap
        if n4 >= 0 and self._blocked4(n4):
            return "ip4"
        if w is not None and self._blocked6(w):
            return "ip6"
        if i.asn is not None and self._blocked_asn(i.asn):
            return "asn"
        if i.country and s.country and i.country in s.country:
            return "country"
        if i.tlsx and i.tlsx in s.tls:
            return "tls"
        if (s.paths_exact or s.paths_prefix or s.paths_regex) and self._blocked_path(clean_path(i.path)):
            return "path"
        return None

    @staticmethod
    def _side(st: RangeSet, i: MatchInput, n4: int, w: Words | None) -> str | None:
        """A v4 side list (allow or challenge). No tls axis: §A3's side meta has no tls key."""
        if st.empty:
            return None   # the common v3 snapshot
        if n4 >= 0 and in_range4(st.r4, n4):
            return "ip4"
        if w is not None and in_range6(st.r6, st.n6, w):
            return "ip6"
        if i.asn is not None and i.asn in st.asn:
            return "asn"
        if i.country and i.country in st.country:
            return "country"
        if st.paths_exact or st.paths_prefix:
            p = clean_path(i.path)
            if p in st.paths_exact:
                return "path"
            if st.paths_prefix and _prefix_hit(st.paths_prefix, p):
                return "path"
        return None

    def match(self, i: MatchInput) -> MatchResult:
        s = self.snap
        ip = i.ip or ""
        n4, w = -1, None
        if ip:
            if ":" not in ip:
                n4 = parse_ip4(ip)
            else:
                w = parse_ip6(ip)
        if s.rules:
            r = self._req
            r.n4, r.ip6 = n4, w
            r.asn, r.country, r.tlsx = i.asn, i.country, i.tlsx
            r.path, r.ua, r.header = clean_path(i.path), i.ua, i.header
            for rule in s.rules:   # the order IS the precedence (§A4): first match wins
                for cond in rule.conds:
                    if not cond(r):
                        break
                else:
                    return _rule_result(rule, s.version)
        reason = self._side(s.allow, i, n4, w)
        if reason:
            return MatchResult(allowed=True, reason=reason, version=s.version)
        reason = self._block_side(i, n4, w)
        if reason:
            return MatchResult(block=True, reason=reason, version=s.version)
        reason = self._side(s.challenge, i, n4, w)
        if reason:
            return MatchResult(challenge=True, reason=reason, version=s.version)
        return MatchResult(version=s.version)
