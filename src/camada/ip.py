# Client-IP resolution under the tenant's trusted-proxy config. The default is the socket peer:
# raw X-Forwarded-For is attacker-writable and is NEVER trusted without explicit configuration;
# a spoofed XFF must not reach the analysis or the blocklist. Ported from @camada/core src/ip.ts.
from __future__ import annotations

import re
from dataclasses import dataclass

from .config import TrustedProxy
from .ipparse import Words, parse_ip4, parse_ip6


@dataclass(slots=True, frozen=True)
class _Cidr:
    base4: int          # v4 base, or -1
    base6: Words | None
    bits: int


def _valid_ip(s: str) -> bool:
    return parse_ip4(s) >= 0 if ":" not in s else parse_ip6(s) is not None


_PORT_RE = re.compile(r":[0-9]{1,5}")


def _strip_port(e: str) -> str:
    """One X-Forwarded-For entry without its port (camada-all-0vho): `[v6]:port` and `[v6]` -> `v6`, `a.b.c.d:port` ->
    `a.b.c.d`. A bare IPv6 literal comes back whole (its last group is never a port); anything else malformed comes
    back unchanged, so validation still rejects it and the peer wins."""
    if e.startswith("["):
        close = e.find("]")
        if close == -1:
            return e
        inner, rest = e[1:close], e[close + 1 :]
        return inner if ":" in inner and (rest == "" or _PORT_RE.fullmatch(rest)) else e
    colon = e.find(":")
    if colon == -1 or e.find(":", colon + 1) != -1:
        return e   # no colon, or a bare IPv6 literal
    host = e[:colon]
    return host if parse_ip4(host) >= 0 and _PORT_RE.fullmatch(e[colon:]) else e


def _is_loopback(ip: str) -> bool:
    """127.0.0.0/8 or ::1 (camada-all-yfc6, decision D1). The peer's `::ffff:127.x.x.x` form is already reduced to the
    dotted quad by resolve_client_ip."""
    if ":" not in ip:
        n = parse_ip4(ip)
        return n >= 0 and n >> 24 == 127
    return parse_ip6(ip) == (0, 0, 0, 1)


def _entries(xff: str | None) -> list[str]:
    return [e for e in (_strip_port(x.strip()) for x in (xff or "").split(",")) if e]


def _parse_cidrs(cidrs: list[str]) -> list[_Cidr]:
    return [c for c in (_parse_cidr(x) for x in cidrs) if c is not None]


def _untrusted_peer(sock: str | None, trusted: list[_Cidr]) -> bool:
    """The cidrs chain is [...xff, peer]: a peer that is neither loopback nor a trusted proxy did not come through one,
    so it IS the client and XFF (anyone's to write on a direct hit) must not be read."""
    return sock is not None and not _is_loopback(sock) and not any(_in_cidr(sock, t) for t in trusted)


def _parse_cidr(c: str) -> _Cidr | None:
    slash = c.find("/")
    if slash == -1:
        return None
    addr = c[:slash]
    try:
        bits = int(c[slash + 1 :])
    except ValueError:
        return None
    if ":" not in addr:
        base = parse_ip4(addr)
        return _Cidr(base, None, bits) if base >= 0 and 0 <= bits <= 32 else None
    words = parse_ip6(addr)
    return _Cidr(-1, words, bits) if words is not None and 0 <= bits <= 128 else None


def _in_cidr(ip: str, cidr: _Cidr) -> bool:
    if cidr.base6 is None:
        n = parse_ip4(ip)
        if n < 0:
            return False
        bits = cidr.bits
        mask = 0 if bits == 0 else (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
        return (n & mask) == (cidr.base4 & mask)
    words = parse_ip6(ip)
    if words is None:
        return False
    base = cidr.base6
    remaining = cidr.bits
    for k in range(4):
        if remaining <= 0:
            break
        take = min(32, remaining)
        mask = 0xFFFFFFFF if take == 32 else (0xFFFFFFFF << (32 - take)) & 0xFFFFFFFF
        if (words[k] & mask) != (base[k] & mask):
            return False
        remaining -= take
    return True


def resolve_client_ip(peer: str | None, xff: str | None, cfg: TrustedProxy | None, cf_ip: str | None = None) -> str | None:
    """The client IP from the socket peer and X-Forwarded-For per the trusted-proxy config.
    Anything unresolvable falls back to the peer (fail safe). `cf_ip` is CF-Connecting-IP: read only
    under a `cloudflare` list, and only when the hop in front of the client is one of those edges.

    XFF entries are read without a port (`ip:port`, `[v6]:port`, as Azure writes them) in every mode.

    `cidrs` (also what the dashboard's Cloudflare option stores) walks the chain `[...xff, peer]` from the right: if
    the peer is not a trusted proxy, the request did not come through one and the peer IS the client; XFF is ignored,
    since anyone hitting the origin directly can write it. A loopback peer (127.0.0.0/8, ::1, ::ffff:127.x.x.x) counts
    as a trusted hop: it is a local front end or sidecar (App Engine's is always 127.0.0.1), and no remote client can
    be one. Loopback is trusted only as the peer, never as an XFF entry. With no peer at all (`peer` None: a host that
    exposes no socket) the walk runs over XFF alone: such a host trusts its network edge to have written XFF, and the
    app must not be reachable around that edge. `hops` and `vercel` trust XFF by definition and ignore the peer."""
    sock = peer[7:] if peer and peer[:7].lower() == "::ffff:" else (peer or None)   # dual-stack v4-mapped form
    if cfg and cfg.get("mode") == "cidrs" and cfg.get("cloudflare") and cf_ip:
        via_cf = _cloudflare_client(sock, xff, cfg, cf_ip)
        if via_cf:
            return via_cf
    if not cfg or cfg.get("mode") == "none" or not xff:
        return sock
    entries = _entries(xff)
    if not entries:
        return sock
    candidate: str | None = None
    mode = cfg.get("mode")
    if mode == "hops":
        hops = int(cfg.get("hops", 0))
        if 1 <= hops <= len(entries):
            candidate = entries[len(entries) - hops]
    elif mode == "vercel":
        candidate = entries[-1]   # Vercel overwrites XFF, so its rightmost entry is trustworthy
    elif mode == "cidrs":
        trusted = _parse_cidrs(cfg.get("cidrs", []))
        if _untrusted_peer(sock, trusted):
            return sock   # the peer is the first hop
        for entry in reversed(entries):
            if not any(_in_cidr(entry, t) for t in trusted):
                candidate = entry
                break
    return candidate if candidate and _valid_ip(candidate) else sock


def _cloudflare_client(sock: str | None, xff: str | None, cfg: TrustedProxy, cf_ip: str) -> str | None:
    """CF-Connecting-IP when a Cloudflare edge provably forwarded the request, else None. The chain is `[...xff, peer]`,
    as in the cidrs walk: a peer outside every trusted range (and not loopback) is a direct hit, so the header is never
    read (camada-all-yfc6). Otherwise walk from the right past the tenant's own trusted hops (a loopback peer is one);
    the first hop that is not the tenant's own must be a Cloudflare edge."""
    cf_ip = cf_ip.strip()
    if not _valid_ip(cf_ip):
        return None
    if _untrusted_peer(sock, _parse_cidrs(cfg.get("cidrs", []))):
        return None
    edges = _parse_cidrs(cfg.get("cloudflare", []))
    edge_set = set(cfg.get("cloudflare", []))
    own = _parse_cidrs([x for x in cfg.get("cidrs", []) if x not in edge_set])
    chain = _entries(xff)
    if sock is not None and not _is_loopback(sock):
        chain.append(sock)   # a trusted peer: the CF edge itself, or one of the tenant's own hops
    for hop in reversed(chain):
        if any(_in_cidr(hop, t) for t in own):
            continue
        return cf_ip if any(_in_cidr(hop, t) for t in edges) else None
    return None
