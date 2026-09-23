# Client-IP resolution under the tenant's trusted-proxy config. The default is the socket peer:
# raw X-Forwarded-For is attacker-writable and is NEVER trusted without explicit configuration;
# a spoofed XFF must not reach the analysis or the blocklist. Ported from @camada/core src/ip.ts.
from __future__ import annotations

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
    under a `cloudflare` list, and only when the hop in front of the client is one of those edges."""
    sock = peer[7:] if peer and peer.startswith("::ffff:") else peer   # dual-stack v4-mapped form
    if cfg and cfg.get("mode") == "cidrs" and cfg.get("cloudflare") and cf_ip:
        via_cf = _cloudflare_client(sock, xff, cfg, cf_ip)
        if via_cf:
            return via_cf
    if not cfg or cfg.get("mode") == "none" or not xff:
        return sock
    entries = [e.strip() for e in xff.split(",") if e.strip()]
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
        trusted = [c for c in (_parse_cidr(x) for x in cfg.get("cidrs", [])) if c is not None]
        for entry in reversed(entries):
            if not any(_in_cidr(entry, t) for t in trusted):
                candidate = entry
                break
    return candidate if candidate and _valid_ip(candidate) else sock


def _cloudflare_client(sock: str | None, xff: str | None, cfg: TrustedProxy, cf_ip: str) -> str | None:
    """CF-Connecting-IP when a Cloudflare edge provably forwarded the request, else None. Walk X-Forwarded-For
    from the right past the tenant's own trusted hops (the peer stands in only when there is no XFF, as in the
    cidrs walk); the first hop that is not the tenant's own must be a Cloudflare edge. A direct hit on the
    origin fails that test, so its forged header is ignored."""
    cf_ip = cf_ip.strip()
    if not _valid_ip(cf_ip):
        return None
    edges = [c for c in (_parse_cidr(x) for x in cfg.get("cloudflare", [])) if c is not None]
    edge_set = set(cfg.get("cloudflare", []))
    own = [c for c in (_parse_cidr(x) for x in cfg.get("cidrs", []) if x not in edge_set) if c is not None]
    chain = [e.strip() for e in (xff or "").split(",") if e.strip()] or ([sock] if sock else [])
    for hop in reversed(chain):
        if any(_in_cidr(hop, t) for t in own):
            continue
        return cf_ip if any(_in_cidr(hop, t) for t in edges) else None
    return None
