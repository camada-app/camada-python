# Configuration shapes shared by the client and the engine. `parse_key` splits CAMADA_KEY, and
# `RemoteConfig` is what GET /snapshot hands back in x-camada-config (whitelisted server-side).
from __future__ import annotations

import re
from typing import Any, TypedDict, cast

_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
_TOKEN_HEADER_RE = re.compile(r"[a-z0-9-]{1,64}")
_FORBIDDEN_TOKEN_HEADERS = frozenset({"authorization", "cookie", "set-cookie"})


class TrustedProxy(TypedDict, total=False):
    """Mirrors the server-validated tenant config (edge-analyst src/tenant-config.js):
    {mode: none} | {mode: hops, hops: N} | {mode: cidrs, cidrs: [...], cloudflare?: [...]} | {mode: vercel}."""

    mode: str
    hops: int
    cidrs: list[str]
    cloudflare: list[str]   # set by edge-analyst for Cloudflare-fronted origins: which trusted cidrs are Cloudflare edges


class RemoteConfig(TypedDict, total=False):
    tenant: str
    beacon: bool
    sample: float
    exclude: list[str]
    trusted_proxy: TrustedProxy
    poll_seconds: float


def parse_key(key: str | None) -> tuple[str, str] | None:
    """CAMADA_KEY is `<ingest_token>.<snap_token>` (printed by reconcile instructions and seed)."""
    if not key:
        return None
    dot = key.find(".")
    if dot <= 0 or dot == len(key) - 1:
        return None
    return key[:dot], key[dot + 1 :]


def resolve_token_hash(option: bool | None, env: str | None) -> bool:
    return option if option is not None else env == "1"


def resolve_token_header(option: str | None, env: str | None) -> tuple[str | None, bool]:
    """Return the normalized extra header and whether the selected name was rejected."""
    selected = option or env
    if not selected:
        return None, False
    name = selected.translate(_ASCII_LOWER)
    if not _TOKEN_HEADER_RE.fullmatch(name) or name in _FORBIDDEN_TOKEN_HEADERS:
        return None, True
    return name, False


def parse_trusted_proxy_env(v: str | None) -> TrustedProxy | None:
    """CAMADA_TRUSTED_PROXY: none | vercel | hops:N | cidrs:a,b. Unset or malformed returns None,
    which callers treat as "defer to the server-delivered tenant config", never as trust."""
    if not v:
        return None
    if v == "none":
        return {"mode": "none"}
    if v == "vercel":
        return {"mode": "vercel"}
    if v.startswith("hops:"):
        try:
            hops = int(v[5:])
        except ValueError:
            return None
        return {"mode": "hops", "hops": hops} if hops >= 1 else None
    if v.startswith("cidrs:"):
        cidrs = [c.strip() for c in v[6:].split(",") if c.strip()]
        return {"mode": "cidrs", "cidrs": cidrs} if cidrs else None
    return None


def remote_config(raw: Any) -> RemoteConfig | None:
    """The parsed x-camada-config header; anything but a JSON object is ignored (previous kept)."""
    return cast(RemoteConfig, raw) if isinstance(raw, dict) else None
