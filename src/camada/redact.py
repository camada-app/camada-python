# Redaction, non-configurable-off. The SDK never ships: Authorization/Cookie values (scheme
# only, events/build.py), body field values (shape only), query params that look like
# credentials, or raw user identifiers (HMAC-hashed here, inside the SDK, before anything
# reaches the queue). Ported from @camada/core src/redact.ts.
from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any

_NAME_RE = re.compile(r"(pass(word)?|tok(en)?|secret|key|api[-_]?key|auth|sess(ion)?|sig(nature)?|code|jwt|bearer|credential)", re.I)
_JWT_RE = re.compile(r"^eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}")
_HEX_RE = re.compile(r"^[a-f0-9]{32,}$", re.I)
_B64_RE = re.compile(r"^[A-Za-z0-9+/_-]{40,}={0,2}$")

REDACT_ALLOWLIST = ("plan", "role", "locale", "ab_variant")   # additions only, never narrowing


def _suspect_value(v: str) -> bool:
    return bool(_JWT_RE.match(v) or _HEX_RE.match(v) or _B64_RE.match(v))


def scrub_query(query: str | None) -> str:
    """Replaces credential-looking query values with ~r, preserving structure and order."""
    if not query or len(query) <= 1:
        return query or ""
    lead = "?" if query.startswith("?") else ""
    out = []
    for p in (query[1:] if lead else query).split("&"):
        eq = p.find("=")
        if eq == -1:
            out.append(p)
            continue
        name, value = p[:eq], p[eq + 1 :]
        out.append(f"{name}=~r" if _NAME_RE.search(name) or _suspect_value(value) else p)
    return lead + "&".join(out)


def body_shape(obj: Any) -> dict[str, int] | None:
    """Body shape only: field names and byte sizes, never values. One level deep."""
    if not isinstance(obj, dict):
        return None
    out: dict[str, int] = {}
    for k, v in obj.items():
        if isinstance(v, str):
            out[str(k)] = len(v)
        elif v is None:
            out[str(k)] = 0
        else:
            try:
                out[str(k)] = len(json.dumps(v, separators=(",", ":")))
            except (TypeError, ValueError):
                out[str(k)] = 0
    return out


def hash_user_id(user_id: str, ingest_token: str) -> str:
    """Stable per-tenant pseudonym: HMAC-SHA256 keyed by the ingest token, labelled so the hash
    can never double as anything else, truncated to 32 hex chars. The raw identifier never leaves."""
    return hmac.new(ingest_token.encode(), b"uid:" + user_id.encode(), hashlib.sha256).hexdigest()[:32]
