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

# Exact patterns of C6 v3. Matching is ASCII-only (re.ASCII: no Unicode case folding, so U+017F never matches `s` and
# U+212A never matches `k`) and whole-string tests use fullmatch (`$` would match before a trailing newline).
_NAME_RE = re.compile(r"(pass(word)?|tok(en)?|secret|key|api[-_]?key|auth|sess(ion)?|sig(nature)?|code|jwt|bearer|credential)", re.I | re.A)
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}", re.A)   # prefix match: anything may follow
_HEX_RE = re.compile(r"[a-fA-F0-9]{32,}", re.A)
_B64_RE = re.compile(r"[A-Za-z0-9+/_-]{40,}={0,2}", re.A)
_ESC_RE = re.compile(r"%([0-9a-fA-F]{2})", re.A)
_NESTED_SPLIT_RE = re.compile(r"[?&]")

REDACT_ALLOWLIST = ("plan", "role", "locale", "ab_variant")   # additions only, never narrowing


def _suspect_value(v: str) -> bool:
    return bool(_JWT_RE.match(v) or _HEX_RE.fullmatch(v) or _B64_RE.fullmatch(v))


def _decode(s: str) -> str | None:
    """Percent-decoding that never throws: each `%HH` (ASCII hex) becomes that byte as one char (Latin-1), any other
    `%` stays, `+` stays. Up to 4 passes, so double (or triple) encoding cannot hide a name or a nested query; text
    that still holds a `%HH` after 4 passes returns None, which the caller scrubs. Only ever used to TEST a part."""
    for _ in range(4):
        if not _ESC_RE.search(s):
            return s
        s = _ESC_RE.sub(lambda m: chr(int(m.group(1), 16)), s)
    return None if _ESC_RE.search(s) else s


def _cred_segment(seg: str) -> bool:
    eq = seg.find("=")
    return _suspect_value(seg) if eq == -1 else bool(_NAME_RE.search(seg[:eq])) or _suspect_value(seg[eq + 1 :])


def _nested_cred(d: str) -> bool:
    """A decoded value that carries a nested query (`?`, `&` or `=`) is a credential when any of its `[?&]`-separated
    segments is one (C6 v3). `q=a=b` or `q=1' or '1'='1` is not; `next=/r?token=x` is. No further decoding."""
    return any(c in d for c in "?&=") and any(_cred_segment(seg) for seg in _NESTED_SPLIT_RE.split(d))


def scrub_query(query: str | None) -> str:
    """Replaces credential-looking query parts with ~r, preserving structure and order (C6 v3). The string is split on
    `&`, never URL-parsed. Each part's name and value are percent-decoded (_decode) before testing; the output keeps
    the raw text. `name=value` -> `name=~r` when the name looks like a credential, the value looks like one, or the
    value holds a nested query with a credential segment (replaced whole, so payloads like `q=1' or '1'='1` stay
    visible to the scorer). A bare part -> `~r` when it looks like a credential value or holds a credential segment.
    Either half still encoded after 4 decode passes counts as a credential."""
    if not query or len(query) <= 1:
        return query or ""
    lead = "?" if query.startswith("?") else ""
    out = []
    for p in (query[1:] if lead else query).split("&"):
        eq = p.find("=")
        if eq == -1:
            d = _decode(p)
            out.append("~r" if d is None or _suspect_value(d) or _nested_cred(d) else p)
            continue
        name = p[:eq]
        dn, dv = _decode(name), _decode(p[eq + 1 :])
        hit = dn is None or dv is None or _NAME_RE.search(dn) or _suspect_value(dv) or _nested_cred(dv)
        out.append(f"{name}=~r" if hit else p)
    return lead + "&".join(out)


def scrub_url(url: str | None) -> str | None:
    """A URL (a Referer) with its query and fragment run through scrub_query (camada-all-ijsa); the scheme, host and
    path are kept as they are. The path is left alone on purpose: it gets the same treatment as the request's own
    path `p` (none). A same-origin Referer's path already shipped as `p` on that page's own event, and a cross-origin
    one carries only the origin under the browsers' default Referrer-Policy."""
    if url is None:
        return None
    head, hash_, frag = url.partition("#")
    path, q, query = head.partition("?")
    scrubbed = path + scrub_query(q + query) if q else head
    return scrubbed + "#" + scrub_query(frag) if hash_ else scrubbed


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
