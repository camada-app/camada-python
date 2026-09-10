# Wire constants and pure helpers for the SDK-served challenge (contracts §D2), ported from
# @camada/core src/challenge/format.ts. Nothing here does crypto; verify.py supplies HMAC and
# SHA-256 from the stdlib, so the format has exactly one definition across the family.
from __future__ import annotations

import hmac
import json
from urllib.parse import unquote

CHALLENGE_COOKIE = "_cch"
CHALLENGE_TTL_MS = 3_600_000   # 1 h (contract)
POW_BITS = 16                  # leading zero bits of SHA-256(f"{nonce}.{solution}")
NONCE_HEX = 32                 # the nonce is the first 32 hex chars of the HMAC
_DAY_MS = 86_400_000
_MAX_RETURN_TO = 2048
_MAX_SOLUTION = 32


def utc_day(now_ms: int) -> int:
    return now_ms // _DAY_MS


# Domain-separated messages: a nonce HMAC can never be replayed as a cookie HMAC.
def nonce_message(ip: str | None, day: int) -> str:
    return f"camada-challenge-nonce|{ip or ''}|{day}"


def token_message(ip: str | None, exp: int) -> str:
    return f"camada-challenge-token|{ip or ''}|{exp}"


def split_token(value: str | None) -> tuple[int, str] | None:
    if not value:
        return None
    dot = value.find(".")
    if dot <= 0:
        return None
    try:
        exp = int(value[:dot])
    except ValueError:
        return None
    mac = value[dot + 1 :]
    return (exp, mac) if mac else None


def safe_equal(a: str, b: str) -> bool:
    """Constant-time for equal-length strings; length itself is not a secret here."""
    return len(a) == len(b) and hmac.compare_digest(a.encode(), b.encode())


def pow_ok(hex_digest: str, bits: int = POW_BITS) -> bool:
    """True when the hex digest starts with `bits` zero bits."""
    nibbles, rest = bits >> 2, bits & 3
    if len(hex_digest) < nibbles + (1 if rest else 0):
        return False
    if any(hex_digest[i] != "0" for i in range(nibbles)):
        return False
    if rest == 0:
        return True
    try:
        v = int(hex_digest[nibbles], 16)
    except ValueError:
        return False
    return (v >> (4 - rest)) == 0


def solution_shape_ok(solution: str | None) -> bool:
    return bool(solution) and len(solution or "") <= _MAX_SOLUTION


def challenge_cookie(value: str, secure: bool) -> str:
    return f"{CHALLENGE_COOKIE}={value}; Path=/; Max-Age={CHALLENGE_TTL_MS // 1000}; HttpOnly; SameSite=Lax{'; Secure' if secure else ''}"


def safe_return_to(raw: str | None) -> str:
    """Only a printable-ASCII same-site absolute path survives: never an absolute URL, a
    protocol-relative '//host' redirect, a control character, or something absurdly long."""
    if not raw or len(raw) > _MAX_RETURN_TO:
        return "/"
    if raw[0] != "/" or (len(raw) > 1 and raw[1] in "/\\"):
        return "/"
    if any(not (0x21 <= ord(c) <= 0x7E) for c in raw):
        return "/"
    return raw


def wants_html(accept: str | None, sec_fetch_dest: str | None) -> bool:
    """A challenge page is only worth serving to a top-level HTML navigation (contract §D2)."""
    if not accept or "text/html" not in accept:
        return False
    return not sec_fetch_dest or sec_fetch_dest == "document"


def escape_attr(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;")


def escape_script(s: str) -> str:
    """Safe to drop inside an inline <script>: `<` is escaped so no value can close the element early."""
    return json.dumps(s).replace("<", "\\u003c")


def parse_form_body(body: str) -> dict[str, str]:
    """application/x-www-form-urlencoded, last value wins. Never raises on junk."""
    out: dict[str, str] = {}
    for pair in body.split("&"):
        if not pair:
            continue
        eq = pair.find("=")
        k = pair if eq == -1 else pair[:eq]
        v = "" if eq == -1 else pair[eq + 1 :]
        out[unquote(k.replace("+", " "))] = unquote(v.replace("+", " "))
    return out
