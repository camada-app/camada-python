# Wire-event builder: reproduces the collector's record() (edge-analyst
# workers/collector/edge-collector.js) from a normalized request, so events are comparable
# across taps. HDRS bit order is pinned by the shared fixture (hdrs.json) — never reorder.
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from ..config import _ASCII_LOWER
from ..redact import TokenHash, scrub_query, scrub_url, select_credential
from ..redact import auth_scheme as auth_scheme

HDRS: tuple[str, ...] = (
    "accept", "accept-language", "accept-encoding", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest",
    "sec-fetch-user", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "upgrade-insecure-requests", "dnt",
    "cache-control", "pragma", "referer", "origin", "cookie", "authorization", "x-requested-with", "content-type",
    "via", "x-forwarded-for", "priority", "sec-purpose", "save-data", "te", "if-modified-since", "if-none-match",
)
_HDR_BIT = {name: 1 << i for i, name in enumerate(HDRS)}


@dataclass(slots=True)
class RequestInfo:
    method: str
    host: str
    path: str
    query: str = ""                                # includes the leading '?', or empty
    headers: list[tuple[str, str]] | None = None   # in the order the host gives them (wire order under ASGI)
    ip: str | None = None                          # already resolved via trusted-proxy config
    http_version: str | None = None                # e.g. '1.1'


def now_ms() -> int:
    return int(time.time() * 1000)


def build_wire_event(
    r: RequestInfo, *, tap: str, rid: str, sid: str | None = None, new_session: bool = False, ja4: str | None = None,
    token: TokenHash | None = None,
) -> dict[str, Any]:
    """The caller fills st/dur before enqueueing."""
    mask = hn = hb = 0
    cookie = ""
    names: list[str] = []
    first: dict[str, str] = {}
    for name, value in r.headers or ():
        k = name.lower() if name.isascii() else name.translate(_ASCII_LOWER)
        hn += 1
        hb += len(name) + len(value)
        names.append(k)
        if k not in first:
            first[k] = value
        mask |= _HDR_BIT.get(k, 0)
        if k == "cookie":
            cookie = cookie + "; " + value if cookie else value
    h = first.get
    query = r.query or ""
    qn = len([p for p in query[1:].split("&") if p]) if len(query) > 1 else 0
    ev: dict[str, Any] = {
        "tap": tap, "rid": rid, "sid": sid, "ns": 1 if new_session else 0, "ts": now_ms(),
        "ip": r.ip,
        "proto": f"HTTP/{r.http_version}" if r.http_version else None,
        "m": r.method, "h": r.host, "p": r.path, "q": scrub_query(query)[:512], "qn": qn,
        "ct": h("content-type"), "cl": h("content-length"),
        "ua": h("user-agent"), "chua": h("sec-ch-ua"), "chmob": h("sec-ch-ua-mobile"), "chplat": h("sec-ch-ua-platform"),
        "acc": h("accept"), "lang": h("accept-language"), "fs": h("sec-fetch-site"), "fm": h("sec-fetch-mode"),
        # ref: the Referer's query and fragment are scrubbed like q (camada-all-ijsa), so the last page's token stays here
        "fd": h("sec-fetch-dest"), "fu": h("sec-fetch-user"), "ref": scrub_url(h("referer")), "org": h("origin"),
        "xrw": h("x-requested-with"), "auth": auth_scheme(h("authorization")),   # scheme only, never the credential
        "hm": mask, "hn": hn, "hb": hb, "ck": len(cookie.split(";")) if cookie else 0,
        "hord": ",".join(names)[:2048],   # header order as this host reports it (true wire order under ASGI only)
    }
    if ja4:
        ev["ja4"] = ja4
    if token is not None:
        try:
            candidate = select_credential(first, token.header)
            if candidate is not None:
                ev["tk"] = token.hash(candidate)
        except Exception:
            pass   # token telemetry must preserve the row and the verdict
    ev["st"] = None
    ev["dur"] = None   # 'dur': the collector wire already claims 'lat' for latitude
    return ev
