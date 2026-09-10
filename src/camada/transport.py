# The one HTTP seam. The engine, the snapshot client and the event queue speak to the analyst
# through a Transport callable, so tests inject an in-process fake and production uses the
# stdlib. A transport never raises: a network failure is a status-0 response, which every
# caller treats as "keep what we have".
from __future__ import annotations

import gzip
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field


@dataclass(slots=True)
class HttpRequest:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes | None = None
    timeout_s: float = 3.0


@dataclass(slots=True)
class HttpResponse:
    status: int                           # 0 when the request never got an answer
    headers: dict[str, str]               # lower-cased names
    body: bytes


Transport = Callable[[HttpRequest], HttpResponse]


def urllib_transport(req: HttpRequest) -> HttpResponse:
    """urllib.request over the stdlib, gzip-aware (GET /snapshot ships ~5 MB that gzips to a few KB)."""
    r = urllib.request.Request(req.url, data=req.body, method=req.method, headers=req.headers)
    try:
        with urllib.request.urlopen(r, timeout=req.timeout_s) as res:   # noqa: S310 — scheme is the configured analyst URL
            return _response(res.status, dict(res.headers.items()), res.read())
    except urllib.error.HTTPError as e:
        try:
            body = e.read()
        except Exception:
            body = b""
        return _response(e.code, dict(e.headers.items()), body)
    except Exception:
        return HttpResponse(0, {}, b"")


def _response(status: int, headers: dict[str, str], body: bytes) -> HttpResponse:
    lower = {k.lower(): v for k, v in headers.items()}
    if lower.get("content-encoding", "").lower() == "gzip":
        try:
            body = gzip.decompress(body)
        except Exception:
            return HttpResponse(0, lower, b"")   # a body we cannot read is no answer at all
        lower.pop("content-encoding", None)
    return HttpResponse(status, lower, body)
