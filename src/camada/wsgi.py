# WSGI middleware: the lower tier the SDK plan documents (environ loses wire header order, so
# the analyst reads no HEADER_ORDER signal from this tap), and what Django and Flask sit on.
from __future__ import annotations

import io
from collections.abc import Callable, Iterable, Iterator
from typing import Any

from .engine import Answer, Camada, Passed, Req, cookie_value  # noqa: F401 — cookie_value re-exported for integrations
from .guarded import log_rate_limited

StartResponse = Callable[..., Any]
WSGIApp = Callable[[dict[str, Any], StartResponse], Iterable[bytes]]


def req_from_environ(environ: dict[str, Any]) -> Req:
    headers: list[tuple[str, str]] = []
    for k, v in environ.items():
        if k.startswith("HTTP_"):
            headers.append((k[5:].lower().replace("_", "-"), str(v)))
        elif k in ("CONTENT_TYPE", "CONTENT_LENGTH") and v:
            headers.append((k.lower().replace("_", "-"), str(v)))
    query = environ.get("QUERY_STRING") or ""
    proto = str(environ.get("SERVER_PROTOCOL") or "")
    return Req(
        method=str(environ.get("REQUEST_METHOD") or "GET"),
        path=str(environ.get("PATH_INFO") or "/"),
        query="?" + query if query else "",
        host=str(environ.get("HTTP_HOST") or environ.get("SERVER_NAME") or ""),
        http_version=proto[5:] if proto.startswith("HTTP/") else None,
        peer=environ.get("REMOTE_ADDR") or None,
        https=environ.get("wsgi.url_scheme") == "https",
        headers=headers,
    )


def read_body(environ: dict[str, Any], limit: int) -> bytes | None:
    """At most `limit` bytes, or None when the declared or actual size exceeds it. Whatever was
    read is put back so an app the request falls through to still sees its body."""
    try:
        declared = int(environ.get("CONTENT_LENGTH") or 0)
    except ValueError:
        declared = 0
    if declared > limit:
        return None
    stream = environ.get("wsgi.input")
    data = stream.read(limit + 1) if stream is not None else b""
    environ["wsgi.input"] = io.BytesIO(data)
    return None if len(data) > limit else data


class _Closing:
    """Wraps the app's iterable so on_finish fires exactly once, after the last byte or on close()."""

    def __init__(self, inner: Iterable[bytes], done: Callable[[], None]) -> None:
        self._inner, self._done, self._fired = inner, done, False

    def __iter__(self) -> Iterator[bytes]:
        try:
            yield from self._inner
        finally:
            self.close()

    def close(self) -> None:
        try:
            close = getattr(self._inner, "close", None)
            if close:
                close()
        finally:
            if not self._fired:
                self._fired = True
                self._done()


class CamadaWSGI:
    """`app.wsgi_app = CamadaWSGI(app.wsgi_app)`. Without an engine it wires the lazy default
    from the environment on first request."""

    def __init__(self, app: WSGIApp, engine: Camada | None = None, **opts: Any) -> None:
        self.app = app
        self._engine = engine
        self._opts = opts

    @property
    def engine(self) -> Camada:
        if self._engine is None:
            from . import get_default

            self._engine = get_default(**self._opts)
        return self._engine

    def __call__(self, environ: dict[str, Any], start_response: StartResponse) -> Iterable[bytes]:
        eng = self.engine
        try:
            req = req_from_environ(environ)
            limit = eng.wants_body(req.method, req.path)
            body = read_body(environ, limit) if limit is not None else None
        except Exception as err:   # noqa: BLE001
            log_rate_limited(err)
            return self.app(environ, start_response)
        result = eng.handle(req, body)
        if isinstance(result, Answer):
            start_response(f"{result.status} {result.reason}", [*result.headers, ("content-length", str(len(result.body)))])
            return [result.body]
        return self._run(environ, start_response, result)

    def _run(self, environ: dict[str, Any], start_response: StartResponse, p: Passed) -> Iterable[bytes]:
        if p.ctx is not None:
            environ["camada"] = p.ctx
        status_seen = {"status": 500}

        def sr(status: str, headers: list[tuple[str, str]], exc_info: Any = None) -> Any:
            try:
                status_seen["status"] = int(status.split(" ", 1)[0])
                if p.rid:
                    headers = [*headers, ("x-rid", p.rid)]
                if p.set_cookie:
                    headers = [*headers, ("set-cookie", p.set_cookie)]
            except Exception as err:   # noqa: BLE001
                log_rate_limited(err)
            return start_response(status, headers, exc_info) if exc_info is not None else start_response(status, headers)

        def done() -> None:
            if p.on_finish:
                p.on_finish(status_seen["status"])

        try:
            result = self.app(environ, sr)
        except BaseException:
            if p.on_finish:
                p.on_finish(500)   # the app raised: the server will answer 500
            raise
        return _Closing(result, done)
