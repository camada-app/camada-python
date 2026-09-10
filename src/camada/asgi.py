# ASGI3 middleware: the first-class tier (scope["headers"] keeps the wire's header order), and
# what FastAPI / Starlette sit on. A pure ASGI callable — never Starlette's BaseHTTPMiddleware,
# which buffers streaming responses. Only http scopes are touched; lifespan and websocket pass.
from __future__ import annotations

from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

from .engine import Answer, Camada, Passed, Req
from .guarded import log_rate_limited

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


def req_from_scope(scope: Scope) -> Req:
    headers = [(k.decode("latin-1").lower(), v.decode("latin-1")) for k, v in scope.get("headers") or ()]
    query = (scope.get("query_string") or b"").decode("latin-1")
    client = scope.get("client")
    host = next((v for k, v in headers if k == "host"), "") or ":".join(str(x) for x in (scope.get("server") or ())[:1])
    return Req(
        method=str(scope.get("method") or "GET"),
        path=str(scope.get("path") or "/"),
        query="?" + query if query else "",
        host=host,
        http_version=scope.get("http_version"),
        peer=client[0] if client else None,
        https=scope.get("scheme") == "https",
        headers=headers,
    )


async def read_body(scope: Scope, receive: Receive, limit: int) -> tuple[bytes | None, Receive]:
    """At most `limit` bytes (None when the declared or actual size exceeds it), plus a receive()
    that replays what was consumed so an app the request falls through to still sees its body."""
    try:
        declared = int(next((v for k, v in scope.get("headers") or () if k == b"content-length"), b"0") or 0)
    except ValueError:
        declared = 0
    chunks: list[Message] = []
    if declared > limit:
        return None, _replay(chunks, receive)
    size = 0
    over = False
    while True:
        m = await receive()
        chunks.append(m)
        if m["type"] != "http.request":
            break
        size += len(m.get("body") or b"")
        if size > limit:
            over = True
            break
        if not m.get("more_body"):
            break
    body = None if over else b"".join(bytes(m.get("body") or b"") for m in chunks if m["type"] == "http.request")
    return body, _replay(chunks, receive)


def _replay(chunks: list[Message], receive: Receive) -> Receive:
    queued = list(chunks)

    async def replay() -> Message:
        return queued.pop(0) if queued else await receive()

    return replay


class CamadaASGI:
    """`app.add_middleware(CamadaASGI)` (Starlette/FastAPI) or `app = CamadaASGI(app)`. Without an
    engine it wires the lazy default from the environment on first request."""

    def __init__(self, app: ASGIApp, engine: Camada | None = None, **opts: Any) -> None:
        self.app = app
        self._engine = engine
        self._opts = opts

    @property
    def engine(self) -> Camada:
        if self._engine is None:
            from . import get_default

            self._engine = get_default(**self._opts)
        return self._engine

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        eng = self.engine
        try:
            req = req_from_scope(scope)
            limit = eng.wants_body(req.method, req.path)
            body = None
            if limit is not None:
                body, receive = await read_body(scope, receive, limit)
        except Exception as err:   # noqa: BLE001
            log_rate_limited(err)
            await self.app(scope, receive, send)
            return
        result = eng.handle(req, body)
        if isinstance(result, Answer):
            headers = [(k.encode("latin-1"), v.encode("latin-1")) for k, v in result.headers]
            headers.append((b"content-length", str(len(result.body)).encode()))
            await send({"type": "http.response.start", "status": result.status, "headers": headers})
            await send({"type": "http.response.body", "body": result.body})
            return
        await self._run(scope, receive, send, result)

    async def _run(self, scope: Scope, receive: Receive, send: Send, p: Passed) -> None:
        if p.ctx is not None:
            scope["camada"] = p.ctx
        state = {"status": 500, "fired": False}

        def finish(status: int) -> None:
            if state["fired"] or not p.on_finish:
                return
            state["fired"] = True
            if p.ctx is not None and p.ctx.get("_req") is not None:
                route = scope.get("route")
                p.ctx["_req"].route = getattr(route, "path", None) if route is not None else None
            p.on_finish(status)

        async def send_wrapper(m: Message) -> None:
            if m["type"] == "http.response.start":
                try:
                    state["status"] = int(m.get("status", 200))
                    headers = list(m.get("headers") or [])
                    if p.rid:
                        headers.append((b"x-rid", p.rid.encode()))
                    if p.set_cookie:
                        headers.append((b"set-cookie", p.set_cookie.encode("latin-1")))
                    m["headers"] = headers
                except Exception as err:   # noqa: BLE001
                    log_rate_limited(err)
            await send(m)
            if m["type"] == "http.response.body" and not m.get("more_body"):
                finish(int(state["status"]))

        try:
            await self.app(scope, receive, send_wrapper)
        except BaseException:
            finish(500)
            raise
        finally:
            finish(int(state["status"]))
