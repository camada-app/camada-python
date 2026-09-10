# Drivers that run the SDK through each host without a server: a WSGI environ call and an
# ASGI3 scope/receive/send call. The engine suite is parametrized over both so the two hosts
# prove the same contract; host-specific behaviour lives in test_wsgi.py / test_asgi.py.
from __future__ import annotations

import asyncio
import io
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from camada.engine import Camada
from camada.snapshot.match import MatchInput

from .fake_analyst import FakeAnalyst

ENV = {"CAMADA_KEY": "tok-test.snap-test", "CAMADA_INGEST_URL": "https://analyst.test"}


@dataclass
class Reply:
    status: int
    headers: list[tuple[str, str]]
    body: bytes

    def header(self, name: str) -> str | None:
        for k, v in self.headers:
            if k.lower() == name:
                return v
        return None

    def headers_named(self, name: str) -> list[str]:
        return [v for k, v in self.headers if k.lower() == name]

    @property
    def text(self) -> str:
        return self.body.decode()


@dataclass
class Call:
    method: str = "GET"
    path: str = "/"
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    peer: str | None = "172.16.0.9"   # a peer no golden container lists (10.0.0.0/8 is blocked in all of them)
    https: bool = False
    content_length: int | None = None    # override the declared length (None = actual)


AppHandler = Callable[[dict[str, Any]], tuple[int, list[tuple[str, str]], bytes]]
"""A test app: sees the host's request map (environ or scope) and answers (status, headers, body)."""


def engine_with(a: FakeAnalyst, env: dict[str, str] | None = None, **opts: Any) -> Camada:
    return Camada(env={**ENV, **(env or {})}, transport=a.transport, **opts)


def loaded(engine: Camada) -> None:
    assert engine.snap is not None
    for _ in range(400):
        if engine.snap.verdict(MatchInput(ip="0.0.0.0")).reason != "cold":
            return
        time.sleep(0.005)
    raise AssertionError("snapshot never loaded")


def hello(_: dict[str, Any]) -> tuple[int, list[tuple[str, str]], bytes]:
    return 200, [("content-type", "text/plain")], b"hello"


class WsgiDriver:
    name = "wsgi"

    def __init__(self, engine: Camada, handler: AppHandler = hello) -> None:
        from camada.wsgi import CamadaWSGI

        self.seen: list[dict[str, Any]] = []

        def app(environ: dict[str, Any], start_response: Callable[..., Any]) -> Iterable[bytes]:
            self.seen.append(environ)
            status, headers, body = handler(environ)
            start_response(f"{status} X", headers)
            return [body]

        self.app = CamadaWSGI(app, engine=engine)

    def __call__(self, c: Call) -> Reply:
        environ: dict[str, Any] = {
            "REQUEST_METHOD": c.method, "PATH_INFO": c.path.split("?")[0], "QUERY_STRING": c.path.split("?")[1] if "?" in c.path else "",
            "SERVER_PROTOCOL": "HTTP/1.1", "wsgi.url_scheme": "https" if c.https else "http", "wsgi.input": io.BytesIO(c.body),
            "SERVER_NAME": "x.test", "SERVER_PORT": "80",
        }
        if c.peer is not None:
            environ["REMOTE_ADDR"] = c.peer
        if c.method in ("POST", "PUT") or c.body:
            environ["CONTENT_LENGTH"] = str(len(c.body) if c.content_length is None else c.content_length)
        for k, v in c.headers:
            key = k.upper().replace("-", "_")
            key = key if key in ("CONTENT_TYPE", "CONTENT_LENGTH") else "HTTP_" + key
            environ[key] = v if key not in environ else environ[key] + ", " + v
        environ.setdefault("HTTP_HOST", "x.test")
        out: dict[str, Any] = {}

        def start_response(status: str, headers: list[tuple[str, str]], exc_info: Any = None) -> Any:
            out["status"], out["headers"] = int(status.split()[0]), headers
            return lambda _: None

        result = self.app(environ, start_response)
        try:
            body = b"".join(result)
        finally:
            close = getattr(result, "close", None)
            if close:
                close()
        return Reply(out["status"], out["headers"], body)


class AsgiDriver:
    name = "asgi"

    def __init__(self, engine: Camada, handler: AppHandler = hello) -> None:
        from camada.asgi import CamadaASGI

        self.seen: list[dict[str, Any]] = []

        async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
            assert scope["type"] == "http"
            self.seen.append(scope)
            status, headers, body = handler(scope)
            await send({"type": "http.response.start", "status": status, "headers": [(k.encode(), v.encode()) for k, v in headers]})
            await send({"type": "http.response.body", "body": body})

        self.app = CamadaASGI(app, engine=engine)

    def __call__(self, c: Call) -> Reply:
        path, _, query = c.path.partition("?")
        headers = [(k.lower().encode(), v.encode()) for k, v in c.headers]
        if c.method in ("POST", "PUT") or c.body:
            headers.append((b"content-length", str(len(c.body) if c.content_length is None else c.content_length).encode()))
        if not any(k == b"host" for k, _ in headers):
            headers.append((b"host", b"x.test"))
        scope = {
            "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": c.method, "scheme": "https" if c.https else "http",
            "path": path, "raw_path": path.encode(), "query_string": query.encode(), "headers": headers,
            "client": (c.peer, 12345) if c.peer is not None else None, "server": ("x.test", 80),
        }
        messages: list[dict[str, Any]] = []
        chunks = [c.body]

        async def receive() -> dict[str, Any]:
            if chunks:
                return {"type": "http.request", "body": chunks.pop(0), "more_body": False}
            return {"type": "http.disconnect"}

        async def send(m: dict[str, Any]) -> None:
            messages.append(m)

        asyncio.run(self.app(scope, receive, send))
        start = next(m for m in messages if m["type"] == "http.response.start")
        body = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
        return Reply(start["status"], [(k.decode(), v.decode()) for k, v in start["headers"]], body)


DRIVERS = [WsgiDriver, AsgiDriver]
