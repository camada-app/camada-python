# What only the ASGI host can show: wire header order reaches the event, streaming bodies pass
# untouched, non-http scopes are left alone, and a body camada read is replayed to the app.
from __future__ import annotations

import asyncio
from collections.abc import Iterator
from typing import Any

import pytest

from camada.asgi import CamadaASGI
from camada.engine import Camada

from .fake_analyst import FakeAnalyst
from .hosts import AsgiDriver, Call, engine_with, loaded


@pytest.fixture
def engine() -> Iterator[Camada]:
    a = FakeAnalyst()
    e = engine_with(a)
    e.analyst = a  # type: ignore[attr-defined]
    loaded(e)
    yield e
    e.stop()


def run(app: Any, scope: dict[str, Any], body: bytes = b"") -> list[dict[str, Any]]:
    sent: list[dict[str, Any]] = []
    chunks = [body]

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": chunks.pop(0), "more_body": False} if chunks else {"type": "http.disconnect"}

    async def send(m: dict[str, Any]) -> None:
        sent.append(m)

    asyncio.run(app(scope, receive, send))
    return sent


def test_wire_header_order_reaches_the_event(engine: Camada) -> None:
    d = AsgiDriver(engine)
    d(Call("GET", "/", headers=[("x-b", "1"), ("accept", "*/*"), ("x-a", "2")]))
    engine.queue.flush()  # type: ignore[union-attr]
    (ev,) = engine.analyst.all_events  # type: ignore[attr-defined]
    assert ev["hord"] == "x-b,accept,x-a,content-length,host" or ev["hord"].startswith("x-b,accept,x-a")


def test_streaming_bodies_pass_untouched_and_finish_once(engine: Camada) -> None:
    async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/plain")]})
        for part in (b"a", b"b", b"c"):
            await send({"type": "http.response.body", "body": part, "more_body": True})
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    sent = run(CamadaASGI(app, engine=engine), {"type": "http", "method": "GET", "path": "/s", "headers": [], "client": ("172.16.0.9", 1), "scheme": "http"})
    assert [m.get("body") for m in sent if m["type"] == "http.response.body"] == [b"a", b"b", b"c", b""]
    assert any(k == b"x-rid" for k, _ in sent[0]["headers"])
    engine.queue.flush()  # type: ignore[union-attr]
    evs = engine.analyst.all_events  # type: ignore[attr-defined]
    assert len(evs) == 1 and evs[0]["p"] == "/s" and evs[0]["st"] == 200


def test_lifespan_and_websocket_scopes_pass_through(engine: Camada) -> None:
    seen: list[str] = []

    async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        seen.append(scope["type"])

    for t in ("lifespan", "websocket"):
        asyncio.run(CamadaASGI(app, engine=engine)({"type": t}, None, None))
    assert seen == ["lifespan", "websocket"]


def test_a_body_camada_read_is_replayed_to_the_app(engine: Camada) -> None:
    engine.analyst.config["beacon"] = False  # type: ignore[attr-defined]
    engine.snap.refresh()  # type: ignore[union-attr]
    got: list[bytes] = []

    async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        m = await receive()
        got.append(m["body"])
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    # a beacon POST with the beacon off falls through: the app must still read the body
    scope = {"type": "http", "method": "POST", "path": "/_cam/fp", "headers": [(b"content-length", b"2")], "client": ("172.16.0.9", 1), "scheme": "http"}
    engine2 = engine_with(engine.analyst)  # type: ignore[attr-defined]
    loaded(engine2)
    try:
        sent = run(CamadaASGI(app, engine=engine2), scope, b"{}")
    finally:
        engine2.stop()
    assert sent[-1]["body"] == b"ok" and got == [b"{}"]


def test_route_pattern_reaches_the_event_when_the_host_sets_it(engine: Camada) -> None:
    class R:
        path = "/items/{id}"

    async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        scope["route"] = R()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    run(CamadaASGI(app, engine=engine), {"type": "http", "method": "GET", "path": "/items/7", "headers": [], "client": ("172.16.0.9", 1), "scheme": "http"})
    engine.queue.flush()  # type: ignore[union-attr]
    assert engine.analyst.all_events[0]["rt"] == "/items/{id}"  # type: ignore[attr-defined]
