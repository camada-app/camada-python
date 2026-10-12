# What only the ASGI host can show: wire header order reaches the event, streaming bodies pass
# untouched, non-http scopes are left alone, and a body camada read is replayed to the app.
from __future__ import annotations

import asyncio
from typing import Any

from camada.asgi import CamadaASGI, req_from_scope
from camada.engine import Camada
from camada.ip import resolve_client_ip

from .fake_analyst import FakeAnalyst
from .hosts import AsgiDriver, Call


def run(app: Any, scope: dict[str, Any], body: bytes = b"") -> list[dict[str, Any]]:
    sent: list[dict[str, Any]] = []
    chunks = [body]

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": chunks.pop(0), "more_body": False} if chunks else {"type": "http.disconnect"}

    async def send(m: dict[str, Any]) -> None:
        sent.append(m)

    asyncio.run(app(scope, receive, send))
    return sent


def test_wire_header_order_reaches_the_event(engine: Camada, analyst: FakeAnalyst) -> None:
    d = AsgiDriver(engine)
    d(Call("GET", "/", headers=[("x-b", "1"), ("accept", "*/*"), ("x-a", "2")]))
    engine.queue.flush()  # type: ignore[union-attr]
    (ev,) = analyst.all_events
    assert ev["hord"].startswith("x-b,accept,x-a")


def test_streaming_bodies_pass_untouched_and_finish_once(engine: Camada, analyst: FakeAnalyst) -> None:
    async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/plain")]})
        for part in (b"a", b"b", b"c"):
            await send({"type": "http.response.body", "body": part, "more_body": True})
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    sent = run(CamadaASGI(app, engine=engine), {"type": "http", "method": "GET", "path": "/s", "headers": [], "client": ("172.16.0.9", 1), "scheme": "http"})
    assert [m.get("body") for m in sent if m["type"] == "http.response.body"] == [b"a", b"b", b"c", b""]
    assert any(k == b"x-rid" for k, _ in sent[0]["headers"])
    engine.queue.flush()  # type: ignore[union-attr]
    evs = analyst.all_events
    assert len(evs) == 1 and evs[0]["p"] == "/s" and evs[0]["st"] == 200


def test_lifespan_and_websocket_scopes_pass_through(engine: Camada) -> None:
    seen: list[str] = []

    async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        seen.append(scope["type"])

    for t in ("lifespan", "websocket"):
        asyncio.run(CamadaASGI(app, engine=engine)({"type": t}, None, None))
    assert seen == ["lifespan", "websocket"]


def test_a_body_camada_read_is_replayed_to_the_app(engine: Camada, analyst: FakeAnalyst) -> None:
    analyst.config["beacon"] = False
    engine.snap.refresh()  # type: ignore[union-attr]
    got: list[bytes] = []

    async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        m = await receive()
        got.append(m["body"])
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    # a beacon POST with the beacon off falls through: the app must still read the body
    scope = {"type": "http", "method": "POST", "path": "/_cam/fp", "headers": [(b"content-length", b"2")], "client": ("172.16.0.9", 1), "scheme": "http"}
    sent = run(CamadaASGI(app, engine=engine), scope, b"{}")
    assert sent[-1]["body"] == b"ok" and got == [b"{}"]


def test_route_pattern_reaches_the_event_when_the_host_sets_it(engine: Camada, analyst: FakeAnalyst) -> None:
    class R:
        path = "/items/{id}"

    async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        scope["route"] = R()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    run(CamadaASGI(app, engine=engine), {"type": "http", "method": "GET", "path": "/items/7", "headers": [], "client": ("172.16.0.9", 1), "scheme": "http"})
    engine.queue.flush()  # type: ignore[union-attr]
    assert analyst.all_events[0]["rt"] == "/items/{id}"


def test_cookies_split_over_several_fields_still_join_the_session(engine: Camada, analyst: FakeAnalyst) -> None:
    # HTTP/2 clients send one cookie per field; node:http joins them with '; ' and so does Req.header
    d = AsgiDriver(engine)
    d(Call("GET", "/", headers=[("cookie", "a=1"), ("cookie", "_sfp=abc")]))
    d(Call("GET", "/", headers=[("cookie", "a=1"), ("cookie", "_sfp=abc")]))
    engine.queue.flush()  # type: ignore[union-attr]
    assert [(e["sid"], e["ns"]) for e in analyst.all_events] == [("abc", 0), ("abc", 0)]


def test_peer_rule_unix_socket_listener_walks_and_unreadable_peer_is_none() -> None:
    # C6 v3 peer table: uvicorn --uds gives no client (or ""), so cidrs walks XFF alone; a client host that is not an
    # ip could not be read, and the result is None, never the XFF walk.
    cfg: Any = {"mode": "cidrs", "cidrs": ["172.64.0.0/13"]}
    base = {"type": "http", "method": "GET", "path": "/", "headers": [(b"x-forwarded-for", b"198.51.100.9, 172.64.1.1")]}
    for scope in ({**base}, {**base, "client": None}, {**base, "client": ("", 0)}):
        req = req_from_scope(scope)
        assert req.peer is None
        assert resolve_client_ip(req.peer, req.header("x-forwarded-for"), cfg) == "198.51.100.9"
    req = req_from_scope({**base, "client": ("/run/app.sock", 0)})
    assert resolve_client_ip(req.peer, req.header("x-forwarded-for"), cfg) is None


def test_a_server_that_rewrites_the_peer_from_xff_hands_camada_the_forged_entry() -> None:
    # Documents RA-3 (README "Proxies that rewrite the peer"): uvicorn's proxy headers (on by default) with
    # FORWARDED_ALLOW_IPS='*' trusts every hop and sets scope["client"] to the leftmost X-Forwarded-For entry, which the
    # client wrote. On Trialsights' chain camada then sees 6.6.6.6 as the socket peer: not a trusted proxy, so it is the
    # client, and the real client (198.51.100.9) is lost. The fix is server-side: --no-proxy-headers, or
    # forwarded-allow-ips restricted to the real proxy.
    trialsights: Any = {"mode": "cidrs", "cidrs": ["172.64.0.0/13", "169.254.0.0/16"], "cloudflare": ["172.64.0.0/13"]}
    xff = b"6.6.6.6, 198.51.100.9, 172.64.1.1, 169.254.1.1"
    base = {"type": "http", "method": "GET", "path": "/", "headers": [(b"x-forwarded-for", xff)]}
    rewritten = req_from_scope({**base, "client": ("6.6.6.6", 0)})
    assert resolve_client_ip(rewritten.peer, rewritten.header("x-forwarded-for"), trialsights) == "6.6.6.6"
    real = req_from_scope({**base, "client": ("127.0.0.1", 51234)})   # --no-proxy-headers: the real front end
    assert resolve_client_ip(real.peer, real.header("x-forwarded-for"), trialsights) == "198.51.100.9"
