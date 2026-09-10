# FastAPI / Starlette: `app.add_middleware(CamadaMiddleware)` — a pure ASGI middleware, so
# streaming responses and lifespan are untouched.
from __future__ import annotations

import json

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.testclient import TestClient

from camada.engine import Camada
from camada.fastapi import CamadaMiddleware, script_tag, serve_challenge, track

from .fake_analyst import BLOCKED_IP, FakeAnalyst


@pytest.fixture
def client(default_engine: Camada) -> TestClient:
    app = FastAPI()
    app.add_middleware(CamadaMiddleware)

    @app.get("/", response_class=HTMLResponse)
    async def home(request: Request) -> str:
        return "<html>" + script_tag(request) + "</html>"

    @app.get("/items/{item_id}")
    async def item(request: Request, item_id: int) -> dict[str, int]:
        track(request, "signup")
        return {"id": item_id}

    @app.get("/export")
    async def export(request: Request) -> PlainTextResponse:
        return serve_challenge(request) or PlainTextResponse("file")

    return TestClient(app)


def test_blocks_captures_routes_and_tracks(client: TestClient, default_engine: Camada, analyst: FakeAnalyst) -> None:
    engine = default_engine
    assert client.get("/", headers={"x-forwarded-for": BLOCKED_IP}).status_code == 403
    r = client.get("/", headers={"x-forwarded-for": "172.16.0.9"})
    assert r.status_code == 200 and f'?r={r.headers["x-rid"]}' in r.text and r.headers["set-cookie"].startswith("_sfp=")
    assert client.get("/items/7", headers={"x-forwarded-for": "172.16.0.9"}).json() == {"id": 7}
    engine.queue.flush()  # type: ignore[union-attr]
    evs = analyst.all_events
    pages = [e for e in evs if "p" in e]
    assert [e["st"] for e in pages] == [403, 200, 200] and pages[2]["rt"] == "/items/{item_id}"
    assert next(e for e in evs if "et" in e)["et"] == "signup" and "hord" in pages[1]
    assert json.dumps(evs).count("sdk-python") == 4


def test_beacon_and_challenge_paths_are_camadas(client: TestClient) -> None:
    assert client.get("/_cam/b.js").headers["content-type"] == "application/javascript"
    assert client.post("/_cam/fp", content=b"{}", headers={"x-forwarded-for": "198.18.0.5"}).status_code == 204
    assert client.post("/__camada/challenge", content=b"nonce=x", headers={"x-forwarded-for": "198.18.0.5"}).status_code == 403


def test_a_route_gates_itself_with_serve_challenge(client: TestClient, default_engine: Camada, analyst: FakeAnalyst) -> None:
    html = {"x-forwarded-for": "172.16.0.9", "accept": "text/html", "sec-fetch-dest": "document"}
    r = client.get("/export", headers=html)
    assert r.status_code == 403 and r.headers["x-camada-challenge"] == "1" and "text/html" in r.headers["content-type"]
    assert default_engine.kit is not None
    cch = default_engine.kit.issue("172.16.0.9", default_engine.now_ms())
    assert client.get("/export", headers={**html, "cookie": f"_cch={cch}"}).text == "file"
    default_engine.queue.flush()  # type: ignore[union-attr]
    assert [(e["st"], e.get("blk")) for e in analyst.all_events] == [(403, "challenge"), (200, None)]   # one request, one event
