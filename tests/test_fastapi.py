# FastAPI / Starlette: `app.add_middleware(CamadaMiddleware)` — a pure ASGI middleware, so
# streaming responses and lifespan are untouched.
from __future__ import annotations

import json
from collections.abc import Iterator

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient

import camada
from camada.engine import Camada
from camada.fastapi import CamadaMiddleware, script_tag, track

from .fake_analyst import BLOCKED_IP, FakeAnalyst
from .hosts import engine_with, loaded


@pytest.fixture
def analyst() -> FakeAnalyst:
    return FakeAnalyst()


@pytest.fixture
def engine(analyst: FakeAnalyst, monkeypatch: pytest.MonkeyPatch) -> Iterator[Camada]:
    e = engine_with(analyst, {"CAMADA_TRUSTED_PROXY": "hops:1"})
    monkeypatch.setattr(camada, "_default", e)
    loaded(e)
    yield e
    e.stop()


@pytest.fixture
def client(engine: Camada) -> TestClient:
    app = FastAPI()
    app.add_middleware(CamadaMiddleware)

    @app.get("/", response_class=HTMLResponse)
    async def home(request: Request) -> str:
        return "<html>" + script_tag(request) + "</html>"

    @app.get("/items/{item_id}")
    async def item(request: Request, item_id: int) -> dict[str, int]:
        track(request, "signup")
        return {"id": item_id}

    return TestClient(app)


def test_blocks_captures_routes_and_tracks(client: TestClient, engine: Camada, analyst: FakeAnalyst) -> None:
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


def test_beacon_and_challenge_paths_are_camadas(client: TestClient, engine: Camada, analyst: FakeAnalyst) -> None:
    assert client.get("/_cam/b.js").headers["content-type"] == "application/javascript"
    assert client.post("/_cam/fp", content=b"{}", headers={"x-forwarded-for": "198.18.0.5"}).status_code == 204
    assert client.post("/__camada/challenge", content=b"nonce=x", headers={"x-forwarded-for": "198.18.0.5"}).status_code == 403
