# Django: `MIDDLEWARE = ["camada.django.CamadaMiddleware", ...]`, sync and async stacks alike.
from __future__ import annotations

import json
from collections.abc import Iterator

import django
import pytest
from django.conf import settings
from django.http import HttpRequest, HttpResponse
from django.test import AsyncClient, Client
from django.urls import path

import camada
from camada.engine import Camada

from .fake_analyst import BLOCKED_IP, FakeAnalyst
from .hosts import engine_with, loaded

analyst = FakeAnalyst()


def home(request: HttpRequest, id: int = 0) -> HttpResponse:  # noqa: A002
    from camada.django import script_tag, track

    if request.GET.get("fail"):
        track(request, "login_failed", user="alice@example.com")
    return HttpResponse("<html>" + script_tag(request) + "</html>")


async def ahome(request: HttpRequest) -> HttpResponse:
    return HttpResponse("async")


def export(request: HttpRequest) -> HttpResponse:
    from camada.django import serve_challenge

    return serve_challenge(request) or HttpResponse("file")


urlpatterns = [path("", home), path("a/", ahome), path("items/<int:id>/", home), path("export/", export)]

if not settings.configured:
    settings.configure(
        DEBUG=True, SECRET_KEY="x", ROOT_URLCONF=__name__, ALLOWED_HOSTS=["*"],
        MIDDLEWARE=["camada.django.CamadaMiddleware"],
    )
    django.setup()


@pytest.fixture(autouse=True)
def engine(monkeypatch: pytest.MonkeyPatch) -> Iterator[Camada]:
    e = engine_with(analyst, {"CAMADA_TRUSTED_PROXY": "hops:1"})
    monkeypatch.setattr(camada, "_default", e)
    loaded(e)
    yield e
    e.stop()
    analyst.events.clear()


def events(e: Camada) -> list[dict[str, object]]:
    e.queue.flush()  # type: ignore[union-attr]
    return analyst.all_events


def test_blocks_before_the_view_and_ships_the_event(engine: Camada) -> None:
    r = Client().get("/", HTTP_X_FORWARDED_FOR=BLOCKED_IP)
    assert r.status_code == 403 and r["x-block-reason"] == "ip4" and r.content == b"Forbidden"
    (ev,) = events(engine)
    assert ev["tap"] == "sdk-python" and ev["st"] == 403 and ev["blk"] == "ip4"


def test_captures_with_rid_session_route_and_script_tag(engine: Camada) -> None:
    r = Client().get("/items/7/?fail=1", HTTP_X_FORWARDED_FOR="172.16.0.9")
    assert r.status_code == 200
    rid = r["x-rid"]
    assert f'<script src="/_cam/b.js?r={rid}" async></script>' in r.content.decode()
    assert r.cookies["_sfp"]["httponly"] and r.cookies["_sfp"]["samesite"] == "Lax"
    evs = events(engine)
    page = next(e for e in evs if "p" in e)
    tracked = next(e for e in evs if "et" in e)
    assert page["rid"] == rid and page["rt"] == "items/<int:id>/" and page["st"] == 200
    assert tracked["rid"] == rid and tracked["et"] == "login_failed" and "alice" not in json.dumps(evs)


def test_beacon_endpoints_answer_before_routing(engine: Camada) -> None:
    c = Client()
    assert c.get("/_cam/b.js").status_code == 200
    r = c.post("/_cam/fp", data=json.dumps({"scr": "1x1"}), content_type="application/json", HTTP_X_FORWARDED_FOR="198.18.0.5")
    assert r.status_code == 204
    (row,) = events(engine)
    assert row["sig"] == 1 and row["ip"] == "198.18.0.5" and row["tap"] == "sdk-python"


def test_async_stack(engine: Camada) -> None:
    import asyncio

    async def go() -> tuple[int, int]:
        c = AsyncClient()
        blocked = await c.get("/a/", headers={"x-forwarded-for": BLOCKED_IP})
        ok = await c.get("/a/", headers={"x-forwarded-for": "172.16.0.9"})
        return blocked.status_code, ok.status_code

    assert asyncio.run(go()) == (403, 200)
    evs = events(engine)
    assert [e["st"] for e in evs] == [403, 200]


def test_a_view_gates_itself_with_serve_challenge(engine: Camada) -> None:
    c = Client()
    html = {"HTTP_X_FORWARDED_FOR": "172.16.0.9", "HTTP_ACCEPT": "text/html", "HTTP_SEC_FETCH_DEST": "document"}
    r = c.get("/export/", **html)
    assert r.status_code == 403 and r["x-camada-challenge"] == "1" and r["content-type"].startswith("text/html")
    assert engine.kit is not None
    cch = engine.kit.issue("172.16.0.9", engine.now_ms())
    assert c.get("/export/", HTTP_COOKIE=f"_cch={cch}", **html).content == b"file"
    assert [(e["st"], e.get("blk")) for e in events(engine)] == [(403, "challenge"), (200, None)]
