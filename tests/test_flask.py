# Flask: `camada.flask.init_app(app)` wraps app.wsgi_app so camada answers before routing.
from __future__ import annotations

import json

import pytest
from flask import Flask, Response

from camada.engine import Camada
from camada.flask import init_app, script_tag, serve_challenge, track

from .fake_analyst import BLOCKED_IP, FakeAnalyst


@pytest.fixture
def app(default_engine: Camada) -> Flask:
    app = Flask(__name__)
    init_app(app)

    @app.get("/export")
    def export() -> Response:
        return serve_challenge() or Response("file")

    @app.get("/")
    def home() -> str:
        return "<html>" + script_tag() + "</html>"

    @app.post("/login")
    def login() -> tuple[str, int]:
        track("login_failed", user="bob")
        return "nope", 401

    return app


def test_blocks_captures_and_tracks(app: Flask, default_engine: Camada, analyst: FakeAnalyst) -> None:
    engine = default_engine
    c = app.test_client()
    assert c.get("/", headers={"x-forwarded-for": BLOCKED_IP}).status_code == 403
    r = c.get("/", headers={"x-forwarded-for": "172.16.0.9"})
    assert r.status_code == 200 and f'?r={r.headers["x-rid"]}' in r.get_data(as_text=True)
    assert r.headers.get("set-cookie", "").startswith("_sfp=")
    assert c.post("/login", headers={"x-forwarded-for": "172.16.0.9"}).status_code == 401
    engine.queue.flush()  # type: ignore[union-attr]
    evs = analyst.all_events
    assert [e.get("st") for e in evs if "p" in e] == [403, 200, 401]
    assert next(e for e in evs if "et" in e)["uid"] and "bob" not in json.dumps(evs)


def test_beacon_answers_before_routing(app: Flask, default_engine: Camada, analyst: FakeAnalyst) -> None:
    engine = default_engine
    c = app.test_client()
    assert "@camada/browser" in c.get("/_cam/b.js").get_data(as_text=True)
    assert c.post("/_cam/fp", data=b'{"a":1}', headers={"x-forwarded-for": "198.18.0.5"}).status_code == 204
    engine.queue.flush()  # type: ignore[union-attr]
    (row,) = analyst.all_events
    assert row["sig"] == 1 and row["ip"] == "198.18.0.5"


def test_a_route_gates_itself_with_serve_challenge(app: Flask, default_engine: Camada, analyst: FakeAnalyst) -> None:
    c = app.test_client()
    html = {"x-forwarded-for": "172.16.0.9", "accept": "text/html", "sec-fetch-dest": "document"}
    r = c.get("/export", headers=html)
    assert r.status_code == 403 and r.headers["x-camada-challenge"] == "1" and r.headers["content-type"].startswith("text/html")
    assert default_engine.kit is not None
    c.set_cookie("_cch", default_engine.kit.issue("172.16.0.9", default_engine.now_ms()))
    assert c.get("/export", headers=html).get_data(as_text=True) == "file"
    default_engine.queue.flush()  # type: ignore[union-attr]
    assert [(e["st"], e.get("blk")) for e in analyst.all_events] == [(403, "challenge"), (200, None)]
