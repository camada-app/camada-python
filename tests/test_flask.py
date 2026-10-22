# Flask: `camada.flask.init_app(app)` wraps app.wsgi_app so camada answers before routing.
from __future__ import annotations

import json

import pytest
from flask import Flask, Response

from camada.challenge.page import challenge_page_csp
from camada.engine import Camada
from camada.flask import init_app, script_tag, serve_challenge, track

from .fake_analyst import BLOCKED_IP, FakeAnalyst


@pytest.fixture
def app(default_engine: Camada) -> Flask:
    app = Flask(__name__)
    init_app(app)

    @app.get("/export")
    def export() -> Response:
        return serve_challenge() or Response("file", headers={"CDN-Cache-Control": "public, max-age=60", "Surrogate-Control": "max-age=60"})

    @app.after_request
    def site_csp(r: Response) -> Response:   # what Flask-Talisman does: a policy on every response
        r.headers["Content-Security-Policy"] = "script-src 'self'"
        r.headers["Content-Security-Policy-Report-Only"] = "default-src 'self'"
        return r

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
    assert r.headers.getlist("content-security-policy") == [challenge_page_csp()]   # camada-all-y38o: the app's policy is replaced
    assert "content-security-policy-report-only" not in r.headers
    assert default_engine.kit is not None
    c.set_cookie("_cch", default_engine.kit.issue("172.16.0.9", default_engine.now_ms()))
    ok = c.get("/export", headers=html)
    assert ok.get_data(as_text=True) == "file" and ok.headers["cdn-cache-control"] == "public, max-age=60" and ok.headers["surrogate-control"] == "max-age=60"   # not signalled: untouched
    default_engine.queue.flush()  # type: ignore[union-attr]
    assert [(e["st"], e.get("blk")) for e in analyst.all_events] == [(403, "challenge"), (200, None)]


def test_a_non_html_request_under_a_challenge_is_signalled(app: Flask, default_engine: Camada, analyst: FakeAnalyst) -> None:
    c = app.test_client()
    r = c.get("/export", headers={"x-forwarded-for": "172.16.0.9", "accept": "application/json"})   # serve_challenge() runs inside the route
    assert r.status_code == 200 and r.get_data(as_text=True) == "file"
    assert r.headers["x-camada-challenge"] == "1" and r.headers["cache-control"] == "no-store"
    for name in ("cache-control", "cdn-cache-control", "surrogate-control", "cloudflare-cdn-cache-control", "vercel-cdn-cache-control", "netlify-cdn-cache-control"):   # the app's CDN headers are overridden (camada-all-1zlg)
        assert r.headers.getlist(name) == ["no-store"]
    default_engine.queue.flush()  # type: ignore[union-attr]
    (ev,) = analyst.all_events
    assert ev["chs"] == 1 and ev["st"] == 200 and "blk" not in ev
