# What only the WSGI host can show: the environ mapping, and a body camada read being put back.
from __future__ import annotations

import io
from collections.abc import Iterator
from typing import Any

import pytest

from camada.engine import Camada
from camada.wsgi import CamadaWSGI, req_from_environ

from .fake_analyst import FakeAnalyst


def test_environ_mapping() -> None:
    req = req_from_environ({
        "REQUEST_METHOD": "PUT", "PATH_INFO": "/a", "QUERY_STRING": "x=1", "SERVER_PROTOCOL": "HTTP/1.0", "wsgi.url_scheme": "https",
        "REMOTE_ADDR": "::ffff:1.2.3.4", "HTTP_HOST": "h", "HTTP_X_FORWARDED_FOR": "5.6.7.8", "CONTENT_TYPE": "text/plain", "CONTENT_LENGTH": "3",
    })
    assert (req.method, req.path, req.query, req.host, req.http_version, req.peer, req.https) == ("PUT", "/a", "?x=1", "h", "1.0", "::ffff:1.2.3.4", True)
    assert ("x-forwarded-for", "5.6.7.8") in req.headers and ("content-type", "text/plain") in req.headers and ("content-length", "3") in req.headers
    assert req.header("x-forwarded-for") == "5.6.7.8"


def test_a_body_camada_read_is_put_back_for_the_app(engine: Camada, analyst: FakeAnalyst) -> None:
    analyst.config["beacon"] = False
    engine.snap.refresh()  # type: ignore[union-attr]
    got: list[bytes] = []

    def app(environ: dict[str, Any], start_response: Any) -> list[bytes]:
        got.append(environ["wsgi.input"].read())
        start_response("200 OK", [])
        return [b"ok"]

    environ = {"REQUEST_METHOD": "POST", "PATH_INFO": "/_cam/fp", "CONTENT_LENGTH": "2", "wsgi.input": io.BytesIO(b"{}"), "REMOTE_ADDR": "172.16.0.9"}
    out = b"".join(CamadaWSGI(app, engine=engine)(environ, lambda *a: None))
    assert out == b"ok" and got == [b"{}"]


def test_a_body_over_the_cap_reaches_the_app_whole(engine: Camada) -> None:
    # no ip -> camada never answers the verify endpoint, so the app gets the request with its full body
    big = b"x" * 70_000
    got: list[bytes] = []

    def app(environ: dict[str, Any], start_response: Any) -> list[bytes]:
        got.append(environ["wsgi.input"].read())
        start_response("200 OK", [])
        return [b"ok"]

    environ = {"REQUEST_METHOD": "POST", "PATH_INFO": "/__camada/challenge", "wsgi.input": io.BytesIO(big)}
    assert b"".join(CamadaWSGI(app, engine=engine)(environ, lambda *a: None)) == b"ok" and got == [big]


def test_the_app_iterable_is_closed_exactly_once(engine: Camada) -> None:
    closes: list[int] = []

    class Body:
        def __iter__(self) -> Iterator[bytes]:
            yield b"ok"

        def close(self) -> None:
            closes.append(1)

    def app(environ: dict[str, Any], start_response: Any) -> Body:
        start_response("200 OK", [])
        return Body()

    result = CamadaWSGI(app, engine=engine)({"REQUEST_METHOD": "GET", "PATH_INFO": "/", "REMOTE_ADDR": "172.16.0.9"}, lambda *a: None)
    assert b"".join(result) == b"ok"
    result.close()   # what a PEP 3333 server does after iterating
    assert closes == [1]


def test_wraps_the_default_engine_lazily(monkeypatch: pytest.MonkeyPatch) -> None:
    import camada

    monkeypatch.setattr(camada, "_default", None)
    monkeypatch.setenv("CAMADA_DISABLED", "1")
    monkeypatch.setenv("CAMADA_KEY", "a.b")
    out = b"".join(CamadaWSGI(lambda e, sr: (sr("200 OK", []), [b"x"])[1])({"REQUEST_METHOD": "GET", "PATH_INFO": "/"}, lambda *a: None))
    assert out == b"x" and camada.get_default().disabled
    camada.get_default().stop()
    monkeypatch.setattr(camada, "_default", None)
