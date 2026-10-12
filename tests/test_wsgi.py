# What only the WSGI host can show: the environ mapping, and a body camada read being put back.
from __future__ import annotations

import io
from collections.abc import Iterator
from typing import Any

import pytest

from camada.engine import Camada
from camada.ip import resolve_client_ip
from camada.wsgi import CamadaWSGI, read_body, req_from_environ

from .fake_analyst import FakeAnalyst


def test_environ_mapping() -> None:
    req = req_from_environ({
        "REQUEST_METHOD": "PUT", "PATH_INFO": "/a", "QUERY_STRING": "x=1", "SERVER_PROTOCOL": "HTTP/1.0", "wsgi.url_scheme": "https",
        "REMOTE_ADDR": "::ffff:1.2.3.4", "HTTP_HOST": "h", "HTTP_X_FORWARDED_FOR": "5.6.7.8", "CONTENT_TYPE": "text/plain", "CONTENT_LENGTH": "3",
    })
    assert (req.method, req.path, req.query, req.host, req.http_version, req.peer, req.https) == ("PUT", "/a", "?x=1", "h", "1.0", "::ffff:1.2.3.4", True)
    assert ("x-forwarded-for", "5.6.7.8") in req.headers and ("content-type", "text/plain") in req.headers and ("content-length", "3") in req.headers
    assert req.header("x-forwarded-for") == "5.6.7.8"


CIDRS: Any = {"mode": "cidrs", "cidrs": ["172.64.0.0/13"]}


def test_peer_rule_unix_socket_listener_walks_and_unreadable_peer_is_none() -> None:
    # C6 v3 peer table: REMOTE_ADDR "" or absent (gunicorn/uwsgi bound to a path) is no peer, so cidrs walks XFF alone;
    # a non-empty REMOTE_ADDR that is not an ip could not be read, and the result is None, never the XFF walk.
    base = {"REQUEST_METHOD": "GET", "PATH_INFO": "/", "HTTP_X_FORWARDED_FOR": "198.51.100.9, 172.64.1.1"}
    for env in ({**base}, {**base, "REMOTE_ADDR": ""}):
        req = req_from_environ(env)
        assert req.peer is None
        assert resolve_client_ip(req.peer, req.header("x-forwarded-for"), CIDRS) == "198.51.100.9"
    for bad in ("/run/app.sock", "unix:/run/app.sock", "@", "1.2.3.4:5"):
        req = req_from_environ({**base, "REMOTE_ADDR": bad})
        assert resolve_client_ip(req.peer, req.header("x-forwarded-for"), CIDRS) is None, bad


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

    environ = {"REQUEST_METHOD": "POST", "PATH_INFO": "/__camada/challenge", "wsgi.input": io.BytesIO(big), "wsgi.input_terminated": True}
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


def test_path_info_latin1_bytes_read_back_as_utf8() -> None:
    environ = {"REQUEST_METHOD": "GET", "PATH_INFO": "/café".encode().decode("latin-1")}
    assert req_from_environ(environ).path == "/café"
    assert req_from_environ({"PATH_INFO": "/\udcff"}).path == "/\udcff"   # not latin-1-encodable: kept as is


class SocketLike(io.RawIOBase):
    """A raw socket's wsgi.input (werkzeug's dev server): the declared body, then a read that would
    block forever waiting for bytes the client never sends — here it raises instead (camada-all-4sko)."""

    def __init__(self, body: bytes) -> None:
        self._body = body

    def readable(self) -> bool:
        return True

    def readinto(self, b: Any) -> int:
        if not self._body:
            raise AssertionError("read past CONTENT_LENGTH: a socket stream would block here")
        n = min(len(b), len(self._body))
        b[:n], self._body = self._body[:n], self._body[n:]
        return n


def test_never_reads_past_content_length(engine: Camada, analyst: FakeAnalyst) -> None:
    body = b'{"scr":"1x1"}'
    environ = {"REQUEST_METHOD": "POST", "PATH_INFO": "/_cam/fp", "CONTENT_LENGTH": str(len(body)), "wsgi.input": io.BufferedReader(SocketLike(body)),
               "REMOTE_ADDR": "172.16.0.9"}
    statuses: list[str] = []
    out = b"".join(CamadaWSGI(lambda e, sr: [], engine=engine)(environ, lambda s, h: statuses.append(s)))
    assert statuses == ["204 No Content"] and out == b""
    engine.queue.flush()  # type: ignore[union-attr]
    assert any(e.get("sig") == 1 and e.get("scr") == "1x1" for e in analyst.all_events)


def test_short_reads_are_filled_up_to_content_length() -> None:
    class Trickle(SocketLike):
        def readinto(self, b: Any) -> int:
            return super().readinto(memoryview(b)[:1])   # one byte per read, as a socket may hand out

    environ: dict[str, Any] = {"CONTENT_LENGTH": "5", "wsgi.input": Trickle(b"hello")}
    assert read_body(environ, 100) == b"hello" and environ["wsgi.input"].read() == b"hello"


def test_no_content_length_reads_nothing_unless_the_input_is_terminated() -> None:
    stream = io.BufferedReader(SocketLike(b""))
    environ: dict[str, Any] = {"wsgi.input": stream}
    assert read_body(environ, 100) == b""   # PEP 3333: no CONTENT_LENGTH and no wsgi.input_terminated is an empty body
    assert environ["wsgi.input"] is stream
    chunked: dict[str, Any] = {"wsgi.input": io.BytesIO(b"abc"), "wsgi.input_terminated": True}
    assert read_body(chunked, 100) == b"abc" and chunked["wsgi.input"].read() == b"abc"
    big: dict[str, Any] = {"wsgi.input": io.BytesIO(b"x" * 10), "wsgi.input_terminated": True}
    assert read_body(big, 4) is None and big["wsgi.input"].read() == b"x" * 10
