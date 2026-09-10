# The wire event reproduces the collector's record(); HDRS bit order is pinned by the shared
# fixture (test_conformance) — here the derived counters and the credential rules.
from camada.events.build import HDRS, RequestInfo, auth_scheme, build_wire_event


def req(headers: list[tuple[str, str]], query: str = "", ip: str | None = "1.2.3.4") -> RequestInfo:
    return RequestInfo(method="GET", host="x.test", path="/p", query=query, headers=headers, ip=ip, http_version="1.1")


def test_auth_scheme_only_ever_ships_a_scheme() -> None:
    assert auth_scheme("Bearer abc.def") == "Bearer"
    assert auth_scheme("Basic dXNlcjpwYXNz") == "Basic"
    assert auth_scheme("rawtoken") is None
    assert auth_scheme(" Bearer x") is None
    assert auth_scheme("a" * 17 + " x") is None
    assert auth_scheme(None) is None


def test_event_fields_and_counters() -> None:
    headers = [("Accept", "text/html"), ("Cookie", "a=1; b=2"), ("Authorization", "Bearer t"), ("Accept", "*/*"), ("User-Agent", "ua")]
    ev = build_wire_event(req(headers, query="?x=1&token=t&&y"), tap="sdk-python", rid="r1", sid="s1", new_session=True)
    assert ev["tap"] == "sdk-python" and ev["rid"] == "r1" and ev["sid"] == "s1" and ev["ns"] == 1
    assert ev["m"] == "GET" and ev["h"] == "x.test" and ev["p"] == "/p" and ev["proto"] == "HTTP/1.1"
    assert ev["q"] == "?x=1&token=~r&&y" and ev["qn"] == 3
    assert ev["acc"] == "text/html"          # first occurrence wins
    assert ev["auth"] == "Bearer"
    assert ev["ck"] == 2
    assert ev["hn"] == 5
    assert ev["hb"] == sum(len(n) + len(v) for n, v in headers)
    assert ev["hord"] == "accept,cookie,authorization,accept,user-agent"
    assert ev["hm"] == (1 << HDRS.index("accept")) | (1 << HDRS.index("cookie")) | (1 << HDRS.index("authorization"))
    assert ev["ua"] == "ua" and ev["st"] is None and ev["dur"] is None
    assert isinstance(ev["ts"], int)
    assert "ja4" not in ev


def test_event_without_headers_or_ip() -> None:
    ev = build_wire_event(req([], ip=None), tap="sdk-python", rid="r")
    assert ev["ip"] is None and ev["sid"] is None and ev["ns"] == 0
    assert ev["hm"] == 0 and ev["hn"] == 0 and ev["hb"] == 0 and ev["ck"] == 0 and ev["hord"] == ""
    assert ev["qn"] == 0 and ev["q"] == ""


def test_hord_and_query_are_capped() -> None:
    ev = build_wire_event(req([("x-" + str(i), "v") for i in range(1000)], query="?" + "a" * 600), tap="sdk-python", rid="r")
    assert len(ev["hord"]) == 2048 and len(ev["q"]) == 512
