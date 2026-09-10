# SnapshotClient: the single-tenant port of the edge collector's snapshot lifecycle over the
# GET /snapshot contract (200 frame + etag + x-camada-config; 304 unchanged; 204 nothing
# published -> enforce nothing). Cold = fail open; any error keeps the previous snapshot.
from __future__ import annotations

import gzip
import time

from camada.snapshot.client import SnapshotClient
from camada.snapshot.match import MatchInput
from camada.transport import HttpRequest, HttpResponse, urllib_transport

from .fake_analyst import BLOCKED_IP, FakeAnalyst, frame

URL = "https://analyst.test/snapshot"


def client(a: FakeAnalyst, **kw: object) -> SnapshotClient:
    return SnapshotClient(URL, "snap-test", transport=a.transport, sdk="@camada/python/0.0.0", mode="lazy", **kw)  # type: ignore[arg-type]


def test_cold_client_fails_open() -> None:
    c = client(FakeAnalyst())
    v = c.verdict(MatchInput(ip=BLOCKED_IP))
    assert v.reason == "cold" and not v.block and not v.challenge and not v.allowed


def test_loads_and_enforces_with_the_contract_headers() -> None:
    a = FakeAnalyst()
    c = client(a)
    c.refresh()
    assert c.verdict(MatchInput(ip=BLOCKED_IP)).block
    req = a.snapshot_requests[0]
    assert req.headers["authorization"] == "Bearer snap-test"
    assert req.headers["x-camada-sdk"] == "@camada/python/0.0.0"
    assert req.headers["x-camada-snapshot"] == "5"
    assert "if-none-match" not in req.headers
    assert c.config == a.config


def test_304_repeats_config_and_keeps_the_snapshot() -> None:
    a = FakeAnalyst()
    c = client(a)
    c.refresh()
    a.config = {**a.config, "beacon": False}
    c.refresh()
    assert a.snapshot_requests[1].headers["if-none-match"] == a.etag
    assert c.verdict(MatchInput(ip=BLOCKED_IP)).block
    assert c.config is not None and c.config["beacon"] is False


def test_204_means_nothing_published_and_not_cold() -> None:
    a = FakeAnalyst()
    a.snapshot_status = 204
    c = client(a)
    c.refresh()
    v = c.verdict(MatchInput(ip=BLOCKED_IP))
    assert v.reason is None and not v.block


def test_errors_keep_what_we_have() -> None:
    a = FakeAnalyst()
    c = client(a)
    c.refresh()
    for status in (401, 500):
        a.snapshot_status = status
        c.refresh()
        assert c.verdict(MatchInput(ip=BLOCKED_IP)).block
    a.snapshot_status = None
    a.snapshot_down = True
    c.refresh()
    assert c.verdict(MatchInput(ip=BLOCKED_IP)).block


def test_corrupt_body_keeps_the_previous_snapshot() -> None:
    a = FakeAnalyst()
    c = client(a)
    c.refresh()
    good = a.transport

    def corrupt(req: HttpRequest) -> HttpResponse:
        r = good(req)
        return HttpResponse(200, {**r.headers, "etag": '"other"'}, b"\x05\x00\x00\x00junk!" + b"\x00" * 10)

    c.transport = corrupt
    c.refresh()
    assert c.verdict(MatchInput(ip=BLOCKED_IP)).block


def test_same_version_new_etag_reparses() -> None:
    # the server ships v3/v4/v5 bodies of one publish under the same meta.version and different etags
    a = FakeAnalyst()
    c = client(a)
    c.refresh()
    assert not c.verdict(MatchInput(ip="192.0.2.20")).challenge   # v3 has no challenge side
    a.container = "v4"
    c.refresh()
    assert c.verdict(MatchInput(ip="192.0.2.20")).challenge


def test_snapshot_version_header_follows_the_option() -> None:
    a = FakeAnalyst()
    client(a, snapshot_version=4).refresh()
    client(a, snapshot_version=3).refresh()
    assert a.snapshot_versions == ["4", ""]


def test_server_steers_the_cadence_unless_pinned() -> None:
    a = FakeAnalyst()
    a.config = {**a.config, "poll_seconds": 7}
    c = client(a)
    c.refresh()
    assert c.refresh_s == 7
    a.config = {**a.config, "poll_seconds": 1}   # below the 5 s floor: ignored
    c.refresh()
    assert c.refresh_s == 7
    pinned = client(a, refresh_s=11)
    pinned.refresh()
    assert pinned.refresh_s == 11


def test_ensure_fresh_is_off_path_and_single_in_flight() -> None:
    a = FakeAnalyst()
    c = client(a)
    c.ensure_fresh()
    c.ensure_fresh()
    for _ in range(200):
        if c.verdict(MatchInput(ip="0.0.0.0")).reason != "cold":
            break
        time.sleep(0.005)
    assert c.verdict(MatchInput(ip=BLOCKED_IP)).block
    assert len(a.snapshot_requests) == 1
    c.ensure_fresh()   # fresh: no new poll
    time.sleep(0.02)
    assert len(a.snapshot_requests) == 1


def test_timer_mode_polls_on_its_own_and_stops() -> None:
    a = FakeAnalyst()
    c = SnapshotClient(URL, "snap-test", transport=a.transport, mode="timer", refresh_s=0.02)
    c.start()
    try:
        for _ in range(200):
            if len(a.snapshot_requests) >= 3:
                break
            time.sleep(0.005)
        assert len(a.snapshot_requests) >= 3
    finally:
        c.stop()
    n = len(a.snapshot_requests)
    time.sleep(0.05)
    assert len(a.snapshot_requests) == n


def test_urllib_transport_gunzips_and_never_raises() -> None:
    import http.server
    import threading

    payload = frame({"version": "z"}, b"BLK")

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            body = gzip.compress(payload)
            self.send_response(200)
            self.send_header("content-encoding", "gzip")
            self.send_header("etag", '"z"')
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a: object) -> None:
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        r = urllib_transport(HttpRequest("GET", f"http://127.0.0.1:{srv.server_port}/snapshot", {"accept-encoding": "gzip"}, None, 2.0))
        assert r.status == 200 and r.body == payload and r.headers["etag"] == '"z"'
    finally:
        srv.shutdown()
    dead = urllib_transport(HttpRequest("GET", "http://127.0.0.1:1/snapshot", {}, None, 0.2))
    assert dead.status == 0
