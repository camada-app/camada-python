# The engine through each host (WSGI and ASGI drive the same contract): inline enforcement,
# ordered custom rules, the challenge, the first-party beacon, request capture, app-context
# events, and the fail-open envelope. The case list mirrors camada-node's engine, rules and
# challenge suites.
from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Iterator
from typing import Any

import pytest

from camada.engine import Camada
from camada.version import SDK_ID

from .fake_analyst import (
    ALLOWED_IP,
    BLOCKED_HEADER,
    BLOCKED_HEADER_VALUE,
    BLOCKED_IP,
    BLOCKED_UA,
    CHALLENGED_IP,
    RULE_BLOCKED_IP,
    RULE_BLOCKED_PATH,
    SKIP_PATH,
    WARN_UA,
    FakeAnalyst,
)
from .hosts import DRIVERS, AppHandler, AsgiDriver, Call, Reply, WsgiDriver, engine_with, hello, loaded
from .test_challenge import solve

Driver = type[WsgiDriver] | type[AsgiDriver]
HTML = [("accept", "text/html,*/*"), ("sec-fetch-dest", "document")]


@pytest.fixture(params=DRIVERS, ids=lambda d: d.name)
def driver(request: pytest.FixtureRequest) -> Driver:
    return request.param  # type: ignore[no-any-return]


@pytest.fixture
def engines() -> Iterator[list[Camada]]:
    made: list[Camada] = []
    yield made
    for e in made:
        e.stop()


class Host:
    """One engine + one host per test, loaded unless asked otherwise."""

    def __init__(self, driver: Driver, a: FakeAnalyst, engines: list[Camada], env: dict[str, str] | None = None,
                 handler: AppHandler = hello, load: bool = True, **opts: Any) -> None:
        self.a = a
        self.engine = engine_with(a, env, **opts)
        engines.append(self.engine)
        self.drv = driver(self.engine, handler)
        if load and self.engine.snap is not None:
            loaded(self.engine)

    def __call__(self, *args: Any, **kw: Any) -> Reply:
        return self.drv(Call(*args, **kw))

    def events(self) -> list[dict[str, Any]]:
        assert self.engine.queue is not None
        self.engine.queue.flush()
        return self.a.all_events

    @property
    def seen(self) -> list[dict[str, Any]]:
        return self.drv.seen


def ip(addr: str) -> dict[str, Any]:
    return {"headers": [("x-forwarded-for", addr)]}


def hops1(a: FakeAnalyst) -> None:
    a.config["trusted_proxy"] = {"mode": "hops", "hops": 1}


class TestInlineBlocking:
    def test_answers_403_before_the_app_and_still_ships_the_event(self, driver: Driver, analyst: FakeAnalyst, engines: list[Camada]) -> None:
        h = Host(driver, analyst, engines, {"CAMADA_TRUSTED_PROXY": "hops:1"})
        r = h("GET", "/admin?x=1", **ip(BLOCKED_IP))
        assert r.status == 403 and r.body == b"Forbidden"
        assert r.header("x-block-reason") == "ip4" and r.header("x-block-version") == analyst.meta["version"]
        assert r.header("content-type") == "text/plain" and r.header("x-block-rule") is None
        assert h.seen == []
        (ev,) = h.events()
        assert ev["st"] == 403 and ev["blk"] == "ip4" and ev["ip"] == BLOCKED_IP and ev["p"] == "/admin" and ev["tap"] == "sdk-python"
        assert "rl" not in ev

    def test_ignores_a_spoofed_xff_without_trusted_proxy_config(self, driver: Driver, analyst: FakeAnalyst, engines: list[Camada]) -> None:
        h = Host(driver, analyst, engines)
        assert h("GET", "/", **ip(BLOCKED_IP)).status == 200
        assert h("GET", "/", peer=BLOCKED_IP).status == 403

    def test_server_delivered_trusted_proxy_applies_when_no_local_override(self, driver: Driver, analyst: FakeAnalyst, engines: list[Camada]) -> None:
        hops1(analyst)
        h = Host(driver, analyst, engines)
        assert h("GET", "/", **ip(BLOCKED_IP)).status == 403

    def test_fails_open_while_cold(self, driver: Driver, analyst: FakeAnalyst, engines: list[Camada]) -> None:
        analyst.snapshot_down = True
        h = Host(driver, analyst, engines, load=False)
        assert h("GET", "/", peer=BLOCKED_IP).status == 200
        assert h.seen[0]

    def test_honours_the_allow_side_over_a_wider_block(self, driver: Driver, analyst: FakeAnalyst, engines: list[Camada]) -> None:
        analyst.container = "v4"
        h = Host(driver, analyst, engines)
        assert h("GET", "/", peer="10.0.0.9").status == 403
        assert h("GET", "/", peer=ALLOWED_IP).status == 200


class TestSdkIdentity:
    def test_sends_x_camada_sdk_on_polls_and_batches(self, driver: Driver, analyst: FakeAnalyst, engines: list[Camada]) -> None:
        h = Host(driver, analyst, engines)
        h("GET", "/")
        h.events()
        assert set(analyst.sdk_headers) == {SDK_ID} and len(analyst.sdk_headers) >= 2

    def test_asks_for_v5_by_default_and_opts_out_at_3(self, driver: Driver, analyst: FakeAnalyst, engines: list[Camada]) -> None:
        Host(driver, analyst, engines)
        Host(driver, analyst, engines, snapshot_version=3)
        assert analyst.snapshot_versions[:2] == ["5", ""]


class TestCapture:
    def test_captures_on_finish_with_status_latency_session_and_rid(self, driver: Driver, analyst: FakeAnalyst, engines: list[Camada]) -> None:
        h = Host(driver, analyst, engines, handler=lambda _: (201, [("x-app", "1")], b"made"))
        r = h("POST", "/things?q=1&token=secret", headers=[("user-agent", "UA/1"), ("accept", "*/*")], body=b"{}")
        assert r.status == 201 and r.body == b"made" and r.header("x-app") == "1"
        rid = r.header("x-rid")
        assert rid and len(rid) == 36
        cookie = r.header("set-cookie")
        assert cookie and cookie.startswith("_sfp=") and "HttpOnly" in cookie and "SameSite=Lax" in cookie and "Secure" not in cookie
        (ev,) = h.events()
        assert ev["rid"] == rid and ev["sid"] == cookie[5:].split(";")[0] and ev["ns"] == 1
        assert ev["st"] == 201 and isinstance(ev["dur"], int) and ev["dur"] >= 0
        assert ev["m"] == "POST" and ev["p"] == "/things" and ev["q"] == "?q=1&token=~r" and ev["ua"] == "UA/1"
        assert ev["ip"] == "172.16.0.9" and ev["proto"] == "HTTP/1.1" and ev["h"] == "x.test"
        assert "blk" not in ev and "wrn" not in ev

    def test_reuses_the_session_cookie_and_marks_https_secure(self, driver: Driver, analyst: FakeAnalyst, engines: list[Camada]) -> None:
        h = Host(driver, analyst, engines)
        r = h("GET", "/", headers=[("cookie", "a=1; _sfp=sess-1; b=2")], https=True)
        assert r.header("set-cookie") is None
        r2 = h("GET", "/", https=True)
        assert r2.header("set-cookie") and "; Secure" in r2.header("set-cookie")   # type: ignore[operator]
        r3 = h("GET", "/", headers=[("x-forwarded-proto", "https")])
        assert "; Secure" in (r3.header("set-cookie") or "")
        ev = h.events()[0]
        assert ev["sid"] == "sess-1" and ev["ns"] == 0

    def test_keeps_the_apps_own_cookies(self, driver: Driver, analyst: FakeAnalyst, engines: list[Camada]) -> None:
        h = Host(driver, analyst, engines, handler=lambda _: (200, [("set-cookie", "app=1; Path=/"), ("set-cookie", "b=2")], b""))
        r = h("GET", "/")
        cookies = r.headers_named("set-cookie")
        assert len(cookies) == 3 and "app=1; Path=/" in cookies and "b=2" in cookies and any(c.startswith("_sfp=") for c in cookies)

    def test_honours_exclude_and_sample_and_never_captures_credentials(self, driver: Driver, analyst: FakeAnalyst, engines: list[Camada]) -> None:
        analyst.config["exclude"] = ["/health"]
        h = Host(driver, analyst, engines)
        h("GET", "/health/live")
        h("GET", "/api", headers=[("authorization", "Bearer very-secret"), ("cookie", "s=1; t=2")])
        (ev,) = h.events()
        assert ev["p"] == "/api" and ev["auth"] == "Bearer" and ev["ck"] == 2
        assert "very-secret" not in json.dumps(ev) and "s=1" not in json.dumps(ev)
        analyst.config["sample"] = 0
        h.engine.snap.refresh()   # type: ignore[union-attr]
        h("GET", "/api")
        assert len(h.events()) == 1

    def test_exposes_rid_sid_ip_to_the_app(self, driver: Driver, analyst: FakeAnalyst, engines: list[Camada]) -> None:
        h = Host(driver, analyst, engines)
        r = h("GET", "/")
        ctx = h.seen[0]["camada"]
        assert ctx["rid"] == r.header("x-rid") and ctx["ip"] == "172.16.0.9" and ctx["sid"]

    def test_an_app_exception_ships_st_500_and_propagates(self, driver: Driver, analyst: FakeAnalyst, engines: list[Camada]) -> None:
        def boom(_: dict[str, Any]) -> tuple[int, list[tuple[str, str]], bytes]:
            raise RuntimeError("app bug")

        h = Host(driver, analyst, engines, handler=boom)
        with pytest.raises(RuntimeError):
            h("GET", "/crash")
        (ev,) = h.events()
        assert ev["p"] == "/crash" and ev["st"] == 500


class TestTrack:
    def test_track_ships_an_app_context_event_with_a_hashed_uid(self, driver: Driver, analyst: FakeAnalyst, engines: list[Camada]) -> None:
        def login(req: dict[str, Any]) -> tuple[int, list[tuple[str, str]], bytes]:
            h.engine.track(req["camada"], "login_failed", user="alice@example.com")
            return 401, [], b""

        h = Host(driver, analyst, engines, handler=login)
        r = h("POST", "/login", body=b"x=1")
        evs = h.events()
        tracked = next(e for e in evs if e.get("et"))
        assert tracked["et"] == "login_failed" and tracked["tap"] == "sdk-python" and tracked["rid"] == r.header("x-rid")
        assert tracked["uid"] == hmac.new(b"tok-test", b"uid:alice@example.com", hashlib.sha256).hexdigest()[:32]
        assert "alice" not in json.dumps(evs)
        assert tracked["ip"] == "172.16.0.9" and "p" not in tracked

    def test_track_without_a_user_and_without_context(self, driver: Driver, analyst: FakeAnalyst, engines: list[Camada]) -> None:
        h = Host(driver, analyst, engines)
        h.engine.track(None, "signup")
        (ev,) = h.events()
        assert ev["et"] == "signup" and ev["uid"] is None and ev["rid"] is None


class TestBeacon:
    def test_serves_the_script_and_batches_fp_as_a_sig_row_with_the_resolved_ip(self, driver: Driver, analyst: FakeAnalyst, engines: list[Camada]) -> None:
        hops1(analyst)
        h = Host(driver, analyst, engines)
        js = h("GET", "/_cam/b.js")
        assert js.status == 200 and js.header("content-type") == "application/javascript" and "@camada/browser" in js.text
        assert js.header("cache-control") == "public, max-age=3600"
        body = json.dumps({"sdk": "@camada/browser/0.2.0", "rid": "r-1", "ip": "9.9.9.9", "tap": "proxy", "scr": "1x1"}).encode()
        fp = h("POST", "/_cam/fp", headers=[("x-forwarded-for", "198.18.0.5"), ("content-type", "application/json")], body=body)
        assert fp.status == 204 and fp.header("cache-control") == "no-store"
        assert h.seen == []
        (row,) = h.events()
        assert row["sig"] == 1 and row["ip"] == "198.18.0.5" and row["tap"] == "sdk-python" and row["scr"] == "1x1" and row["rid"] == "r-1"

    def test_drops_junk_bodies_instead_of_shipping_them(self, driver: Driver, analyst: FakeAnalyst, engines: list[Camada]) -> None:
        h = Host(driver, analyst, engines)
        for junk in (b"not json", b"[1,2]", b"42", b""):
            assert h("POST", "/_cam/fp", body=junk).status == 204
        assert h.events() == []

    def test_rejects_oversized_posts_declared_or_actual(self, driver: Driver, analyst: FakeAnalyst, engines: list[Camada]) -> None:
        h = Host(driver, analyst, engines)
        assert h("POST", "/_cam/fp", body=b"{}", content_length=40000).status == 413
        assert h("POST", "/_cam/fp", body=b"{" + b" " * 33000 + b"}").status == 413
        assert h.events() == []

    def test_falls_through_to_the_app_when_the_tenant_disabled_the_beacon(self, driver: Driver, analyst: FakeAnalyst, engines: list[Camada]) -> None:
        analyst.config["beacon"] = False
        h = Host(driver, analyst, engines)
        assert h("GET", "/_cam/b.js").body == b"hello"
        assert h("POST", "/_cam/fp", body=b"{}").body == b"hello"
        assert h.engine.script_tag(h.seen[0]["camada"]) == ""

    def test_script_tag_carries_the_rid(self, driver: Driver, analyst: FakeAnalyst, engines: list[Camada]) -> None:
        h = Host(driver, analyst, engines)
        r = h("GET", "/")
        assert h.engine.script_tag(h.seen[0]["camada"]) == f'<script src="/_cam/b.js?r={r.header("x-rid")}" async></script>'
        assert h.engine.script_tag(None) == '<script src="/_cam/b.js" async></script>'

    def test_enforcement_comes_before_the_beacon_endpoints(self, driver: Driver, analyst: FakeAnalyst, engines: list[Camada]) -> None:
        h = Host(driver, analyst, engines)
        assert h("GET", "/_cam/b.js", peer=BLOCKED_IP).status == 403


class TestRules:
    @pytest.fixture(autouse=True)
    def v5(self, analyst: FakeAnalyst) -> None:
        analyst.container = "v5"
        hops1(analyst)

    def test_skip_rule_beats_the_wider_block(self, driver: Driver, analyst: FakeAnalyst, engines: list[Camada]) -> None:
        h = Host(driver, analyst, engines)
        assert h("GET", SKIP_PATH, **ip(BLOCKED_IP)).status == 200
        (ev,) = h.events()
        assert "blk" not in ev and "wrn" not in ev

    def test_blocks_by_rule_with_x_block_rule_and_ships_rl(self, driver: Driver, analyst: FakeAnalyst, engines: list[Camada]) -> None:
        h = Host(driver, analyst, engines)
        r = h("GET", "/", **ip(RULE_BLOCKED_IP))
        assert r.status == 403 and r.header("x-block-reason") == "rule" and r.header("x-block-rule") == "builtin:block"
        (ev,) = h.events()
        assert ev["blk"] == "rule" and ev["rl"] == "builtin:block"

    def test_blocks_by_path_ua_and_header_rules(self, driver: Driver, analyst: FakeAnalyst, engines: list[Camada]) -> None:
        h = Host(driver, analyst, engines)
        assert h("GET", RULE_BLOCKED_PATH).header("x-block-rule") == "cr_00000000000c"
        assert h("GET", "/", headers=[("user-agent", BLOCKED_UA)]).status == 403
        assert h("GET", "/", headers=[(BLOCKED_HEADER.upper(), BLOCKED_HEADER_VALUE)]).status == 403   # any spelling
        assert h("GET", "/", headers=[(BLOCKED_HEADER, "other")]).status == 200
        assert h("GET", "/").status == 200

    def test_warn_passes_and_stamps_wrn(self, driver: Driver, analyst: FakeAnalyst, engines: list[Camada]) -> None:
        h = Host(driver, analyst, engines)
        assert h("GET", "/", headers=[("user-agent", WARN_UA)]).status == 200
        (ev,) = h.events()
        assert ev["wrn"] == "cr_00000000000e" and ev["st"] == 200

    def test_still_enforces_against_an_analyst_that_only_publishes_v3(self, driver: Driver, analyst: FakeAnalyst, engines: list[Camada]) -> None:
        analyst.container = "v3"
        h = Host(driver, analyst, engines)
        assert h("GET", "/", **ip(BLOCKED_IP)).status == 403
        assert h("GET", "/", headers=[("user-agent", BLOCKED_UA)]).status == 200   # a rule-only signal: v3 carries no rules


class TestChallenge:
    @pytest.fixture(autouse=True)
    def v4(self, analyst: FakeAnalyst) -> None:
        analyst.container = "v4"

    def test_serves_the_page_for_an_html_navigation_and_ships_blk_challenge(self, driver: Driver, analyst: FakeAnalyst, engines: list[Camada]) -> None:
        h = Host(driver, analyst, engines)
        r = h("GET", "/account?tab=1", headers=HTML, peer=CHALLENGED_IP)
        assert r.status == 403 and r.header("content-type") == "text/html; charset=utf-8"
        assert r.header("x-camada-challenge") == "1" and r.header("cache-control") == "no-store"
        assert 'action="/__camada/challenge"' in r.text and 'name="to" value="/account?tab=1"' in r.text
        assert h.seen == []
        (ev,) = h.events()
        assert ev["st"] == 403 and ev["blk"] == "challenge" and ev["p"] == "/account"

    def test_answers_json_for_a_non_html_request(self, driver: Driver, analyst: FakeAnalyst, engines: list[Camada]) -> None:
        h = Host(driver, analyst, engines)
        r = h("GET", "/api", headers=[("accept", "application/json")], peer=CHALLENGED_IP)
        assert r.status == 403 and r.header("content-type") == "application/json" and json.loads(r.text) == {"error": "challenge_required"}
        r2 = h("GET", "/api", headers=[("accept", "text/html"), ("sec-fetch-dest", "empty")], peer=CHALLENGED_IP)
        assert r2.header("content-type") == "application/json"

    def test_blocks_outright_rather_than_challenging_a_blocked_ip(self, driver: Driver, analyst: FakeAnalyst, engines: list[Camada]) -> None:
        h = Host(driver, analyst, engines)
        r = h("GET", "/", headers=HTML, peer=BLOCKED_IP)
        assert r.status == 403 and r.header("x-camada-challenge") is None

    def test_verify_sets_cch_redirects_back_and_ships_ch_1(self, driver: Driver, analyst: FakeAnalyst, engines: list[Camada]) -> None:
        h = Host(driver, analyst, engines)
        page = h("GET", "/back?x=1", headers=HTML, peer=CHALLENGED_IP).text
        nonce = page.split('name="nonce" value="')[1].split('"')[0]
        form = f"nonce={nonce}&solution={solve(nonce)}&to=%2Fback%3Fx%3D1"
        r = h("POST", "/__camada/challenge", headers=[("content-type", "application/x-www-form-urlencoded")], body=form.encode(), peer=CHALLENGED_IP)
        assert r.status == 302 and r.header("location") == "/back?x=1" and r.header("cache-control") == "no-store"
        cookie = r.header("set-cookie") or ""
        assert cookie.startswith("_cch=") and "HttpOnly" in cookie
        evs = h.events()
        assert evs[-1]["st"] == 200 and evs[-1]["ch"] == 1 and evs[-1]["p"] == "/__camada/challenge"
        # the holder of a valid _cch passes; a cookie minted for another ip does not
        assert h("GET", "/back", headers=[*HTML, ("cookie", cookie.split(";")[0])], peer=CHALLENGED_IP).status == 200
        assert h("GET", "/back", headers=[*HTML, ("cookie", cookie.split(";")[0])], peer="192.0.2.21").status == 200   # not challenged at all
        # a tampered mac: flip the last hex digit (a replace of the first "0" was a no-op on the hashes that had none)
        minted = cookie.split(";")[0][5:]
        tampered = minted[:-1] + ("0" if minted[-1] != "0" else "1")
        assert h("GET", "/back", headers=[*HTML, ("cookie", "_cch=" + tampered)], peer=CHALLENGED_IP).status == 403

    def test_wrong_solution_or_forged_nonce_reserves_the_page(self, driver: Driver, analyst: FakeAnalyst, engines: list[Camada]) -> None:
        h = Host(driver, analyst, engines)
        page = h("GET", "/", headers=HTML, peer=CHALLENGED_IP).text
        nonce = page.split('name="nonce" value="')[1].split('"')[0]
        r = h("POST", "/__camada/challenge", body=f"nonce={nonce}&solution=1&to=%2F".encode(), peer=CHALLENGED_IP)
        assert r.status == 403 and r.header("set-cookie") is None and "camada-f" in r.text
        forged = "f" * 32
        r = h("POST", "/__camada/challenge", body=f"nonce={forged}&solution={solve(forged)}&to=%2F".encode(), peer=CHALLENGED_IP)
        assert r.status == 403 and r.header("set-cookie") is None

    def test_never_redirects_off_site(self, driver: Driver, analyst: FakeAnalyst, engines: list[Camada]) -> None:
        h = Host(driver, analyst, engines)
        nonce = h.engine.kit.nonce(CHALLENGED_IP, h.engine.now_ms())   # type: ignore[union-attr]
        r = h("POST", "/__camada/challenge", body=f"nonce={nonce}&solution={solve(nonce)}&to=https%3A%2F%2Fevil".encode(), peer=CHALLENGED_IP)
        assert r.status == 302 and r.header("location") == "/"

    def test_refuses_an_oversized_verify_body(self, driver: Driver, analyst: FakeAnalyst, engines: list[Camada]) -> None:
        h = Host(driver, analyst, engines)
        assert h("POST", "/__camada/challenge", body=b"a=" + b"b" * 5000, peer=CHALLENGED_IP).status == 413

    def test_no_ip_means_no_challenge(self, driver: Driver, analyst: FakeAnalyst, engines: list[Camada]) -> None:
        h = Host(driver, analyst, engines)
        assert h("GET", "/", headers=HTML, peer=None).status == 200

    def test_switched_off_by_env_or_option(self, driver: Driver, analyst: FakeAnalyst, engines: list[Camada]) -> None:
        assert Host(driver, analyst, engines, {"CAMADA_CHALLENGE": "0"})("GET", "/", headers=HTML, peer=CHALLENGED_IP).status == 200
        assert Host(driver, analyst, engines, challenge=False)("GET", "/", headers=HTML, peer=CHALLENGED_IP).status == 200

    def test_serve_challenge_on_demand(self, driver: Driver, analyst: FakeAnalyst, engines: list[Camada]) -> None:
        def gated(req: dict[str, Any]) -> tuple[int, list[tuple[str, str]], bytes]:
            answer = h.engine.serve_challenge(req["camada"])
            if answer:
                return answer.status, answer.headers, answer.body
            return 200, [], b"secret page"

        h = Host(driver, analyst, engines, handler=gated)
        r = h("GET", "/challenge-me", headers=HTML)
        assert r.status == 403 and "camada-f" in r.text
        evs = h.events()
        assert len(evs) == 1 and evs[0]["blk"] == "challenge"   # one request, one event
        nonce = r.text.split('name="nonce" value="')[1].split('"')[0]
        ok = h("POST", "/__camada/challenge", body=f"nonce={nonce}&solution={solve(nonce)}&to=%2Fchallenge-me".encode())
        cookie = (ok.header("set-cookie") or "").split(";")[0]
        assert h("GET", "/challenge-me", headers=[*HTML, ("cookie", cookie)]).body == b"secret page"


class TestFailOpen:
    def test_keeps_serving_when_ingest_is_down(self, driver: Driver, analyst: FakeAnalyst, engines: list[Camada]) -> None:
        analyst.ingest_down = True
        h = Host(driver, analyst, engines)
        assert h("GET", "/").status == 200
        assert h.events() == [] and h.engine.queue.dropped == 1   # type: ignore[union-attr]

    def test_disabled_bypasses_the_sdk_entirely(self, driver: Driver, analyst: FakeAnalyst, engines: list[Camada]) -> None:
        h = Host(driver, analyst, engines, {"CAMADA_DISABLED": "1"}, load=False)
        assert h.engine.snap is None and h.engine.disabled
        r = h("GET", "/", peer=BLOCKED_IP)
        assert r.status == 200 and r.header("x-rid") is None and analyst.snapshot_requests == []

    def test_stays_inert_without_credentials(self, driver: Driver, analyst: FakeAnalyst, engines: list[Camada]) -> None:
        h = Host(driver, analyst, engines, {"CAMADA_KEY": ""}, load=False)
        assert h.engine.env is None
        assert h("GET", "/", peer=BLOCKED_IP).status == 200
        assert h.engine.script_tag(None) == "" and h.engine.serve_challenge(None) is None
        h.engine.track(None, "x")

    def test_a_camada_bug_costs_the_join_not_the_request(self, driver: Driver, analyst: FakeAnalyst, engines: list[Camada], monkeypatch: pytest.MonkeyPatch) -> None:
        h = Host(driver, analyst, engines)
        monkeypatch.setattr(h.engine, "_decide", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("sdk bug")))
        r = h("GET", "/", peer=BLOCKED_IP)
        assert r.status == 200 and r.body == b"hello"
