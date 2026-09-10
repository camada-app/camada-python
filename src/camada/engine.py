# The engine: the host-neutral request handling every adapter delegates to (the Python twin of
# @camada/node's Camada.handle). An adapter turns its request into a Req, asks wants_body() and
# reads at most that many bytes, then calls handle(): an Answer means camada fully answered the
# request (block, challenge, verify, beacon endpoints); a Passed means run the app, stamp the
# rid header and session cookie on its response, and call on_finish(status) once when it is
# done. Everything runs inside the fail-open envelope: a camada bug must never 5xx the customer,
# and CAMADA_DISABLED=1 bypasses the SDK entirely.
from __future__ import annotations

import json
import os
import random
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from http import HTTPStatus
from typing import Any

from . import constants as C
from .beacon_js import BEACON_JS
from .challenge.format import CHALLENGE_COOKIE, challenge_cookie, parse_form_body, safe_return_to, wants_html
from .challenge.page import challenge_page
from .challenge.verify import ChallengeKit, create_challenge
from .config import TrustedProxy
from .env import Env, resolve_env
from .events.build import RequestInfo, build_wire_event, now_ms
from .events.queue import EventQueue
from .guarded import log_rate_limited
from .ip import resolve_client_ip
from .redact import hash_user_id
from .snapshot.client import SnapshotClient
from .snapshot.match import MatchInput
from .transport import Transport
from .version import SDK_ID

Headers = list[tuple[str, str]]


@dataclass(slots=True)
class Req:
    """What an adapter hands the engine. Header names are lower-cased; the list keeps the order
    the host gave (true wire order under ASGI, the environ's under WSGI)."""

    method: str
    path: str                       # no query
    query: str = ""                 # with the leading '?', or ''
    host: str = ""
    http_version: str | None = None
    peer: str | None = None         # the socket peer the host vouches for
    https: bool = False
    headers: Headers = field(default_factory=list)
    route: str | None = None        # the matched route pattern, when the host knows it at finish time

    def header(self, name: str) -> str | None:
        """A header the client repeated is joined the way node:http does it: cookies with '; ' (HTTP/2
        clients split them into several fields; cookie_value() looks for '; name='), the rest with ', '."""
        vals = [v for k, v in self.headers if k == name]
        if not vals:
            return None
        return ("; " if name == "cookie" else ", ").join(vals)


@dataclass(slots=True)
class Answer:
    """camada answered the request; the adapter writes exactly this."""

    status: int
    headers: Headers
    body: bytes

    @property
    def reason(self) -> str:
        try:
            return HTTPStatus(self.status).phrase
        except ValueError:
            return "Unknown"


@dataclass(slots=True)
class Passed:
    """Run the app. rid/set_cookie ride the response; ctx is stored on the host request
    (environ['camada'] / scope['camada']); on_finish(status) is called once at the end."""

    rid: str | None
    set_cookie: str | None
    ctx: dict[str, Any] | None
    on_finish: Callable[[int], None] | None


INERT = Passed(None, None, None, None)


def cookie_value(cookie: str | None, name: str) -> str | None:
    src = "; " + (cookie or "")
    i = src.find("; " + name + "=")
    if i == -1:
        return None
    start = i + len(name) + 3
    j = src.find(";", start)
    return src[start:] if j == -1 else src[start:j]


class Camada:
    def __init__(
        self,
        *,
        env: Mapping[str, str] | None = None,
        transport: Transport | None = None,     # threaded into the snapshot client and event queue (tests)
        refresh_s: float | None = None,
        script_path: str = C.SCRIPT_PATH,
        fp_path: str = C.FP_PATH,
        challenge: bool = True,                 # enforce `challenge` verdicts with the first-party page (CAMADA_CHALLENGE=0 also off)
        challenge_path: str = C.CHALLENGE_PATH,
        snapshot_version: int = C.DEFAULT_SNAPSHOT_VERSION,
    ) -> None:
        source: Mapping[str, str] = env if env is not None else os.environ
        self._env_source = source
        self.script_path, self.fp_path, self.challenge_path = script_path, fp_path, challenge_path
        self.challenge_on = challenge and source.get("CAMADA_CHALLENGE") != "0"
        self.env: Env | None = resolve_env(source)
        self.snap: SnapshotClient | None = None
        self.queue: EventQueue | None = None
        self.kit: ChallengeKit | None = None
        if self.env is None or source.get(C.KILL_SWITCH_ENV) == "1":
            return   # unconfigured or killed at boot: no threads, no exit hooks, truly silent
        self.snap = SnapshotClient(
            self.env.snapshot_url, self.env.snap_token, refresh_s=refresh_s, mode="lazy" if self.env.serverless else "timer",
            transport=transport, sdk=SDK_ID, snapshot_version=snapshot_version,
        )
        self.queue = EventQueue(self.env.ingest_url, self.env.ingest_token, transport=transport, sdk=SDK_ID)
        self.kit = create_challenge(self.env.secret)
        self.snap.start()
        self.queue.install_exit_flush()

    @property
    def disabled(self) -> bool:
        return self.env is None or self._env_source.get(C.KILL_SWITCH_ENV) == "1"

    @staticmethod
    def now_ms() -> int:
        return now_ms()

    def _trusted_proxy(self) -> TrustedProxy | None:
        if self.env and self.env.trusted_proxy is not None:
            return self.env.trusted_proxy   # explicit local override wins
        return (self.snap.config or {}).get("trusted_proxy") if self.snap else None

    def _beacon_enabled(self) -> bool:
        return self.snap is not None and (self.snap.config or {}).get("beacon") is not False

    def _ip(self, req: Req) -> str | None:
        return resolve_client_ip(req.peer, req.header("x-forwarded-for"), self._trusted_proxy())

    # ---- the adapter contract ----

    def wants_body(self, method: str, path: str) -> int | None:
        """The byte cap to read the body under, when camada itself may answer this request."""
        if self.disabled or method != "POST":
            return None
        if path == self.fp_path and self._beacon_enabled():
            return C.FP_MAX
        if path == self.challenge_path and self.challenge_on:
            return C.BODY_MAX
        return None

    def handle(self, req: Req, body: bytes | None = None) -> Answer | Passed:
        """Never raises. `body` is the request body when wants_body() asked for one, or None when
        the adapter refused to read it (declared or actual size over the cap)."""
        try:
            return self._decide(req, body)
        except Exception as err:   # a camada bug costs the join, never the request (node's handle() returns false too)
            log_rate_limited(err)
            return INERT

    def _decide(self, req: Req, body: bytes | None) -> Answer | Passed:
        if self.disabled or self.snap is None or self.queue is None or self.env is None:
            return INERT
        queue = self.queue
        t0 = time.monotonic()
        self.snap.ensure_fresh()
        ip = self._ip(req)

        # Enforce before anything else, beacon endpoints included — fail open while cold. The
        # custom rules read the user agent and the request headers (§D3).
        v = self.snap.verdict(MatchInput(ip=ip, path=req.path, ua=req.header("user-agent"), header=req.header))
        if v.block:
            headers: Headers = [("content-type", "text/plain"), ("x-block-reason", v.reason or ""), ("x-block-version", v.version or "")]
            if v.rule:
                headers.append(("x-block-rule", v.rule))   # a custom rule blocked: name it, so the customer knows which row to edit
            ev = self._event(req, str(uuid.uuid4()), None, False, ip)
            ev["st"] = 403   # blocked requests always ship: silent expiry makes blocks oscillate
            ev["blk"] = v.reason   # the reason rides the event so the analyst counts SDK blocks, not the app's own 403s
            if v.rule:
                ev["rl"] = v.rule
            queue.push(ev)
            return Answer(403, headers, b"Forbidden")
        # `warn` passes the request and only marks its event (below, on finish); a skip passes
        # with nothing stamped at all — it is the absence of enforcement.

        # A challenge needs a resolved client IP: the nonce and the _cch cookie are bound to it,
        # so without one a single solve would mint a cookie every unidentified client could
        # present. No ip -> no challenge (fail open), the same stance ip rules take.
        if self.challenge_on and ip:
            # The verify endpoint answers first: a challenged client must be able to reach it.
            if req.method == "POST" and req.path == self.challenge_path:
                return self._verify(req, body, ip)
            if v.challenge and not self._challenge_passed(req, ip):
                return self._serve_challenge(req, ip, sid=cookie_value(req.header("cookie"), C.SESSION_COOKIE))

        if self._beacon_enabled():
            if req.method == "GET" and req.path == self.script_path:
                js_headers: Headers = [("content-type", "application/javascript"), ("cache-control", "public, max-age=3600")]
                return Answer(200, js_headers, BEACON_JS.encode())
            if req.method == "POST" and req.path == self.fp_path:
                return self._relay_beacon(body, ip)

        rid = str(uuid.uuid4())
        sid = cookie_value(req.header("cookie"), C.SESSION_COOKIE)
        new_session = not sid
        set_cookie = None
        if not sid:
            sid = str(uuid.uuid4())
            secure = req.https or req.header("x-forwarded-proto") == "https"
            set_cookie = f"{C.SESSION_COOKIE}={sid}; Path=/; Max-Age={C.SESSION_MAX_AGE}; HttpOnly; SameSite=Lax"
            if secure:
                set_cookie += "; Secure"
        ctx: dict[str, Any] = {"rid": rid, "sid": sid, "ip": ip, "_req": req, "_engine": self}

        cfg = self.snap.config or {}
        excluded = any(req.path.startswith(x) for x in cfg.get("exclude") or [])
        sample = cfg.get("sample")
        sampled = random.random() < (1.0 if sample is None else float(sample))   # sampling, not crypto
        warn_rule = v.rule if v.warn else None

        def on_finish(status: int) -> None:
            try:
                # serve_challenge() may have answered from inside the app, and it already shipped
                # the `blk: "challenge"` row — one request, one event.
                if ctx.get("challenged") or excluded or not sampled:
                    return
                ev = self._event(req, rid, sid, new_session, ip)
                ev["st"], ev["dur"] = status, int((time.monotonic() - t0) * 1000)
                if req.route:
                    ev["rt"] = req.route
                if warn_rule:
                    ev["wrn"] = warn_rule   # §D3: the warn rule that let this request through
                queue.push(ev)
            except Exception as err:
                log_rate_limited(err)

        return Passed(rid, set_cookie, ctx, on_finish)

    def _event(self, req: Req, rid: str, sid: str | None, new_session: bool, ip: str | None) -> dict[str, Any]:
        info = RequestInfo(
            method=req.method, host=req.host, path=req.path, query=req.query, headers=req.headers, ip=ip, http_version=req.http_version
        )
        return build_wire_event(info, tap=C.TAP, rid=rid, sid=sid, new_session=new_session)

    # ---- beacon ----

    def _relay_beacon(self, body: bytes | None, ip: str | None) -> Answer:
        """Answers 204, and queues the beacon as a `sig: 1` row with the trusted-proxy-resolved
        client IP: it rides the next event batch. Junk bodies are dropped, never shipped."""
        if body is None:
            return Answer(413, [], b"")
        answer = Answer(204, [("cache-control", "no-store")], b"")
        try:
            parsed = json.loads(body)
        except ValueError:
            return answer
        if not isinstance(parsed, dict):
            return answer
        assert self.queue is not None
        self.queue.push({**parsed, "sig": 1, "ip": ip, "tap": C.TAP})   # spread first: ip and tap are the server's word
        return answer

    def script_tag(self, ctx: Mapping[str, Any] | None) -> str:
        """For HTML templates: the first-party beacon tag with the request's rid."""
        if self.disabled or not self._beacon_enabled():
            return ""
        rid = ctx.get("rid") if ctx else None
        return f'<script src="{self.script_path}{f"?r={rid}" if rid else ""}" async></script>'

    # ---- challenge ----

    def _challenge_passed(self, req: Req, ip: str | None) -> bool:
        return bool(self.kit and self.kit.token_valid(ip, self.now_ms(), cookie_value(req.header("cookie"), CHALLENGE_COOKIE)))

    def _page(self, ip: str, to: str) -> Answer:
        assert self.kit is not None
        html = challenge_page(nonce=self.kit.nonce(ip, self.now_ms()), action=self.challenge_path, to=to)
        headers: Headers = [("content-type", "text/html; charset=utf-8"), ("cache-control", "no-store"), ("x-camada-challenge", "1")]
        return Answer(403, headers, html.encode())

    def _serve_challenge(self, req: Req, ip: str, sid: str | None) -> Answer:
        """403 + the proof-of-work page (HTML navigations) or 403 JSON (everything else), plus the
        `blk: "challenge"` event — a served challenge is reported like a block (contract §D2)."""
        to = safe_return_to(req.path + req.query)
        if wants_html(req.header("accept"), req.header("sec-fetch-dest")):
            answer = self._page(ip, to)
        else:
            headers: Headers = [("content-type", "application/json"), ("cache-control", "no-store"), ("x-camada-challenge", "1")]
            answer = Answer(403, headers, b'{"error":"challenge_required"}')
        try:
            assert self.queue is not None
            ev = self._event(req, str(uuid.uuid4()), sid, False, ip)
            ev["st"], ev["blk"] = 403, "challenge"
            self.queue.push(ev)
        except Exception as err:   # the response is decided; telemetry must never undo that
            log_rate_limited(err)
        return answer

    def _verify(self, req: Req, body: bytes | None, ip: str) -> Answer:
        """POST from the challenge page: validate the nonce and the proof of work, set _cch, 302
        back to the (sanitised, same-site) original URL, and ship `{ st: 200, ch: 1 }`."""
        assert self.kit is not None and self.queue is not None
        if body is None:
            return Answer(413, [], b"")
        form = parse_form_body(body.decode("utf-8", "replace"))
        to = safe_return_to(form.get("to"))
        now = self.now_ms()
        if not self.kit.verify(ip, now, form.get("nonce"), form.get("solution")):
            return self._page(ip, to)
        secure = req.https or req.header("x-forwarded-proto") == "https"
        cookie = challenge_cookie(self.kit.issue(ip, now), secure)
        headers: Headers = [("location", to), ("set-cookie", cookie), ("cache-control", "no-store")]
        ev = self._event(req, str(uuid.uuid4()), cookie_value(req.header("cookie"), C.SESSION_COOKIE), False, ip)
        ev["st"], ev["ch"] = 200, 1   # challenge passed (contract §A3 ingest field)
        self.queue.push(ev)
        return Answer(302, headers, b"")

    def serve_challenge(self, ctx: Mapping[str, Any] | None) -> Answer | None:
        """Serve the challenge for this request on demand — for a route the app wants to gate
        itself. None when the client already holds a valid _cch (render your own page), or when
        the client cannot be identified (fail open)."""
        try:
            if self.disabled or not self.kit or not ctx:
                return None
            req: Req | None = ctx.get("_req")
            ip = ctx.get("ip")
            if req is None or not ip or self._challenge_passed(req, ip):
                return None
            if isinstance(ctx, dict):
                ctx["challenged"] = True
            return self._serve_challenge(req, ip, sid=ctx.get("sid"))
        except Exception as err:
            log_rate_limited(err)
            return None

    # ---- app-context events ----

    def track(self, ctx: Mapping[str, Any] | None, event: str, user: str | None = None) -> None:
        """App-context outcome events (login failed, signup, ...). The identifier is HMAC-hashed
        in-process; the raw value never reaches the queue."""
        try:
            if self.disabled or self.queue is None or self.env is None:
                return
            uid = hash_user_id(user, self.env.ingest_token) if user else None
            c = ctx or {}
            row = {"tap": C.TAP, "et": event, "uid": uid, "rid": c.get("rid"), "sid": c.get("sid"), "ip": c.get("ip"), "ts": self.now_ms()}
            self.queue.push(row)
        except Exception as err:
            log_rate_limited(err)

    def stop(self) -> None:
        if self.snap:
            self.snap.stop()
        if self.queue:
            self.queue.stop()


def engine_of(ctx: Mapping[str, Any] | None) -> Camada | None:
    """The engine that produced a request context (integrations resolve script_tag/track through it)."""
    eng = ctx.get("_engine") if ctx else None
    return eng if isinstance(eng, Camada) else None


def create_camada(**opts: Any) -> Camada:
    c = Camada(**opts)
    if c.env is None:
        log_rate_limited("CAMADA_KEY (or CAMADA_TOKEN + CAMADA_SNAPSHOT_TOKEN) not set — camada is inactive")
    return c
