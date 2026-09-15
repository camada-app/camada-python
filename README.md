# camada

camada for Python: enforces the tenant snapshot inline (your ordered custom rules, then allow,
block, challenge), serves a first-party proof-of-work challenge page and beacon, records the
outcomes your handlers know (`track()`), and ships wire events in batches off the request path.
One package on PyPI with an ASGI middleware (the first-class tier: it keeps the wire's header
order), a WSGI middleware, and integrations for FastAPI, Django and Flask — the `sentry-sdk`
model. Fails open by design: a camada outage or bug never 5xxes your app.

Not yet on PyPI — install it from a sibling checkout: `pip install -e ../camada-python` (or a uv
path dependency, as [`camada-python-example`](../camada-python-example) does); publishing is one
decision with the npm packages (SDK-G01). Python 3.10 or newer, no runtime dependencies.

## Quickstart

```python
# FastAPI / Starlette
from camada.fastapi import CamadaMiddleware
app.add_middleware(CamadaMiddleware)   # last, so it runs outermost

# Django — settings.py
MIDDLEWARE = ["camada.django.CamadaMiddleware", *MIDDLEWARE]   # first

# Flask
from camada.flask import init_app
init_app(app)   # wraps app.wsgi_app, so camada answers before routing

# any ASGI 3 or WSGI app
from camada.asgi import CamadaASGI      # application = CamadaASGI(application)
from camada.wsgi import CamadaWSGI      # application = CamadaWSGI(application)
```

Env (printed by camada onboarding / `npm run seed` in dev):

```
CAMADA_KEY=<ingest_token>.<snap_token>
CAMADA_INGEST_URL=http://localhost:8787        # dev only; defaults to production ingest
```

The integrations share one lazy engine built from the environment on the first request. That
build starts the snapshot poll on a thread and never blocks, so the request that triggered it is
answered cold: it passes (fail open), and so does anything else that arrives before that first
poll lands (a few hundred milliseconds against a local analyst; snapshot-size and network bound).
To enforce from request 1, warm the engine in a startup hook by waiting for the boot poll —
`snap.refresh()` alone is not it, the boot poll already holds the single-in-flight lock:

```python
import time
import camada
from camada.snapshot.match import MatchInput

engine = camada.get_default()   # builds the engine; the boot poll is already running on its thread
if engine.snap:                 # None when CAMADA_KEY is unset or CAMADA_DISABLED=1
    deadline = time.monotonic() + 5
    while engine.snap.verdict(MatchInput(ip="0.0.0.0")).reason == "cold" and time.monotonic() < deadline:
        time.sleep(0.01)        # bounded: an unreachable analyst leaves it cold, and the app still fails open
```

`snap.refresh()` is not the warm-up: the boot poll holds the single-in-flight lock, so a
synchronous `refresh()` called right after `get_default()` returns at once and the engine is
still cold.

Without `CAMADA_KEY` the engine is inert (one log line, no requests, no enforcement). An app that
reads its own config builds the engine itself and hands it in:

```python
from camada import Camada
engine = Camada(env={"CAMADA_KEY": MY_KEY, "CAMADA_INGEST_URL": MY_INGEST})
app.add_middleware(CamadaMiddleware, engine=engine)      # init_app(app, engine=engine) for Flask
```

## What it does per request

1. Keeps the snapshot fresh. A Python server is a long-lived process, so the default is a daemon
   poll thread at the cadence your tenant config sets (`poll_seconds`), with ETag/304 and gzip on
   the wire. `CAMADA_SERVERLESS=1` switches to a per-request staleness check with no thread. Every
   poll and event batch carries `x-camada-sdk: @camada/python/<version>`, and polls ask for
   snapshot v5 (`x-camada-snapshot: 5`) — the container that carries your ordered custom rules.
2. Resolves the client from the socket peer (`REMOTE_ADDR` / `scope["client"]`), combined with
   `X-Forwarded-For` only under your tenant's trusted-proxy config (or `CAMADA_TRUSTED_PROXY`
   locally). A forwarded header on its own is never the ip: any caller can set it.
3. Enforces before anything else, beacon endpoints included: your ordered custom rules first (first
   match wins; they read ip, path, user-agent and request headers), then allow → block → challenge.
   A block answers `403 Forbidden` with `x-block-reason`, `x-block-version` and, when a rule
   decided, `x-block-rule`; its event ships with `blk` (and `rl`). A `warn` rule passes and stamps
   `wrn`; a `skip` rule passes with nothing stamped. Cold (no snapshot yet) passes: fail open.
4. Challenge: a `challenge` verdict gets the self-contained proof-of-work page (or 403 JSON for a
   non-HTML request); `POST /__camada/challenge` verifies the solution, sets `_cch` (bound to the
   ip, one hour) and 302s back. A request whose ip cannot be resolved is never challenged.
5. Serves the beacon: `GET /_cam/b.js` (the `@camada/browser` build, vendored) and `POST /_cam/fp`
   (≤ 32 KB, relayed onto the event batch as a `sig: 1` row with the ip camada resolved). Both
   fall through to your app when the tenant switched the beacon off.
6. Runs your app with `x-rid` and the `_sfp` session cookie on its response, and when the response
   is done ships one redacted event: method, host, path, scrubbed query, status, latency, header
   names/sizes/order, the auth scheme (never the credential), cookie count (never values). An
   exception in your app ships as `st: 500` and propagates unchanged.

## Options

`Camada(...)` keyword arguments; everything credential-shaped comes from the environment.

| option | default | meaning |
|---|---|---|
| `env` | `os.environ` | where `CAMADA_*` are read from |
| `transport` | urllib | the HTTP callable that reaches the analyst (tests inject a fake) |
| `refresh_s` | server-steered | poll cadence; set, it is pinned |
| `challenge` | `True` | serve the proof-of-work page for challenge verdicts (`CAMADA_CHALLENGE=0` too) |
| `challenge_path` | `/__camada/challenge` | where the page posts its solution |
| `snapshot_version` | `5` | 4 drops your custom rules; 3 the allow/challenge sides too |
| `script_path` / `fp_path` | `/_cam/b.js` / `/_cam/fp` | the beacon endpoints; keep them in one directory |

Env: `CAMADA_KEY` (or `CAMADA_TOKEN` + `CAMADA_SNAPSHOT_TOKEN`), `CAMADA_INGEST_URL`,
`CAMADA_SNAPSHOT_URL`, `CAMADA_TRUSTED_PROXY` (`none | vercel | hops:N | cidrs:a,b`),
`CAMADA_SERVERLESS=1`, `CAMADA_CHALLENGE=0`, and the kill switch `CAMADA_DISABLED=1` (checked per
request; set at boot, no threads start at all).

## The first-party beacon

```python
from camada.fastapi import script_tag        # camada.django: script_tag(request); camada.flask: script_tag()
return HTMLResponse(f"<html><head>{script_tag(request)}</head>…")
```

The tag is `<script src="/_cam/b.js?r=<rid>" async>`, so the beacon joins the page view that
served it. Move both paths with `script_path` / `fp_path` when `/_cam/` is not yours; the script
derives the post path from its own URL, so the two must share a directory.

## App-context events

```python
from camada.fastapi import track             # camada.django: track(request, ...); camada.flask: track(event, user=...)
track(request, "login_failed", user=email)
```

The identifier is HMAC-hashed in-process with your ingest token; the raw value never reaches the
queue. `track()` never raises. Outside the middleware (a request it did not run for) the outcome
still ships, with no `rid`/`sid`/`ip` to join on — and it builds the default engine from the
environment if nothing has yet. The event name is free-form; the analyst's app-context rules read
this vocabulary:

| event | when |
|---|---|
| `login_failed` / `login_succeeded` | a login attempt settled; pass `user=` so attempts per account can be counted |
| `signup` | an account was created |
| `password_reset` | a reset was requested |
| `mfa_failed` | a second factor was rejected |
| `payment_failed` / `payment_succeeded` | a payment authorisation settled |
| `coupon_failed` | a promo/voucher code was rejected |

A route you gate yourself: `serve_challenge(request)` (Flask: `serve_challenge()`) returns the
page as a framework response to return from the handler until the browser holds a valid `_cch`,
then `None`.

## What this tap can see

`sdk-python` is an in-app tap: status, latency, session, the beacon's browser signals and your
outcomes. Under ASGI the event also carries the wire's header order (`hord`); WSGI's `environ`
loses it, which is why ASGI is the first-class tier. The analyst knows what this tap can see and
never scores the absence of header order, ASN, country or a TLS fingerprint against a request;
ASN and country it resolves itself. Enforcement at this position covers ip, path, user-agent and
header conditions — ASN, country and TLS entries fail open in-app. `matches` patterns are JS
regexes read by Python's `re` (named groups, `[^]` and `\cX` are translated, `\d`/`\w`/`\b` stay
ASCII); a spelling `re` still rejects never matches here, while it does at the edge.

## Deploying it

- Every worker process polls its own snapshot (about 5 MB resident) and flushes its own batches;
  the tenant's `poll_seconds` keeps the cadence honest across a fleet.
- Threads do not survive a fork. Under gunicorn `--preload` or uWSGI the SDK notices the fork
  (`os.register_at_fork`) and restarts its poll and flush threads in each worker.
- Pending events drain at interpreter exit within half a second. No signal handlers are
  installed — an app owns its own shutdown — so a worker killed by SIGTERM without one may drop
  its last batch.
- Serverless: `CAMADA_SERVERLESS=1`. A cold invocation fails open and catches up on the next one.

## Fail open

Every entry point runs inside the fail-open envelope: a dead ingest drops telemetry (logged at
most once a minute), a corrupt snapshot keeps the previous one, a bug in the package costs the
request its join, never its response. `CAMADA_DISABLED=1` bypasses everything.

## Development

```
uv sync && uv run ruff check && uv run mypy && uv run pytest
```

The suite reads the golden snapshot fixtures from the `camada-core` sibling checkout and pins the
vendored beacon to `camada-browser/dist/auto.global.js` (`npm run build` there first, then
`python scripts/sync_beacon.py` after a beacon release). Both fail by name when the checkout is
missing rather than skipping.

[`camada-python-example`](../camada-python-example) is the hand-test bench (FastAPI under uvicorn on
:3002), and `node scripts/e2e-sdk-python.mjs` in `camada/edge-analyst` drives it against a seeded
local analyst over real HTTP, cold first request included.
