# Flask integration: `camada.flask.init_app(app)` wraps app.wsgi_app so camada answers before
# routing; `script_tag()` and `track("login_failed", user=email)` read the current request.
from __future__ import annotations

from typing import Any

from flask import Flask, request

from . import get_default
from .engine import Camada, engine_of
from .wsgi import CamadaWSGI


def init_app(app: Flask, engine: Camada | None = None, **opts: Any) -> CamadaWSGI:
    wrapped = CamadaWSGI(app.wsgi_app, engine, **opts)
    app.wsgi_app = wrapped  # type: ignore[method-assign]
    app.extensions["camada"] = wrapped

    @app.teardown_request
    def _route(_exc: BaseException | None) -> None:
        # the matched rule is known here, before the WSGI wrapper's close() ships the event
        ctx = request.environ.get("camada")
        rule = request.url_rule
        if ctx is not None and rule is not None and ctx.get("_req") is not None:
            ctx["_req"].route = rule.rule

    return wrapped


def _ctx() -> dict[str, Any] | None:
    ctx = request.environ.get("camada")
    return ctx if isinstance(ctx, dict) else None


def script_tag() -> str:
    ctx = _ctx()
    return (engine_of(ctx) or get_default()).script_tag(ctx)


def track(event: str, user: str | None = None) -> None:
    ctx = _ctx()
    (engine_of(ctx) or get_default()).track(ctx, event, user)


__all__ = ["init_app", "script_tag", "track"]
