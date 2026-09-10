# FastAPI / Starlette integration: `app.add_middleware(CamadaMiddleware)` — the pure ASGI
# middleware, so streaming responses and lifespan are untouched — then `script_tag(request)`
# in templates, `track(request, "login_failed", user=email)` in handlers, and
# `serve_challenge(request)` for a route the app gates itself.
from __future__ import annotations

from typing import Any

from starlette.responses import Response

from . import engine_for
from .asgi import CamadaASGI as CamadaMiddleware


def _ctx(request: Any) -> dict[str, Any] | None:
    ctx = getattr(request, "scope", {}).get("camada")
    return ctx if isinstance(ctx, dict) else None


def script_tag(request: Any) -> str:
    ctx = _ctx(request)
    return engine_for(ctx).script_tag(ctx)


def track(request: Any, event: str, user: str | None = None) -> None:
    ctx = _ctx(request)
    engine_for(ctx).track(ctx, event, user)


def serve_challenge(request: Any) -> Response | None:
    """The proof-of-work page (or 403 JSON) to return from a route you gate yourself; None once
    the browser holds a valid _cch, or when the client cannot be identified (fail open)."""
    ctx = _ctx(request)
    a = engine_for(ctx).serve_challenge(ctx)
    return None if a is None else Response(content=a.body, status_code=a.status, headers=dict(a.headers))


__all__ = ["CamadaMiddleware", "script_tag", "serve_challenge", "track"]
