# FastAPI / Starlette integration: `app.add_middleware(CamadaMiddleware)` — the pure ASGI
# middleware, so streaming responses and lifespan are untouched — then `script_tag(request)`
# in templates and `track(request, "login_failed", user=email)` in handlers.
from __future__ import annotations

from typing import Any

from . import get_default
from .asgi import CamadaASGI as CamadaMiddleware
from .engine import engine_of


def _ctx(request: Any) -> dict[str, Any] | None:
    ctx = getattr(request, "scope", {}).get("camada")
    return ctx if isinstance(ctx, dict) else None


def script_tag(request: Any) -> str:
    ctx = _ctx(request)
    return (engine_of(ctx) or get_default()).script_tag(ctx)


def track(request: Any, event: str, user: str | None = None) -> None:
    ctx = _ctx(request)
    (engine_of(ctx) or get_default()).track(ctx, event, user)


__all__ = ["CamadaMiddleware", "script_tag", "track"]
