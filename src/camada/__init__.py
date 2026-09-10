"""camada for Python: inline enforcement of your tenant snapshot (ordered custom rules, then
block, allow, challenge), a first-party proof-of-work challenge and beacon, app-context events,
and batched wire events shipped off the request path. Fails open by design.

Quickstart (env: CAMADA_KEY, plus CAMADA_INGEST_URL in dev):

    # FastAPI / Starlette
    from camada.fastapi import CamadaMiddleware
    app.add_middleware(CamadaMiddleware)

    # Django: MIDDLEWARE = ["camada.django.CamadaMiddleware", ...]
    # Flask:  camada.flask.init_app(app)
    # Any ASGI / WSGI app: camada.asgi.CamadaASGI(app) / camada.wsgi.CamadaWSGI(app)
"""
from __future__ import annotations

from typing import Any

from .engine import Answer, Camada, Passed, Req, create_camada
from .version import SDK_ID, __version__

__all__ = ["Answer", "Camada", "Passed", "Req", "SDK_ID", "__version__", "configure", "create_camada", "get_default"]

_default: Camada | None = None


def get_default(**opts: Any) -> Camada:
    """The lazy singleton wired from the environment on first use (what the integrations share)."""
    global _default
    if _default is None:
        _default = create_camada(**opts)
    return _default


def configure(**opts: Any) -> Camada:
    """Replaces the default engine (stopping the old one) — for tests and explicit wiring."""
    global _default
    if _default is not None:
        _default.stop()
    _default = create_camada(**opts)
    return _default
