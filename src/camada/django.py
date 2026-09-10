# Django integration: `MIDDLEWARE = ["camada.django.CamadaMiddleware", ...]` (put it first, so
# camada answers before anything else runs), then `script_tag(request)` in templates and
# `track(request, "login_failed", user=email)` in views. Works on sync and async stacks.
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from asgiref.sync import iscoroutinefunction, markcoroutinefunction
from django.http import HttpRequest, HttpResponse, HttpResponseBase

from . import constants as C
from . import get_default
from .engine import Answer, Camada, Passed, engine_of
from .guarded import log_rate_limited
from .wsgi import req_from_environ

GetResponse = Callable[[HttpRequest], Any]


def _engine(request: HttpRequest) -> Camada:
    return engine_of(getattr(request, "camada", None)) or get_default()


def script_tag(request: HttpRequest) -> str:
    return _engine(request).script_tag(getattr(request, "camada", None))


def track(request: HttpRequest, event: str, user: str | None = None) -> None:
    _engine(request).track(getattr(request, "camada", None), event, user)


def _answer(a: Answer) -> HttpResponse:
    r = HttpResponse(a.body, status=a.status)
    del r["content-type"]
    for k, v in a.headers:
        r[k] = v
    return r


class CamadaMiddleware:
    sync_capable = True
    async_capable = True

    def __init__(self, get_response: GetResponse, engine: Camada | None = None) -> None:
        self.get_response = get_response
        self._engine = engine
        self._async = iscoroutinefunction(get_response)
        if self._async:
            markcoroutinefunction(self)

    @property
    def engine(self) -> Camada:
        return self._engine or get_default()

    def __call__(self, request: HttpRequest) -> Any:
        if self._async:
            return self._acall(request)
        started = self._before(request)
        if isinstance(started, HttpResponse):
            return started
        try:
            response = self.get_response(request)
        except BaseException:
            self._finish(request, started, 500)
            raise
        return self._after(request, started, response)

    async def _acall(self, request: HttpRequest) -> Any:
        started = self._before(request)
        if isinstance(started, HttpResponse):
            return started
        try:
            response = await self.get_response(request)
        except BaseException:
            self._finish(request, started, 500)
            raise
        return self._after(request, started, response)

    def _before(self, request: HttpRequest) -> HttpResponse | Passed:
        eng = self.engine
        try:
            req = req_from_environ(request.META)
            req.path = request.path
            req.https = request.is_secure()
            limit = eng.wants_body(req.method, req.path)
            body: bytes | None = None
            if limit is not None:
                body = self._body(request, limit)
        except Exception as err:   # noqa: BLE001
            log_rate_limited(err)
            return Passed(None, None, None, None)
        result = eng.handle(req, body)
        if isinstance(result, Answer):
            return _answer(result)
        if result.ctx is not None:
            request.camada = result.ctx
        return result

    @staticmethod
    def _body(request: HttpRequest, limit: int) -> bytes | None:
        try:
            declared = int(request.META.get("CONTENT_LENGTH") or 0)
        except ValueError:
            declared = 0
        if declared > limit:
            return None
        try:
            data = request.body
        except Exception:   # noqa: BLE001 — stream already consumed, or too big for Django's own cap
            return None
        return None if len(data) > limit else data

    def _after(self, request: HttpRequest, p: Passed, response: HttpResponseBase) -> HttpResponseBase:
        try:
            if p.rid:
                response["x-rid"] = p.rid
            if p.set_cookie and p.ctx:
                response.set_cookie(
                    C.SESSION_COOKIE, p.ctx["sid"], max_age=C.SESSION_MAX_AGE, path="/", httponly=True, samesite="Lax",
                    secure="; Secure" in p.set_cookie,
                )
        except Exception as err:   # noqa: BLE001
            log_rate_limited(err)
        self._finish(request, p, getattr(response, "status_code", 200))
        return response

    @staticmethod
    def _finish(request: HttpRequest, p: Passed, status: int) -> None:
        if not p.on_finish:
            return
        try:
            match = getattr(request, "resolver_match", None)
            if match is not None and p.ctx is not None and p.ctx.get("_req") is not None:
                p.ctx["_req"].route = getattr(match, "route", None) or None
        except Exception as err:   # noqa: BLE001
            log_rate_limited(err)
        p.on_finish(status)


__all__ = ["CamadaMiddleware", "script_tag", "track"]
