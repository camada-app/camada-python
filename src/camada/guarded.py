# The fail-open envelope: a camada bug must never 5xx the customer. Every public entry point of
# the SDK runs inside guarded(); failures fall back and log at most once a minute.
from __future__ import annotations

import logging
import time
from collections.abc import Callable
from typing import TypeVar

log = logging.getLogger("camada")
_last_log = 0.0
T = TypeVar("T")


def log_rate_limited(err: object) -> None:
    global _last_log
    now = time.monotonic()
    if now - _last_log < 60:
        return
    _last_log = now
    try:
        log.error("[camada] suppressed error (SDK fails open): %s", err)
    except Exception:
        pass   # even logging must not raise


def guarded(fn: Callable[[], T], fallback: T) -> T:
    try:
        return fn()
    except Exception as err:   # noqa: BLE001 — the whole point: nothing escapes into the app
        log_rate_limited(err)
        return fallback
