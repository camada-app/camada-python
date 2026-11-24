# The fail-open envelope: a camada bug must never 5xx the customer. Every public entry point of
# the SDK catches, falls back, and reports through log_rate_limited(): at most one line a minute.
from __future__ import annotations

import logging
import time

log = logging.getLogger("camada")
_last_log = 0.0
_last_warn = float("-inf")


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


def warn_rate_limited(msg: str) -> None:
    global _last_warn
    now = time.monotonic()
    if now - _last_warn < 60:
        return
    _last_warn = now
    try:
        log.warning("[camada] config warning: %s", msg)
    except Exception:
        pass   # even logging must not raise
