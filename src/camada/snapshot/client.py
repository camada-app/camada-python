# SnapshotClient: the single-tenant port of the edge collector's snapshot lifecycle over the
# GET /snapshot contract (ported from @camada/core src/snapshot/client.ts):
#   200  [u32 LE meta-length][meta JSON][BLK container] + etag + x-camada-config
#   304  nothing changed; config header repeated (config refreshes every poll for free)
#   204  authenticated, no snapshot published -> enforce nothing, fail open
# Semantics ported exactly: single-in-flight load; loaded_at stamped even on 204 (retry per
# poll cadence, not per request); any error keeps the previous snapshot; cold = fail open.
# Timers are threads here: timer mode runs one daemon thread per client; lazy mode kicks a
# one-shot daemon thread from ensure_fresh() so the request path never waits on the network.
from __future__ import annotations

import json
import math
import os
import struct
import threading
import time
from typing import Any, Literal

from ..config import RemoteConfig, remote_config
from ..constants import DEFAULT_REFRESH_S, DEFAULT_SNAPSHOT_VERSION
from ..guarded import log_rate_limited
from ..transport import HttpRequest, Transport, urllib_transport
from .match import Matcher, MatchInput, MatchResult
from .parse import parse_snapshot

COLD = MatchResult(reason="cold")   # never loaded yet: fail open, mirrors the collector
NONE = MatchResult()


class SnapshotClient:
    def __init__(
        self,
        url: str,
        token: str,
        *,
        refresh_s: float | None = None,        # leave unset and the server's poll_seconds steers it; set it and it is pinned
        timeout_s: float = 3.0,
        mode: Literal["timer", "lazy"] = "timer",
        transport: Transport | None = None,
        sdk: str | None = None,                # '<package>/<version>': sent as x-camada-sdk on every poll (SDK-03)
        snapshot_version: int = DEFAULT_SNAPSHOT_VERSION,   # 5 asks for the custom rules too; 4 the sides only; 3 opts out of both
    ) -> None:
        self.url, self.token = url, token
        self.timeout_s, self.mode, self.sdk, self.snapshot_version = timeout_s, mode, sdk, snapshot_version
        self.transport: Transport = transport or urllib_transport
        self.matcher: Matcher | None = None
        self.config: RemoteConfig | None = None
        self.refresh_s = refresh_s if refresh_s is not None else DEFAULT_REFRESH_S
        self._pinned = refresh_s is not None
        self._etag: str | None = None
        self._loaded_at = 0.0
        self._loading = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        if hasattr(os, "register_at_fork"):
            os.register_at_fork(after_in_child=self._after_fork)

    def _after_fork(self) -> None:
        """Threads do not survive fork (gunicorn --preload): forget the parent's, then re-arm the
        timer so the child polls on its own (lazy mode refreshes from the request path anyway)."""
        self._thread = None
        self._loading = threading.Lock()
        self._stop = threading.Event()
        if self.mode == "timer":
            self.start()

    def start(self) -> None:
        self.ensure_fresh()
        if self.mode != "timer" or self._thread is not None:
            return
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="camada-snapshot", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        stop = self._stop
        while not stop.wait(self.refresh_s):
            self.ensure_fresh()

    def stop(self) -> None:
        self._stop.set()
        self._thread = None

    @property
    def stale(self) -> bool:
        # 0.9 x refresh so a timer tick arriving at ~refresh-ε still refreshes; a full-interval
        # comparison makes every other tick a no-op (effective cadence 2x).
        return time.monotonic() - self._loaded_at > self.refresh_s * 0.9

    def ensure_fresh(self) -> None:
        """Kicks a refresh when stale; never blocks the request path, never raises."""
        if not self.stale or self._loading.locked():
            return
        threading.Thread(target=self.refresh, name="camada-snapshot-load", daemon=True).start()

    def refresh(self) -> None:
        """One synchronous poll (single in-flight): what the threads call, and what tests and warm-ups call directly."""
        lock = self._loading   # bound once: _after_fork swaps the attribute
        if not lock.acquire(blocking=False):
            return
        try:
            self._load()
        except Exception as err:   # a poll that can never succeed must not be silent, nor fatal
            log_rate_limited(err)
        finally:
            lock.release()

    def _load(self) -> None:
        headers = {"authorization": f"Bearer {self.token}", "accept-encoding": "gzip"}
        if self._etag:
            headers["if-none-match"] = self._etag
        if self.sdk:
            headers["x-camada-sdk"] = self.sdk
        if self.snapshot_version > 3:
            headers["x-camada-snapshot"] = str(self.snapshot_version)   # a tenant without that container is answered with the next one down
        res = self.transport(HttpRequest("GET", self.url, headers, None, self.timeout_s))
        if res.status not in (200, 204, 304):
            return   # 401/5xx/network: keep what we have
        self._loaded_at = time.monotonic()
        self._read_config(res.headers.get("x-camada-config"))
        if res.status == 304:
            return
        if res.status == 204:   # no snapshot published: enforce nothing
            self.matcher, self._etag = None, None
            return
        body = res.body
        if len(body) < 4:
            raise ValueError("camada: truncated snapshot frame")
        (meta_len,) = struct.unpack_from("<I", body, 0)
        if 4 + meta_len > len(body):
            raise ValueError("camada: truncated snapshot frame")
        meta: dict[str, Any] = json.loads(body[4 : 4 + meta_len])
        # The server ships the v3, v4 and v5 bodies of one publish under the SAME meta.version and
        # different etags, so version alone cannot say "nothing changed".
        etag = res.headers.get("etag")
        if self.matcher and meta.get("version") == self.matcher.snap.version and etag is not None and etag == self._etag:
            return
        # parse_snapshot raises on corrupt data -> caught by refresh(), previous kept
        self.matcher = Matcher(parse_snapshot(memoryview(body)[4 + meta_len :], meta))
        self._etag = etag

    def _read_config(self, raw: str | None) -> None:
        if not raw:
            return
        try:
            cfg = remote_config(json.loads(raw))
        except ValueError:
            return   # keep the previous config
        if cfg is None:
            return
        self.config = cfg
        # the server steers the poll cadence per tenant (its cost lever) unless the client pinned one
        try:
            secs = float(cfg.get("poll_seconds", 0))
        except (TypeError, ValueError):
            return
        if self._pinned or not math.isfinite(secs) or secs < 5 or secs == self.refresh_s:   # json.loads admits NaN and 1e999
            return
        self.refresh_s = secs

    def verdict(self, i: MatchInput) -> MatchResult:
        """Cold (never loaded) and no-snapshot both fail open, mirroring the edge collector."""
        if not self._loaded_at:
            return COLD
        m = self.matcher
        return m.match(i) if m else NONE
