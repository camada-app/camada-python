# EventQueue: fire-and-forget batched shipping to POST /e (ported from @camada/core
# src/events/queue.ts). The collector ships one event per request; an in-process SDK batches,
# flushes on size or interval, and drains at exit — but the same law holds: NOTHING here may
# ever raise into the customer's request path, and a dead ingest must cost nothing but dropped
# telemetry. Defaults (15 s / 500): every flush is one request and one R2 put at the analyst,
# so the bill scales with instance count x flush cadence — not with traffic.
from __future__ import annotations

import atexit
import json
import os
import threading
from collections import deque
from typing import Any

from ..guarded import log_rate_limited
from ..transport import HttpRequest, Transport, urllib_transport


class EventQueue:
    def __init__(
        self,
        url: str,                      # ingest base, e.g. https://analyst.example.com
        token: str,                    # ingest token (x-tenant header)
        *,
        max_batch: int = 500,          # flush when the queue reaches this many (server caps at 1000)
        max_queue: int = 2000,         # drop-oldest beyond this
        flush_s: float = 15.0,
        timeout_s: float = 2.0,
        transport: Transport | None = None,
        sdk: str | None = None,        # '<package>/<version>': sent as x-camada-sdk on every batch (SDK-03)
    ) -> None:
        self.url, self.token = url.rstrip("/"), token
        self.max_batch, self.max_queue, self.flush_s, self.timeout_s, self.sdk = max_batch, max_queue, flush_s, timeout_s, sdk
        self.transport: Transport = transport or urllib_transport
        self.dropped = 0               # debug counter, not an API promise
        self._q: deque[Any] = deque()
        self._lock = threading.Lock()
        self._inflight = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._exit_installed = False
        if hasattr(os, "register_at_fork"):
            os.register_at_fork(after_in_child=self._after_fork)

    def _after_fork(self) -> None:
        """A forked worker inherits the queue but not its thread: start fresh on the next push. The
        parent keeps its pending events (and may have held _lock mid-flush), so the child starts empty."""
        self._q = deque()
        self._lock = threading.Lock()
        self._thread = None
        self._inflight = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._exit_installed = False

    @property
    def size(self) -> int:
        return len(self._q)

    def push(self, event: Any) -> None:
        """Synchronous, never raises. Starts the flush thread lazily on first push; a stopped queue
        stays stopped (configure() replaces the engine rather than reviving one)."""
        try:
            with self._lock:
                if len(self._q) >= self.max_queue:
                    self._q.popleft()
                    self.dropped += 1
                self._q.append(event)
                n = len(self._q)
                if self._thread is None and not self._stop.is_set():
                    self._thread = threading.Thread(target=self._run, name="camada-events", daemon=True)
                    self._thread.start()
            if n >= self.max_batch:
                self._wake.set()
        except Exception as err:   # never into the request path
            log_rate_limited(err)

    def _run(self) -> None:
        stop, wake = self._stop, self._wake
        while not stop.is_set():
            wake.wait(self.flush_s)
            wake.clear()
            if stop.is_set():
                return
            self.flush()

    def flush(self, wait: bool = False) -> None:
        """Drains the queue, <=1000 events per POST (the server slices there); single-in-flight;
        never raises. `wait` queues behind a flush already in flight instead of yielding to it —
        the exit drain needs the full queue gone, not just the batch someone else is posting."""
        inflight = self._inflight   # bound once: _after_fork swaps the attribute
        if not inflight.acquire(blocking=wait):
            return
        try:
            headers = {"x-tenant": self.token, "content-type": "application/json"}
            if self.sdk:
                headers["x-camada-sdk"] = self.sdk
            while True:
                with self._lock:
                    if not self._q:
                        return
                    batch = [self._q.popleft() for _ in range(min(1000, len(self._q)))]
                try:
                    body = json.dumps(batch, separators=(",", ":")).encode()
                    res = self.transport(HttpRequest("POST", f"{self.url}/e", headers, body, self.timeout_s))
                    if res.status == 0:
                        raise ConnectionError("ingest unreachable")
                except Exception as err:
                    self.dropped += len(batch)
                    # Dropping telemetry is by design, doing it silently is not: a mount that can never
                    # reach ingest looks identical to a healthy one otherwise.
                    log_rate_limited(err)
        finally:
            inflight.release()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        self._thread = None

    def install_exit_flush(self, budget_s: float = 0.5) -> None:
        """Opt-in: drain at interpreter exit within a small budget. No signal handlers — an app owns
        its own shutdown; SIGTERM without a handler skips atexit, which the README says out loud."""
        if self._exit_installed:
            return
        self._exit_installed = True

        atexit.register(self.drain, budget_s)

    def drain(self, budget_s: float = 0.5) -> None:
        """A full drain (behind any flush in flight) on a daemon thread, abandoned once the budget is spent."""
        t = threading.Thread(target=self.flush, kwargs={"wait": True}, name="camada-exit-flush", daemon=True)
        t.start()
        t.join(budget_s)
