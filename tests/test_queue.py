# EventQueue: fire-and-forget batched shipping to POST /e. Nothing here may ever raise into the
# customer's request path, and a dead ingest must cost nothing but dropped telemetry.
from __future__ import annotations

import time

from camada.events.queue import EventQueue

from .fake_analyst import FakeAnalyst


def queue(a: FakeAnalyst, **kw: object) -> EventQueue:
    return EventQueue("https://analyst.test", "tok-test", transport=a.transport, sdk="@camada/python/0.0.0", **kw)  # type: ignore[arg-type]


def test_flush_posts_a_json_array_with_the_tenant_and_sdk_headers() -> None:
    a = FakeAnalyst()
    q = queue(a)
    q.push({"p": "/"})
    q.flush()
    assert a.events == [[{"p": "/"}]]
    assert a.sdk_headers == ["@camada/python/0.0.0"]


def test_flushes_when_the_batch_size_is_reached() -> None:
    a = FakeAnalyst()
    q = queue(a, max_batch=3, flush_s=60)
    for i in range(3):
        q.push({"i": i})
    for _ in range(100):
        if a.events:
            break
        time.sleep(0.005)
    assert a.events == [[{"i": 0}, {"i": 1}, {"i": 2}]]


def test_flushes_on_the_interval() -> None:
    a = FakeAnalyst()
    q = queue(a, flush_s=0.02)
    q.push({"i": 1})
    for _ in range(100):
        if a.events:
            break
        time.sleep(0.005)
    assert a.events == [[{"i": 1}]]
    q.stop()


def test_drains_in_slices_of_1000() -> None:
    a = FakeAnalyst()
    q = queue(a, max_batch=5000, max_queue=5000)
    for i in range(1500):
        q.push({"i": i})
    q.flush()
    assert [len(b) for b in a.events] == [1000, 500]


def test_drops_oldest_beyond_the_queue_cap() -> None:
    a = FakeAnalyst()
    q = queue(a, max_queue=3, max_batch=100, flush_s=60)
    for i in range(5):
        q.push({"i": i})
    assert q.size == 3 and q.dropped == 2
    q.flush()
    assert a.events == [[{"i": 2}, {"i": 3}, {"i": 4}]]


def test_dead_ingest_drops_silently_and_recovers() -> None:
    a = FakeAnalyst()
    a.ingest_down = True
    q = queue(a)
    q.push({"i": 1})
    q.flush()
    assert q.dropped == 1 and q.size == 0
    a.ingest_down = False
    q.push({"i": 2})
    q.flush()
    assert a.events == [[{"i": 2}]]


def test_push_never_raises() -> None:
    a = FakeAnalyst()
    q = queue(a)
    q.transport = None  # type: ignore[assignment]
    q.push({"i": 1})
    q.flush()   # a broken transport is swallowed and logged, never raised
    assert q.size == 0


def test_stop_ends_the_flush_thread() -> None:
    a = FakeAnalyst()
    q = queue(a, flush_s=0.01)
    q.push({"i": 1})
    q.stop()
    time.sleep(0.03)
    n = len(a.events)
    q.push({"i": 2})
    time.sleep(0.03)
    assert len(a.events) == n   # nothing flushes on its own after stop()
