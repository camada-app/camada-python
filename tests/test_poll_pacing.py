# Snapshot poll pacing (camada-all-pbv9): a failed poll (any status but 200/204/304, or no
# answer) keeps the blocks and gates the next self-initiated poll until now + next_poll_delay.
# Driven by camada-core's shared fixture poll/backoff.json, read the way blk3/blk5 are.
from __future__ import annotations

import threading
from typing import Any

import pytest

from camada.snapshot.client import SnapshotClient, next_poll_delay
from camada.snapshot.match import MatchInput
from camada.transport import HttpRequest, HttpResponse

from .conftest import read_json
from .fake_analyst import FakeAnalyst

URL = "https://analyst.test/snapshot"
FX = read_json("poll/backoff.json")


@pytest.mark.parametrize("case", FX["delay"], ids=[c["name"] for c in FX["delay"]])
def test_next_poll_delay(case: dict[str, Any]) -> None:
    got = next_poll_delay(case["status"], case["retryAfter"], case["refreshSeconds"])
    want = case["expectDelaySeconds"]
    if want is None:
        assert got is None
    else:
        assert got is not None and abs(got - want) < 1e-9


class Rig:
    """A lazy client with refresh pinned, an injected clock and a transport whose answer the test picks."""

    def __init__(self, refresh_s: float, base: float) -> None:
        self.analyst = FakeAnalyst()
        self.now = base
        self.reply: dict[str, Any] = {"status": 200}
        self.polls = 0
        self.c = SnapshotClient(URL, "t", transport=self.transport, mode="lazy", refresh_s=refresh_s)
        self.c._clock = lambda: self.now

    def transport(self, req: HttpRequest) -> HttpResponse:
        self.polls += 1
        r = self.reply
        if r["status"] == 200:
            return self.analyst.transport(req)
        h = {"retry-after": r["retryAfter"]} if r.get("retryAfter") is not None else {}
        # edge-analyst sends x-camada-config on a 503 too: a failed answer must not read it
        if r["status"] not in (204, 304):
            h["x-camada-config"] = '{"tenant":"x","poll_seconds":7}'
        return HttpResponse(r["status"], h, b"")


@pytest.mark.parametrize("tl", FX["timelines"], ids=[t["name"] for t in FX["timelines"]])
def test_timeline(tl: dict[str, Any]) -> None:
    rig = Rig(tl["refreshSeconds"], tl["clockBase"])
    for step in tl["steps"]:
        rig.now = tl["clockBase"] + step["t"]
        assert rig.c.due == step["poll"], f"t={step['t']}"
        if not step["poll"]:
            continue
        rig.reply = step["respond"]
        rig.c.refresh()
        v = rig.c.verdict(MatchInput(ip=FX["blockedIp"]))
        assert (v.reason == "cold") == step["after"]["cold"], f"t={step['t']}"
        assert bool(v.block) == step["after"]["blocked"], f"t={step['t']}"
    assert rig.c.config is None or rig.c.config.get("poll_seconds") != 7


def test_cold_client_polls_when_the_clock_is_near_zero() -> None:
    """F1: time.monotonic() counts from boot, so a cold client must be stale whatever the clock reads."""
    rig = Rig(30, 1.0)
    assert rig.c.stale and rig.c.due


def test_background_kick_rechecks_due_after_taking_the_slot() -> None:
    """F3: a kick that finds the poll no longer due (the first poll finished and gated) does not poll."""
    rig = Rig(30, 1000.0)
    rig.c.refresh()
    rig.now += 28
    rig.reply = {"status": 503, "retryAfter": "30"}
    before = rig.polls
    rig.c._refresh_if_due()
    assert rig.polls == before + 1
    rig.c._refresh_if_due()     # the second kick: gated now
    assert rig.polls == before + 1


def test_ensure_fresh_spawns_a_thread_that_polls_once_when_due() -> None:
    rig = Rig(30, 1000.0)
    done = threading.Event()
    orig = rig.c._refresh_if_due
    rig.c._refresh_if_due = lambda: (orig(), done.set())[0]  # type: ignore[method-assign]
    rig.c.ensure_fresh()
    assert done.wait(5) and rig.polls == 1
