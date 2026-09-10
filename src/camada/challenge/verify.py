# The challenge kit over the stdlib's HMAC-SHA256 and SHA-256, ported from @camada/core
# src/challenge/verify.ts. Synchronous, so the engine's handle() stays a plain function.
from __future__ import annotations

import hashlib
import hmac

from .format import (
    CHALLENGE_TTL_MS,
    NONCE_HEX,
    nonce_message,
    pow_ok,
    safe_equal,
    solution_shape_ok,
    split_token,
    token_message,
    utc_day,
)


class ChallengeKit:
    __slots__ = ("_secret",)

    def __init__(self, secret: str) -> None:
        self._secret = secret.encode()

    def _hmac(self, msg: str) -> str:
        return hmac.new(self._secret, msg.encode(), hashlib.sha256).hexdigest()

    def _at(self, ip: str, day: int) -> str:
        return self._hmac(nonce_message(ip, day))[:NONCE_HEX]

    def nonce(self, ip: str, now_ms: int) -> str:
        """Stateless per-(ip, UTC day) nonce; the verify endpoint recomputes it, nothing is stored."""
        return self._at(ip, utc_day(now_ms))

    # Yesterday still passes: a solve started before midnight UTC must not be thrown away.
    # So one solved (nonce, solution) pair is replayable from its own IP for up to ~48 h,
    # minting a fresh 1 h cookie each time. That is the price of a stateless nonce (§D2) and
    # it is deliberate — do not "fix" it into something that needs shared server state.
    def nonce_valid(self, ip: str | None, now_ms: int, nonce: str | None) -> bool:
        if not ip or not nonce or len(nonce) != NONCE_HEX:
            return False
        day = utc_day(now_ms)
        return safe_equal(nonce, self._at(ip, day)) or safe_equal(nonce, self._at(ip, day - 1))

    def issue(self, ip: str, now_ms: int) -> str:
        exp = now_ms + CHALLENGE_TTL_MS
        return f"{exp}.{self._hmac(token_message(ip, exp))}"

    # A null ip is refused outright: without one the token is bound to nothing, so a single
    # solve would mint a cookie every other unidentified client could present. Adapters must
    # fail open (serve no challenge) rather than challenge a client they cannot identify.
    def token_valid(self, ip: str | None, now_ms: int, cookie_value: str | None) -> bool:
        if not ip:
            return False
        t = split_token(cookie_value)
        if t is None:
            return False
        exp, mac = t
        if exp <= now_ms or exp > now_ms + CHALLENGE_TTL_MS:
            return False
        return safe_equal(mac, self._hmac(token_message(ip, exp)))

    def solution_ok(self, nonce: str, solution: str | None) -> bool:
        """Proof of work ONLY. Never call it without a passing nonce_valid() for the same nonce."""
        return solution_shape_ok(solution) and pow_ok(hashlib.sha256(f"{nonce}.{solution}".encode()).hexdigest())

    def verify(self, ip: str | None, now_ms: int, nonce: str | None, solution: str | None) -> bool:
        """The whole submission: the nonce is ours and unexpired, and the work is done."""
        return self.nonce_valid(ip, now_ms, nonce) and self.solution_ok(nonce or "", solution)


def create_challenge(secret: str) -> ChallengeKit:
    return ChallengeKit(secret)
