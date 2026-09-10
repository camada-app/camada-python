# The SDK-served challenge (contracts §D2): a stateless per-(ip, UTC day) HMAC nonce, a 16-bit
# SHA-256 proof of work, and an HMAC cookie bound to the ip for one hour. Ported case for case
# from camada-core/test/challenge.test.ts.
from __future__ import annotations

import hashlib

from camada.challenge.format import (
    NONCE_HEX,
    challenge_cookie,
    escape_attr,
    escape_script,
    parse_form_body,
    pow_ok,
    safe_return_to,
    wants_html,
)
from camada.challenge.page import challenge_page
from camada.challenge.verify import create_challenge

DAY_MS = 86_400_000
NOW = 1_800_000_000_000
IP = "203.0.113.9"


def solve(nonce: str, bits: int = 16) -> str:
    n = 0
    while not pow_ok(hashlib.sha256(f"{nonce}.{n}".encode()).hexdigest(), bits):
        n += 1
    return str(n)


class TestNonce:
    def test_deterministic_per_ip_and_utc_day(self) -> None:
        kit = create_challenge("secret")
        a, b = kit.nonce(IP, NOW), kit.nonce(IP, NOW + 1000)
        assert a == b and len(a) == NONCE_HEX and int(a, 16) >= 0
        assert kit.nonce("203.0.113.10", NOW) != a
        assert kit.nonce(IP, NOW + DAY_MS) != a
        assert create_challenge("other").nonce(IP, NOW) != a

    def test_accepts_today_and_yesterday_rejects_older_and_forgeries(self) -> None:
        kit = create_challenge("secret")
        yesterday = kit.nonce(IP, NOW - DAY_MS)
        assert kit.nonce_valid(IP, NOW, kit.nonce(IP, NOW))
        assert kit.nonce_valid(IP, NOW, yesterday)
        assert not kit.nonce_valid(IP, NOW, kit.nonce(IP, NOW - 2 * DAY_MS))
        assert not kit.nonce_valid(IP, NOW, "0" * 32)
        assert not kit.nonce_valid(IP, NOW, kit.nonce(IP, NOW)[:-1])
        assert not kit.nonce_valid(None, NOW, kit.nonce(IP, NOW))
        assert not kit.nonce_valid(IP, NOW, None)


class TestToken:
    def test_round_trips_within_the_hour_and_expires_after(self) -> None:
        kit = create_challenge("secret")
        t = kit.issue(IP, NOW)
        assert kit.token_valid(IP, NOW + 3_599_000, t)
        assert not kit.token_valid(IP, NOW + 3_600_000, t)

    def test_bound_to_the_ip_and_unforgeable(self) -> None:
        kit = create_challenge("secret")
        t = kit.issue(IP, NOW)
        assert not kit.token_valid("203.0.113.10", NOW, t)
        exp, mac = t.split(".")
        assert not kit.token_valid(IP, NOW, f"{exp}.{'0' * len(mac)}")
        assert not kit.token_valid(IP, NOW, f"{int(exp) + 1}.{mac}")
        assert not kit.token_valid(None, NOW, t)   # no ip: never
        for junk in (None, "", "x", ".mac", "notanumber.mac"):
            assert not kit.token_valid(IP, NOW, junk)

    def test_refuses_an_expiry_further_out_than_the_ttl(self) -> None:
        kit = create_challenge("secret")
        far = kit.issue(IP, NOW + 10_000_000)   # minted "in the future": exp > now + TTL
        assert not kit.token_valid(IP, NOW, far)


class TestProofOfWork:
    def test_accepts_a_16_bit_solution_and_rejects_anything_else(self) -> None:
        kit = create_challenge("secret")
        nonce = kit.nonce(IP, NOW)
        sol = solve(nonce)
        assert kit.solution_ok(nonce, sol)
        assert kit.verify(IP, NOW, nonce, sol)
        assert not kit.solution_ok(nonce, sol + "1")
        assert not kit.solution_ok(nonce, "x" * 33)
        assert not kit.solution_ok(nonce, None)
        assert not kit.verify(IP, NOW, "f" * 32, solve("f" * 32))   # a forged nonce, even with real work

    def test_pow_ok_counts_leading_zero_bits(self) -> None:
        assert pow_ok("0000ffff", 16) and not pow_ok("0001ffff", 16)
        assert pow_ok("00007fff", 17) and not pow_ok("0000ffff", 17)
        assert pow_ok("0", 4) and not pow_ok("", 4)


class TestHelpers:
    def test_cookie_string(self) -> None:
        assert challenge_cookie("1.abc", False) == "_cch=1.abc; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax"
        assert challenge_cookie("1.abc", True).endswith("; Secure")

    def test_safe_return_to_keeps_only_a_same_site_path(self) -> None:
        assert safe_return_to("/a/b?c=1") == "/a/b?c=1"
        for bad in (None, "", "https://evil", "//evil", "/\\evil", "/a b", "/é", "/" + "a" * 2048, "relative"):
            assert safe_return_to(bad) == "/", bad

    def test_wants_html(self) -> None:
        assert wants_html("text/html,*/*", None) and wants_html("text/html", "document")
        assert not wants_html("application/json", None) and not wants_html("text/html", "empty") and not wants_html(None, None)

    def test_form_body_last_value_wins_and_never_raises(self) -> None:
        assert parse_form_body("a=1&b=x+y&a=2&c&%zz=%zz") == {"a": "2", "b": "x y", "c": "", "%zz": "%zz"}
        f = parse_form_body("nonce=abc&solution=7&to=%2Fx%3Fy%3D1")
        assert f == {"nonce": "abc", "solution": "7", "to": "/x?y=1"}
        assert parse_form_body("") == {}

    def test_escaping(self) -> None:
        assert escape_attr('a<b>&"c\'') == "a&lt;b&gt;&amp;&quot;c&#39;"
        assert escape_script("</script>") == '"\\u003c/script>"'


class TestPage:
    def test_self_contained_and_escaped(self) -> None:
        html = challenge_page(nonce="ab" * 16, action="/__camada/challenge", to='/x"><script>')
        assert html.startswith("<!doctype html>")
        assert "http" not in html.split("<script>")[0].replace("http-equiv", "")   # no external assets before the solver
        assert 'action="/__camada/challenge"' in html
        assert 'value="/x&quot;&gt;&lt;script&gt;"' in html
        assert "crypto.subtle" not in html
        assert "__camadaSha256Words" in html and "shift=16" in html

    def test_difficulty_is_clamped(self) -> None:
        assert "shift=0" in challenge_page(nonce="a" * 32, action="/v", to="/", bits=99)
        assert "shift=31" in challenge_page(nonce="a" * 32, action="/v", to="/", bits=0)
