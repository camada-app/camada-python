# Client-IP resolution under the tenant's trusted-proxy config. The default is the socket peer:
# raw X-Forwarded-For is attacker-writable and never trusted without explicit configuration.
from camada.config import TrustedProxy, parse_trusted_proxy_env
from camada.ip import resolve_client_ip


def test_socket_peer_without_config_even_when_xff_is_present() -> None:
    assert resolve_client_ip("10.0.0.1", "203.0.113.66", None) == "10.0.0.1"
    assert resolve_client_ip("10.0.0.1", "203.0.113.66", {"mode": "none"}) == "10.0.0.1"


def test_v4_mapped_peer_is_unwrapped() -> None:
    assert resolve_client_ip("::ffff:10.0.0.1", None, None) == "10.0.0.1"
    assert resolve_client_ip(None, "1.2.3.4", None) is None


def test_hops_counts_from_the_right() -> None:
    cfg = {"mode": "hops", "hops": 1}
    assert resolve_client_ip("10.0.0.1", "203.0.113.66, 198.51.100.7", cfg) == "198.51.100.7"
    assert resolve_client_ip("10.0.0.1", "203.0.113.66, 198.51.100.7", {"mode": "hops", "hops": 2}) == "203.0.113.66"
    assert resolve_client_ip("10.0.0.1", "203.0.113.66", {"mode": "hops", "hops": 2}) == "10.0.0.1"   # out of range: the peer


def test_vercel_takes_the_rightmost_entry() -> None:
    assert resolve_client_ip("10.0.0.1", "spoof, 203.0.113.66", {"mode": "vercel"}) == "203.0.113.66"


def test_cidrs_skips_trusted_proxies_from_the_right() -> None:
    cfg = {"mode": "cidrs", "cidrs": ["10.0.0.0/8", "2001:db8::/32"]}
    assert resolve_client_ip("10.0.0.1", "203.0.113.66, 10.1.2.3, 10.9.9.9", cfg) == "203.0.113.66"
    assert resolve_client_ip("10.0.0.1", "203.0.113.66, 2001:db8::5", cfg) == "203.0.113.66"
    assert resolve_client_ip("10.0.0.1", "10.1.2.3", cfg) == "10.0.0.1"          # everything trusted: the peer
    assert resolve_client_ip("10.0.0.1", "not-an-ip, 10.1.2.3", cfg) == "10.0.0.1"   # candidate must parse


def test_env_string_forms() -> None:
    assert parse_trusted_proxy_env(None) is None
    assert parse_trusted_proxy_env("none") == {"mode": "none"}
    assert parse_trusted_proxy_env("vercel") == {"mode": "vercel"}
    assert parse_trusted_proxy_env("hops:2") == {"mode": "hops", "hops": 2}
    assert parse_trusted_proxy_env("hops:0") is None
    assert parse_trusted_proxy_env("cidrs:10.0.0.0/8, 192.0.2.0/24") == {"mode": "cidrs", "cidrs": ["10.0.0.0/8", "192.0.2.0/24"]}
    assert parse_trusted_proxy_env("cidrs:") is None
    assert parse_trusted_proxy_env("bogus") is None


# trusted_proxy "cloudflare" arrives as a cidrs walk plus the Cloudflare list (edge-analyst expands it). CF-Connecting-IP
# is only believed when the hop in front of the client is a Cloudflare edge: a direct hit on the origin can forge it.
CF = ["104.16.0.0/13", "2a06:98c0::/29"]
CF_CFG: TrustedProxy = {"mode": "cidrs", "cidrs": [*CF, "169.254.0.0/16"], "cloudflare": CF}


def test_cloudflare_header_is_used_when_a_cloudflare_edge_forwarded_the_request() -> None:
    xff = "96.237.249.40, 104.22.14.220, 169.254.1.1"
    assert resolve_client_ip("127.0.0.1", xff, CF_CFG, "96.237.249.40") == "96.237.249.40"
    assert resolve_client_ip("127.0.0.1", "2600:4040::5, 2a06:98c0:3600::103, 169.254.1.1", CF_CFG, "2600:4040::5") == "2600:4040::5"
    assert resolve_client_ip("104.22.14.220", None, CF_CFG, "96.237.249.40") == "96.237.249.40"   # Cloudflare is the peer


def test_cloudflare_header_is_ignored_on_a_direct_hit() -> None:
    # straight to the origin: the hop in front of the client is not Cloudflare, so the forged header loses
    assert resolve_client_ip("127.0.0.1", "96.237.249.40, 169.254.1.1", CF_CFG, "6.6.6.6") == "96.237.249.40"
    assert resolve_client_ip("127.0.0.1", "104.16.0.1, 96.237.249.40, 169.254.1.1", CF_CFG, "6.6.6.6") == "96.237.249.40"
    assert resolve_client_ip("10.0.0.1", None, CF_CFG, "6.6.6.6") == "10.0.0.1"


def test_cloudflare_header_must_be_an_ip() -> None:
    xff = "96.237.249.40, 104.22.14.220, 169.254.1.1"
    assert resolve_client_ip("127.0.0.1", xff, CF_CFG, "not-an-ip") == "96.237.249.40"
    assert resolve_client_ip("127.0.0.1", xff, CF_CFG, None) == "96.237.249.40"
    assert resolve_client_ip("127.0.0.1", xff, {"mode": "cidrs", "cidrs": CF_CFG["cidrs"]}, "6.6.6.6") == "96.237.249.40"   # no cloudflare list: header never read
