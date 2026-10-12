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


# camada-all-0vho: an X-Forwarded-For entry may carry a port (Azure Application Gateway writes `ip:port`).
def test_xff_entries_with_a_port_resolve_to_the_address() -> None:
    hops1: TrustedProxy = {"mode": "hops", "hops": 1}
    assert resolve_client_ip("169.254.130.1", "203.0.113.66:51234", hops1) == "203.0.113.66"
    assert resolve_client_ip("169.254.130.1", "[2001:db8::66]:51234", hops1) == "2001:db8::66"
    assert resolve_client_ip("169.254.130.1", "[2001:db8::66]", hops1) == "2001:db8::66"
    assert resolve_client_ip("169.254.130.1", "2001:db8::66:8080", hops1) == "2001:db8::66:8080"   # a bare v6 is never split
    assert resolve_client_ip("169.254.130.1", "203.0.113.66:51234", {"mode": "vercel"}) == "203.0.113.66"
    azure: TrustedProxy = {"mode": "cidrs", "cidrs": ["169.254.0.0/16"]}
    assert resolve_client_ip("169.254.130.1", "203.0.113.66:51234", azure) == "203.0.113.66"
    assert resolve_client_ip("169.254.130.1", "203.0.113.66, 169.254.1.1:5000", azure) == "203.0.113.66"   # the trust test sees the address


def test_malformed_port_entries_fall_back_to_the_peer() -> None:
    hops1: TrustedProxy = {"mode": "hops", "hops": 1}
    for bad in ("203.0.113.66:", "203.0.113.66:abc", "203.0.113.66:123456", "203.0.113.66:80:90", "[2001:db8::66:51234",
                "[2001:db8::66]:", "[2001:db8::66]x", "[203.0.113.66]:80", "[]:80", "not-an-ip:80", "203.0.113.256:80"):
        assert resolve_client_ip("169.254.130.1", bad, hops1) == "169.254.130.1", bad


# camada-all-yfc6 (D1): in cidrs mode the chain is [...xff, peer]. A peer outside every trusted range is the client and
# its XFF is ignored; a loopback peer is a local front end (App Engine's is always 127.0.0.1) and counts as a trusted hop.
CF_PRESET = ["173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
             "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
             "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22", "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
             "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32"]
CLOUDFLARE: TrustedProxy = {"mode": "cidrs", "cidrs": CF_PRESET, "cloudflare": CF_PRESET}
TRIALSIGHTS: TrustedProxy = {"mode": "cidrs", "cidrs": [*CF_PRESET, "169.254.0.0/16"], "cloudflare": CF_PRESET}


def test_trialsights_app_engine_behind_cloudflare_still_resolves_the_client() -> None:
    # Trialsights (camada 0.2.2, App Engine + the Cloudflare option): the peer is always App Engine's local front end,
    # Google appends 169.254.1.1, Cloudflare's edge sits in front of that. The leftmost entry is client-written.
    xff = "6.6.6.6, 198.51.100.9, 172.64.1.1, 169.254.1.1"
    assert resolve_client_ip("127.0.0.1", xff, TRIALSIGHTS) == "198.51.100.9"
    assert resolve_client_ip("127.0.0.1", xff, TRIALSIGHTS, "198.51.100.9") == "198.51.100.9"   # via CF-Connecting-IP
    assert resolve_client_ip("127.0.0.1", "6.6.6.6, 198.51.100.9, 169.254.1.1", TRIALSIGHTS) == "198.51.100.9"   # direct appspot hit
    assert resolve_client_ip("127.0.0.1", "6.6.6.6, 198.51.100.9, 169.254.1.1", TRIALSIGHTS, "6.6.6.6") == "198.51.100.9"


def test_cidrs_direct_hit_from_an_untrusted_peer_ignores_xff() -> None:
    for xff in ("203.0.113.66", "8.8.8.8", "8.8.8.8, 172.64.1.1"):
        assert resolve_client_ip("203.0.113.200", xff, CLOUDFLARE) == "203.0.113.200", xff
        assert resolve_client_ip("::ffff:203.0.113.200", xff, CLOUDFLARE) == "203.0.113.200", xff
        assert resolve_client_ip("::FFFF:203.0.113.200", xff, CLOUDFLARE) == "203.0.113.200", xff
    assert resolve_client_ip("2001:db8::99", "198.51.100.9", CLOUDFLARE) == "2001:db8::99"
    assert resolve_client_ip("198.51.100.7", "203.0.113.66:51234", {"mode": "cidrs", "cidrs": ["169.254.0.0/16"]}) == "198.51.100.7"
    assert resolve_client_ip("172.64.1.1", "1.2.3.4, 198.51.100.9", CLOUDFLARE) == "198.51.100.9"   # a trusted peer still walks


def test_cloudflare_header_is_never_read_on_a_direct_hit_from_an_untrusted_peer() -> None:
    # a forged chain that ends in a CF edge, plus a forged CF-Connecting-IP naming the victim: the peer is the client
    assert resolve_client_ip("203.0.113.200", "8.8.8.8, 172.64.1.1", CLOUDFLARE, "198.51.100.66") == "203.0.113.200"
    assert resolve_client_ip("203.0.113.200", "172.64.1.1", TRIALSIGHTS, "198.51.100.66") == "203.0.113.200"
    assert resolve_client_ip("::ffff:203.0.113.200", "172.64.1.1, 169.254.1.1", TRIALSIGHTS, "198.51.100.66") == "203.0.113.200"
    assert resolve_client_ip("172.64.1.1", "8.8.8.8", CLOUDFLARE, "198.51.100.66") == "198.51.100.66"   # CF is the peer


def test_loopback_peer_is_a_trusted_hop_only_as_the_peer() -> None:
    for peer in ("127.0.0.1", "127.5.6.7", "::1", "0:0:0:0:0:0:0:1", "::ffff:127.0.0.1"):
        assert resolve_client_ip(peer, "198.51.100.9, 172.64.1.1", CLOUDFLARE) == "198.51.100.9", peer
    assert resolve_client_ip("127.0.0.1", "8.8.8.8", CLOUDFLARE) == "8.8.8.8"          # D1's accepted trade-off
    assert resolve_client_ip("172.64.1.1", "127.0.0.1", CLOUDFLARE) == "127.0.0.1"     # a loopback XFF entry is untrusted


def test_no_peer_keeps_the_plain_walk() -> None:
    assert resolve_client_ip(None, "1.2.3.4, 198.51.100.9, 172.64.1.1", CLOUDFLARE) == "198.51.100.9"
    assert resolve_client_ip(None, "172.64.1.1", CLOUDFLARE) is None
    assert resolve_client_ip("", "1.2.3.4, 198.51.100.9, 172.64.1.1", CLOUDFLARE) == "198.51.100.9"   # "" is no peer


def test_unreadable_peer_never_walks_and_gives_none() -> None:
    # C6 v3: a non-empty peer that is not an ip after unmap could not be read; the result is None in every mode's
    # fallback, and cidrs never walks XFF for it (it is not "no peer").
    for peer in ("unix:/run/app.sock", "/run/app.sock", "@", "1.2.3.4:5", "fe80::1%eth0", "::ffff:zz", "1.2.3.4 ", "64:ff9b::198.51.100.9"):
        assert resolve_client_ip(peer, "198.51.100.9, 172.64.1.1", CLOUDFLARE) is None, peer
        assert resolve_client_ip(peer, None, None) is None, peer
        assert resolve_client_ip(peer, "198.51.100.9", {"mode": "hops", "hops": 1}) == "198.51.100.9", peer
        assert resolve_client_ip(peer, "198.51.100.9, 172.64.1.1", CLOUDFLARE, "198.51.100.9") is None, peer


def test_v6_grammar_and_unmap_are_ours_not_the_std_lib() -> None:
    hops1: TrustedProxy = {"mode": "hops", "hops": 1}
    for bad in (":8:8:8", "2001:db8::1:", "::1.2.3.4", "::ffff:1.2.3.256", "0:0:0:0:0:ffff:1.2.3.4", ":::", "1:2:3:4:5:6:7:8:9"):
        assert resolve_client_ip("10.0.0.1", bad, hops1) == "10.0.0.1", bad
    assert resolve_client_ip("10.0.0.1", "::FFFF:203.0.113.5", hops1) == "203.0.113.5"
    assert resolve_client_ip("10.0.0.1", "\u00a0203.0.113.5", hops1) == "10.0.0.1"   # NBSP is not OWS
    assert resolve_client_ip("10.0.0.1", "\t203.0.113.5 ", hops1) == "203.0.113.5"
    # ::ffff:7f00:1 is an ordinary v6 address, not loopback (Python 3.13 ipaddress says it is)
    assert resolve_client_ip("::ffff:7f00:1", "198.51.100.9", CLOUDFLARE) == "::ffff:7f00:1"


def test_cloudflare_header_is_never_read_behind_an_unreadable_peer() -> None:
    assert resolve_client_ip("/run/app.sock", "198.51.100.9, 172.64.1.1", CLOUDFLARE, "198.51.100.9") is None
    assert resolve_client_ip(None, "198.51.100.9, 172.64.1.1", CLOUDFLARE, "198.51.100.9") == "198.51.100.9"   # no peer walks
