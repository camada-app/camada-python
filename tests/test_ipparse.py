# Ported from the reference edge-analyst src/blocklist.js parsers: ip4 returns -1 on anything
# unusual; ip6 rejects zone ids and v4-mapped forms. The golden fixtures pin the rest.
from camada.ipparse import parse_ip4, parse_ip6


def test_ip4_dotted_quad_to_int() -> None:
    assert parse_ip4("203.0.113.66") == (203 << 24) | (0 << 16) | (113 << 8) | 66
    assert parse_ip4("255.255.255.255") == 0xFFFFFFFF
    assert parse_ip4("0.0.0.0") == 0


def test_ip4_rejects_anything_unusual() -> None:
    for bad in ["", "1.2.3", "1.2.3.4.5", "256.1.1.1", "1..2.3", "01.2.3.4444", "a.b.c.d", " 1.2.3.4", "1.2.3.4\n"]:
        assert parse_ip4(bad) == -1, bad


def test_ip6_full_and_compressed_forms() -> None:
    assert parse_ip6("2001:db8::1") == (0x20010DB8, 0, 0, 1)
    assert parse_ip6("::1") == (0, 0, 0, 1)
    assert parse_ip6("::") == (0, 0, 0, 0)
    assert parse_ip6("fe80:0:0:0:0:0:0:1") == (0xFE800000, 0, 0, 1)
    assert parse_ip6("2001:DB8:CAFE::") == (0x20010DB8, 0xCAFE0000, 0, 0)


def test_ip6_rejects_zone_ids_mapped_v4_and_malformed() -> None:
    for bad in ["fe80::1%eth0", "::ffff:1.2.3.4", "1:2:3:4:5:6:7:8:9", "1::2::3", "12345::", "g::1", "1:2:3:4:5:6:7", ":1::"]:
        assert parse_ip6(bad) is None, bad
