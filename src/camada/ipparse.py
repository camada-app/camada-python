# Allocation-free IP parsers, ported 1:1 from edge-analyst src/blocklist.js through
# @camada/core src/snapshot/ipparse.ts (the reference the conformance fixtures are generated
# from). Behaviour must not drift: ip4 returns -1 on anything unusual; ip6 rejects zone ids and
# v4-mapped forms. Python ints are unbounded, so the words come back as a tuple instead of
# being written into a caller's scratch array.
from __future__ import annotations

Words = tuple[int, int, int, int]


def parse_ip4(s: str) -> int:
    """Dotted-quad IPv4 to a uint32, or -1 when the string is not a plain IPv4 address."""
    n = part = digits = dots = 0
    for ch in s:
        if ch == ".":
            if digits == 0 or part > 255:
                return -1
            dots += 1
            if dots > 3:
                return -1
            n = n * 256 + part
            part = digits = 0
        elif "0" <= ch <= "9":
            part = part * 10 + (ord(ch) - 48)
            digits += 1
            if digits > 3:
                return -1
        else:
            return -1
    if dots != 3 or digits == 0 or part > 255:
        return -1
    return n * 256 + part


def parse_ip6(s: str) -> Words | None:
    """IPv6 text to four big-endian uint32 words, or None when it is not a plain IPv6 address."""
    length = len(s)
    groups = [0] * 8
    n = val = digits = 0
    dbl = -1
    i = 0
    if length > 1 and s[0] == ":" and s[1] == ":":
        dbl = 0
        i = 2
    while i <= length:
        c = s[i] if i < length else ":"   # a sentinel colon closes the last group
        if c == ":":
            if digits > 0:
                if n >= 8:
                    return None
                groups[n] = val
                n += 1
                val = digits = 0
            elif i < length:
                if dbl != -1:
                    return None
                dbl = n
        else:
            if "0" <= c <= "9":
                d = ord(c) - 48
            elif "a" <= c <= "f":
                d = ord(c) - 87
            elif "A" <= c <= "F":
                d = ord(c) - 55
            else:
                return None
            val = (val << 4) | d
            digits += 1
            if digits > 4:
                return None
        i += 1
    if dbl == -1:
        if n != 8:
            return None
    else:
        if n >= 8:
            return None
        shift = 8 - n
        for k in range(7, dbl + shift - 1, -1):
            groups[k] = groups[k - shift]
        for k in range(dbl, dbl + shift):
            groups[k] = 0
    return (
        (groups[0] << 16) | groups[1],
        (groups[2] << 16) | groups[3],
        (groups[4] << 16) | groups[5],
        (groups[6] << 16) | groups[7],
    )
