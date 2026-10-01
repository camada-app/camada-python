# canon_path against the reference's own outputs (edge-analyst src/blocklist.js pathForms); the golden
# fixtures pin the matching, these pin the canonical strings themselves, edge bytes included.
from __future__ import annotations

import pytest

from camada.snapshot.paths import canon_path, path_forms

CASES = [
    ("/", ("/", "/", "/")),
    ("/%62locked-path", ("/%62locked-path", "/blocked-path", "/blocked-path")),
    ("/BLOCKED-PATH/", ("/BLOCKED-PATH/", "/blocked-path", "/blocked-path")),
    ("//a//b/", ("//a//b/", "/a/b", "/a/b")),
    ("/x/../blocked-path", ("/x/../blocked-path", "/x/../blocked-path", "/blocked-path")),
    ("/x/%2e%2E/y", ("/x/%2e%2E/y", "/x/../y", "/y")),
    ("/..;/admin", ("/..;/admin", "/../admin", "/admin")),
    ("/a%2Fb", ("/a%2Fb", "/a%2fb", "/a%2fb")),
    ("/caf%C3%A9", ("/caf%C3%A9", "/caf%c3%a9", "/caf%c3%a9")),
    ("/café", ("/café", "/caf%c3%a9", "/caf%c3%a9")),
    ("/a b", ("/a b", "/a%20b", "/a%20b")),
    ("/%", ("/%", "/%25", "/%25")),
    ("/%zz", ("/%zz", "/%25zz", "/%25zz")),
    ("/a?b#c", ("/a", "/a", "/a")),
    ("/a#b?c", ("/a", "/a", "/a")),
    ("/..", ("/..", "/..", "/")),
    ("/locked/public/../../x", ("/locked/public/../../x", "/locked/public/../../x", "/x")),
]


@pytest.mark.parametrize(("raw", "want"), CASES)
def test_path_forms_match_the_reference(raw: str, want: tuple[str, str, str]) -> None:
    assert path_forms(raw) == want


def test_canon_is_idempotent() -> None:
    for raw, _ in CASES:
        c = canon_path(raw)
        assert canon_path(c) == c
