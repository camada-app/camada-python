from camada.config import parse_key


def test_key_splits_on_the_first_dot() -> None:
    assert parse_key("tok-acme.snap-acme") == ("tok-acme", "snap-acme")
    assert parse_key("a.b.c") == ("a", "b.c")


def test_key_rejects_missing_halves() -> None:
    for bad in [None, "", "nodot", ".snap", "tok."]:
        assert parse_key(bad) is None, bad
