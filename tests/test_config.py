import pytest

from camada.config import parse_key, resolve_token_hash, resolve_token_header


def test_key_splits_on_the_first_dot() -> None:
    assert parse_key("tok-acme.snap-acme") == ("tok-acme", "snap-acme")
    assert parse_key("a.b.c") == ("a", "b.c")


def test_key_rejects_missing_halves() -> None:
    for bad in [None, "", "nodot", ".snap", "tok."]:
        assert parse_key(bad) is None, bad


@pytest.mark.parametrize(
    ("option", "env", "expected"),
    [(False, "1", False), (True, None, True), (None, "1", True), (None, "true", False), (None, " 1", False), (None, None, False)],
)
def test_token_hash_requires_an_explicit_opt_in(option: bool | None, env: str | None, expected: bool) -> None:
    assert resolve_token_hash(option, env) is expected


@pytest.mark.parametrize("option", [None, ""])
def test_empty_token_header_option_falls_back_to_env(option: str | None) -> None:
    assert resolve_token_header(option, "X-Env-Key") == ("x-env-key", False)


def test_valid_token_header_option_overrides_env() -> None:
    assert resolve_token_header("X-Api-Key", "x-env-key") == ("x-api-key", False)
    assert resolve_token_header(None, "") == (None, False)


@pytest.mark.parametrize("option", ["X_Api_Key", "Authorization", "COOKIE", "Set-Cookie", "X-Api-Key", "X-Api-Key\n", "x" * 65])
def test_invalid_or_forbidden_token_header_does_not_fall_back_to_env(option: str) -> None:
    assert resolve_token_header(option, "x-env-key") == (None, True)
