# Redaction is not configurable off: credential-looking query values become ~r, body values
# never ship, user identifiers are HMAC-hashed inside the SDK.
import hashlib
import hmac

from camada.redact import body_shape, hash_user_id, scrub_query


def test_scrub_query_by_name_and_by_value_shape() -> None:
    assert scrub_query("?q=hello&token=abc&x=1") == "?q=hello&token=~r&x=1"
    assert scrub_query("?api_key=k&PASSWORD=p") == "?api_key=~r&PASSWORD=~r"
    jwt = "eyJhbGciOi.eyJzdWIiOi.sig"
    assert scrub_query("?t=" + jwt) == "?t=~r"
    assert scrub_query("?h=" + "a" * 32) == "?h=~r"
    assert scrub_query("?b=" + "A" * 40 + "==") == "?b=~r"
    assert scrub_query("?flag&x=1") == "?flag&x=1"      # a bare name is kept as is


def test_scrub_query_keeps_shape_and_empties() -> None:
    assert scrub_query("") == ""
    assert scrub_query(None) == ""
    assert scrub_query("?") == "?"
    assert scrub_query("a=1&code=2") == "a=1&code=~r"  # no leading ? is fine too


def test_body_shape_is_names_and_sizes_only() -> None:
    assert body_shape({"email": "a@b.c", "n": 12, "none": None, "arr": [1, 2]}) == {"email": 5, "n": 2, "none": 0, "arr": 5}
    assert body_shape([1]) is None
    assert body_shape("str") is None


def test_hash_user_id_is_a_labelled_truncated_hmac() -> None:
    expected = hmac.new(b"tok", b"uid:alice@example.com", hashlib.sha256).hexdigest()[:32]
    assert hash_user_id("alice@example.com", "tok") == expected
    assert len(hash_user_id("x", "tok")) == 32
