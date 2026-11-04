import hmac

import pytest

from cloudshield.auth import passwords
from cloudshield.auth.limits import MAX_ADDRESSES, LoginLimiter
from cloudshield.auth.passwords import (
    COST_N,
    hash_password,
    parse_hash,
    unused_hash,
    verify_password,
)
from cloudshield.auth.routes import AuthConfigError, check_settings
from cloudshield.auth.session import make_token, read_token
from cloudshield.config import Settings

SECRET = "a-test-secret-with-many-different-characters-0123456789"
PASSWORD = "correct horse battery staple"


@pytest.fixture(scope="module")
def good_hash() -> str:
    return hash_password(PASSWORD)


def settings(**changes) -> Settings:
    values = {
        "auth_enabled": True,
        "owner_password_hash": placeholder_hash(),
        "session_secret": SECRET,
    }
    return Settings(**{**values, **changes})


def placeholder_hash() -> str:
    return "scrypt:32768:8:1:" + "A" * 22 + ":" + "B" * 43


def test_a_hash_has_six_parts_with_the_cost_settings_and_never_holds_the_password(good_hash):
    parts = good_hash.split(":")

    assert parts[:4] == ["scrypt", str(COST_N), "8", "1"]
    assert len(parts) == 6
    assert PASSWORD not in good_hash


def test_the_same_password_gets_a_different_hash_each_time(good_hash):
    assert hash_password(PASSWORD) != good_hash


def test_the_right_password_verifies_and_a_wrong_one_does_not(good_hash):
    assert verify_password(PASSWORD, good_hash) is True
    assert verify_password(PASSWORD + "x", good_hash) is False
    assert verify_password("", good_hash) is False


def test_verification_uses_a_constant_time_comparison(good_hash, monkeypatch):
    calls = []
    real = hmac.compare_digest

    def spy(a, b):
        calls.append(1)
        return real(a, b)

    monkeypatch.setattr(passwords.hmac, "compare_digest", spy)

    verify_password(PASSWORD, good_hash)

    assert calls == [1]


def test_a_password_with_any_characters_works(good_hash):
    odd = "pässwörd with spaces and : colons"

    assert verify_password(odd, hash_password(odd)) is True


def test_the_unused_hash_matches_nothing_and_is_always_the_same_one():
    assert unused_hash() == unused_hash()
    assert verify_password(PASSWORD, unused_hash()) is False


@pytest.mark.parametrize(
    ("stored", "problem"),
    [
        ("", "format"),
        ("plain", "format"),
        ("bcrypt:1:2:3:4:5", "format"),
        ("scrypt:32768:8:1:AAAA", "format"),
        ("scrypt:many:8:1:AAAA:BBBB", "cannot be read"),
        ("scrypt:1024:8:1:" + "A" * 22 + ":" + "B" * 43, "too weak"),
        ("scrypt:20000:8:1:" + "A" * 22 + ":" + "B" * 43, "too weak"),
        ("scrypt:32768:8:0:" + "A" * 22 + ":" + "B" * 43, "too weak"),
        ("scrypt:32768:8:1:AAAA:" + "B" * 43, "too short"),
        ("scrypt:32768:8:1:" + "A" * 22 + ":BBBB", "too short"),
    ],
)
def test_a_hash_that_is_malformed_or_weak_is_refused_in_plain_words(stored, problem):
    with pytest.raises(ValueError, match=problem):
        parse_hash(stored)


def test_a_token_gives_back_its_role_until_it_expires():
    token = make_token("viewer", SECRET, hours=2, now=1000.0)

    assert read_token(token, SECRET, now=1000.0) == "viewer"
    assert read_token(token, SECRET, now=1000.0 + 2 * 3600 - 1) == "viewer"
    assert read_token(token, SECRET, now=1000.0 + 2 * 3600) is None
    assert read_token(token, SECRET, now=1000.0 + 5 * 3600) is None


def test_a_token_signed_with_another_secret_is_refused():
    token = make_token("owner", SECRET, hours=1)

    assert read_token(token, SECRET + "x") is None


def test_a_changed_payload_or_signature_is_refused():
    payload, signature = make_token("viewer", SECRET, hours=1).split(".")
    owner_payload = make_token("owner", SECRET, hours=1).split(".")[0]

    assert read_token(f"{owner_payload}.{signature}", SECRET) is None
    assert read_token(f"{payload}.{signature[:-1]}A", SECRET) is None
    assert read_token(f"{payload}.", SECRET) is None


@pytest.mark.parametrize(
    "token",
    ["", ".", "abc", "a.b.c", "not-base64.signature", "é.é", "eyJ9.x"],
)
def test_garbage_is_refused_without_an_error(token):
    assert read_token(token, SECRET) is None


def test_a_role_that_does_not_exist_is_refused_even_when_signed():
    token = make_token("admin", SECRET, hours=1)

    assert read_token(token, SECRET) is None


def test_the_limiter_blocks_after_five_failures_in_five_minutes_and_says_how_long():
    limiter = LoginLimiter()

    for second in range(5):
        assert limiter.wait("1.1.1.1", 100.0 + second) == 0
        limiter.fail("1.1.1.1", 100.0 + second)

    assert limiter.wait("1.1.1.1", 105.0) == 295
    assert limiter.wait("1.1.1.1", 399.0) == 1
    assert limiter.wait("1.1.1.1", 400.0) == 0


def test_the_limiter_counts_each_address_on_its_own():
    limiter = LoginLimiter()

    for _ in range(5):
        limiter.fail("1.1.1.1", 100.0)

    assert limiter.wait("1.1.1.1", 101.0) > 0
    assert limiter.wait("2.2.2.2", 101.0) == 0


def test_failures_older_than_the_window_do_not_count():
    limiter = LoginLimiter()
    for _ in range(4):
        limiter.fail("1.1.1.1", 100.0)

    limiter.fail("1.1.1.1", 500.0)

    assert limiter.wait("1.1.1.1", 501.0) == 0


def test_a_good_login_clears_the_count():
    limiter = LoginLimiter()
    for _ in range(4):
        limiter.fail("1.1.1.1", 100.0)

    limiter.clear("1.1.1.1")
    limiter.fail("1.1.1.1", 101.0)

    assert limiter.wait("1.1.1.1", 102.0) == 0


def test_the_table_of_addresses_cannot_grow_without_limit():
    limiter = LoginLimiter()
    for number in range(MAX_ADDRESSES):
        limiter.failures[f"old-{number}"] = [1.0]

    limiter.fail("new", 10_000.0)

    assert list(limiter.failures) == ["new"]


def test_the_login_settings_are_not_checked_while_the_login_is_off():
    check_settings(Settings(auth_enabled=False))


def test_good_settings_pass(good_hash):
    check_settings(settings(owner_password_hash=good_hash))
    check_settings(settings(owner_password_hash=good_hash, viewer_password_hash=good_hash))


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"owner_password_hash": None}, "OWNER_PASSWORD_HASH is not set"),
        ({"owner_password_hash": "plain"}, "OWNER_PASSWORD_HASH is not in the format"),
        ({"owner_password_hash": "scrypt:1024:8:1:AAAA:BBBB"}, "OWNER_PASSWORD_HASH"),
        ({"viewer_password_hash": "plain"}, "VIEWER_PASSWORD_HASH is not in the format"),
        ({"session_secret": None}, "SESSION_SECRET is not set"),
        ({"session_secret": "short"}, "SESSION_SECRET is too weak"),
        ({"session_secret": "a" * 64}, "SESSION_SECRET is too weak"),
        ({"session_secret": "abababab" * 8}, "SESSION_SECRET is too weak"),
        ({"session_hours": 0}, "SESSION_HOURS"),
        ({"session_hours": 1000}, "SESSION_HOURS"),
    ],
)
def test_the_server_refuses_to_start_on_missing_or_weak_settings(good_hash, changes, message):
    values = {"owner_password_hash": good_hash, **changes}

    with pytest.raises(AuthConfigError, match=message) as refused:
        check_settings(settings(**values))

    assert SECRET not in str(refused.value)
    assert good_hash not in str(refused.value)


def test_the_message_says_how_to_make_the_missing_thing():
    with pytest.raises(AuthConfigError, match=r"python -m cloudshield\.auth hash-password"):
        check_settings(settings(owner_password_hash=None))
    with pytest.raises(AuthConfigError, match=r"python -m cloudshield\.auth secret"):
        check_settings(settings(session_secret=None))
