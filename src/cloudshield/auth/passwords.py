import base64
import hashlib
import hmac
import secrets
from functools import lru_cache

# A stored hash is one line of six parts, separated by colons:
#   scrypt:<N>:<r>:<p>:<salt>:<key>
# N, r and p are the scrypt cost settings. The salt and the key are base64 (URL safe, no padding).
# The cost settings are stored with the hash, so they can be raised later without breaking old
# hashes.
PREFIX = "scrypt"
COST_N = 2**15
COST_R = 8
COST_P = 1
SALT_BYTES = 16
KEY_BYTES = 32
MIN_COST_N = 2**14
MAX_COST_N = 2**17
MAX_COST_R = 8
MAX_COST_P = 4
MAX_MEMORY = 256 * 1024 * 1024
MIN_PASSWORD_LENGTH = 12


def encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def derive(password: str, salt: bytes, n: int, r: int, p: int, length: int) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=n, r=r, p=p, maxmem=MAX_MEMORY, dklen=length
    )


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(SALT_BYTES)
    key = derive(password, salt, COST_N, COST_R, COST_P, KEY_BYTES)
    return ":".join([PREFIX, str(COST_N), str(COST_R), str(COST_P), encode(salt), encode(key)])


def parse_hash(stored: str) -> tuple[int, int, int, bytes, bytes]:
    """Splits a stored hash. Raises ValueError, in plain words, when it is not a hash that this
    program made or is too weak."""
    parts = stored.split(":")
    if len(parts) != 6 or parts[0] != PREFIX:
        raise ValueError(f"is not in the format {PREFIX}:N:r:p:salt:key")
    try:
        n, r, p = (int(part) for part in parts[1:4])
        salt, key = decode(parts[4]), decode(parts[5])
    except ValueError as exc:
        raise ValueError("has a part that cannot be read") from exc
    if n & (n - 1) or not MIN_COST_N <= n <= MAX_COST_N or not 1 <= r <= MAX_COST_R:
        raise ValueError("uses scrypt cost settings that are too weak or not allowed")
    if not 1 <= p <= MAX_COST_P:
        raise ValueError("uses scrypt cost settings that are too weak or not allowed")
    if len(salt) < SALT_BYTES or len(key) < KEY_BYTES:
        raise ValueError("has a salt or key that is too short")
    return n, r, p, salt, key


def verify_password(password: str, stored: str) -> bool:
    n, r, p, salt, expected = parse_hash(stored)
    key = derive(password, salt, n, r, p, len(expected))
    return hmac.compare_digest(key, expected)


@lru_cache(maxsize=1)
def unused_hash() -> str:
    """A hash nobody has the password for. A login for a role with no password still does the
    same work as a real one, so the time taken does not say which roles exist."""
    return hash_password(secrets.token_urlsafe(16))
