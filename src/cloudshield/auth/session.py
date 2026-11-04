import base64
import hashlib
import hmac
import json
import time

COOKIE_NAME = "cloudshield_session"
ROLES = ("owner", "viewer")


def encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sign(payload: str, secret: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).digest()
    return encode(digest)


def make_token(role: str, secret: str, hours: int, now: float | None = None) -> str:
    """The token is `payload.signature`. The payload is the role and the expiry time, and the
    signature is an HMAC of it. Nothing in it is secret; it only cannot be changed."""
    expires = int((time.time() if now is None else now) + hours * 3600)
    payload = encode(json.dumps({"role": role, "exp": expires}, separators=(",", ":")).encode())
    return f"{payload}.{sign(payload, secret)}"


def read_token(token: str, secret: str, now: float | None = None) -> str | None:
    """The role in a token that is genuine and not expired, or None."""
    payload, dot, signature = token.partition(".")
    expected = sign(payload, secret).encode("utf-8")
    if not dot or not hmac.compare_digest(expected, signature.encode("utf-8")):
        return None
    try:
        claims = json.loads(decode(payload))
        role, expires = claims["role"], claims["exp"]
    except (ValueError, KeyError, TypeError):
        return None
    if role not in ROLES or not isinstance(expires, int):
        return None
    return role if expires > (time.time() if now is None else now) else None
