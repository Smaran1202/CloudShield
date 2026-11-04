import time

from fastapi import APIRouter, HTTPException, Request, Response

from cloudshield.api.schemas import LoginIn, MeOut
from cloudshield.auth.passwords import parse_hash, unused_hash, verify_password
from cloudshield.auth.session import COOKIE_NAME, make_token, read_token
from cloudshield.config import Settings

MIN_SECRET_BYTES = 32
MIN_SECRET_CHARACTERS = 10
WRONG = "The role or password is wrong."
LOG_IN_FIRST = "Log in first."
VIEWING_ONLY = "Viewing only."
HASH_COMMAND = "python -m cloudshield.auth hash-password"
SECRET_COMMAND = "python -m cloudshield.auth secret"

router = APIRouter(prefix="/api/auth")


class AuthConfigError(RuntimeError):
    """The login settings are missing or too weak. The message says what to do."""


def check_settings(settings: Settings) -> None:
    """Refuses to start with the login on and settings that cannot protect anything. Messages
    never contain the value of a setting."""
    if not settings.auth_enabled:
        return
    hashes = (
        ("OWNER_PASSWORD_HASH", settings.owner_password_hash, True),
        ("VIEWER_PASSWORD_HASH", settings.viewer_password_hash, False),
    )
    for name, value, required in hashes:
        if value is None and required:
            raise AuthConfigError(
                f"AUTH_ENABLED is true but {name} is not set. Make one with: {HASH_COMMAND}"
            )
        if value is not None:
            try:
                parse_hash(value)
            except ValueError as exc:
                problem = f"{name} {exc}. Make a new one with: {HASH_COMMAND}"
                raise AuthConfigError(problem) from exc
    secret = settings.session_secret
    if secret is None:
        raise AuthConfigError(
            f"AUTH_ENABLED is true but SESSION_SECRET is not set. Make one with: {SECRET_COMMAND}"
        )
    if len(secret.encode("utf-8")) < MIN_SECRET_BYTES or len(set(secret)) < MIN_SECRET_CHARACTERS:
        raise AuthConfigError(
            "SESSION_SECRET is too weak. It must be random and at least 32 bytes long. "
            f"Make one with: {SECRET_COMMAND}"
        )
    if not 1 <= settings.session_hours <= 168:
        raise AuthConfigError("SESSION_HOURS must be between 1 and 168.")


def role_of(request: Request) -> str | None:
    """The role in the request's session cookie, or None."""
    token = request.cookies.get(COOKIE_NAME)
    secret = request.app.state.settings.session_secret
    return read_token(token, secret) if token and secret else None


def require_session(request: Request) -> None:
    """Runs before every /api route that is not open. A viewer may only read."""
    if not request.app.state.settings.auth_enabled:
        return
    role = role_of(request)
    if role is None:
        raise HTTPException(status_code=401, detail=LOG_IN_FIRST)
    if role == "viewer" and request.method != "GET":
        raise HTTPException(status_code=403, detail=VIEWING_ONLY)


def client_address(request: Request, settings: Settings) -> str:
    # X-Forwarded-For can be written by anyone, so it counts only when a setting says that a
    # proxy of yours puts it there. The last address is the one that proxy saw.
    forwarded = request.headers.get("x-forwarded-for")
    if settings.trust_forwarded_for and forwarded:
        return forwarded.split(",")[-1].strip()
    return request.client.host if request.client else "unknown"


def cookie_options(settings: Settings) -> dict:
    return {
        "httponly": True,
        "samesite": "strict",
        "secure": settings.cookie_secure,
        "path": "/",
    }


@router.post("/login", response_model=MeOut)
def login(body: LoginIn, request: Request, response: Response) -> MeOut:
    state = request.app.state
    settings = state.settings
    if not settings.auth_enabled:
        raise HTTPException(status_code=404, detail="The login is not turned on.")
    address = client_address(request, settings)
    now = time.time()
    wait = state.limiter.wait(address, now)
    if wait:
        detail = f"Too many wrong tries. Try again in {wait} seconds."
        raise HTTPException(status_code=429, detail=detail, headers={"Retry-After": str(wait)})

    hashes = {"owner": settings.owner_password_hash, "viewer": settings.viewer_password_hash}
    stored = hashes[body.role]
    # The check runs for every role, with a hash nobody knows when the role has no password.
    matches = verify_password(body.password, stored or unused_hash())
    if stored is None or not matches:
        state.limiter.fail(address, now)
        raise HTTPException(status_code=401, detail=WRONG)

    state.limiter.clear(address)
    token = make_token(body.role, settings.session_secret, settings.session_hours)
    max_age = settings.session_hours * 3600
    response.set_cookie(COOKIE_NAME, token, max_age=max_age, **cookie_options(settings))
    return MeOut(auth_enabled=True, role=body.role)


@router.post("/logout", status_code=204)
def logout(request: Request, response: Response) -> None:
    response.delete_cookie(COOKIE_NAME, **cookie_options(request.app.state.settings))


@router.get("/me", response_model=MeOut)
def me(request: Request) -> MeOut:
    """The login state, for the dashboard. It is open: without a session it answers 401."""
    if not request.app.state.settings.auth_enabled:
        return MeOut(auth_enabled=False, role="owner")
    role = role_of(request)
    if role is None:
        raise HTTPException(status_code=401, detail=LOG_IN_FIRST)
    return MeOut(auth_enabled=True, role=role)
