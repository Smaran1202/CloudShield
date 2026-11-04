import logging
import time
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from prowler_data import entry, to_bytes

from cloudshield.api.app import create_app
from cloudshield.auth.passwords import hash_password
from cloudshield.auth.routes import AuthConfigError
from cloudshield.auth.session import COOKIE_NAME, make_token
from cloudshield.db.models import Base, FindingRow
from cloudshield.db.session import make_engine
from cloudshield.imports.importer import import_parsed
from cloudshield.imports.parser import parse_bytes

OWNER = "the owner password for tests"
VIEWER = "the viewer password for tests"
SECRET = "a-test-secret-with-many-different-characters-0123456789"
ALLOWED = "http://localhost:5173"
OTHER = "https://evil.example"
JSON = {"Content-Type": "application/json"}
DISMISS = {"disposition": "accepted", "disposition_reason": "This is accepted on purpose."}
WRONG = "The role or password is wrong."


@pytest.fixture(scope="module")
def hashes():
    return SimpleNamespace(owner=hash_password(OWNER), viewer=hash_password(VIEWER))


@pytest.fixture
def scans_started():
    return []


@pytest.fixture
def build(tmp_path, monkeypatch, hashes, scans_started):
    """Makes an app with the login on. Settings can be changed or removed (None) for one test."""

    def make(address="203.0.113.5", **env):
        settings = {
            "AUTH_ENABLED": "true",
            "OWNER_PASSWORD_HASH": hashes.owner,
            "VIEWER_PASSWORD_HASH": hashes.viewer,
            "SESSION_SECRET": SECRET,
            "FRONTEND_ORIGIN": ALLOWED,
            "AWS_REGION": "ap-southeast-2",
            **env,
        }
        for name, value in settings.items():
            if value is None:
                monkeypatch.delenv(name, raising=False)
            else:
                monkeypatch.setenv(name, value)
        url = f"sqlite:///{tmp_path / 'test.db'}"
        Base.metadata.create_all(make_engine(url))

        def scan(regions):
            scans_started.append(regions)
            return {"resources": [], "errors": []}

        app = create_app(database_url=url, scan_function=scan, load_env=False)
        return TestClient(app, client=(address, 50000))

    return make


def log_in(client: TestClient, role: str, password: str):
    return client.post("/api/auth/login", json={"role": role, "password": password})


def logged_in(build, role="owner", **env) -> TestClient:
    client = build(**env)
    password = OWNER if role == "owner" else VIEWER
    assert log_in(client, role, password).status_code == 200
    return client


def a_finding(client: TestClient) -> str:
    with client.app.state.session_factory() as session:
        import_parsed(session, parse_bytes(to_bytes([entry(severity="High")])), "local")
        return session.query(FindingRow).one().finding_id


READS = [
    ("GET", "/api/scans"),
    ("GET", "/api/scans/1"),
    ("GET", "/api/resources"),
    ("GET", "/api/resources/imported"),
    ("GET", "/api/findings"),
    ("GET", "/api/findings/x"),
    ("GET", "/api/findings/x/fix"),
    ("GET", "/api/guardrails"),
    ("GET", "/api/imports"),
    ("GET", "/api/extended/status"),
]
WRITES = [
    ("POST", "/api/scans"),
    ("POST", "/api/findings/x/fix"),
    ("PATCH", "/api/findings/x/disposition"),
    ("DELETE", "/api/findings/x/disposition"),
    ("POST", "/api/imports/prowler"),
]


def send(client: TestClient, method: str, path: str, **extra):
    if method == "PATCH":
        extra.setdefault("json", DISMISS)
    if path.endswith("/prowler"):
        extra.setdefault("content", to_bytes([entry()]))
        extra["headers"] = {**JSON, **extra.get("headers", {})}
    return client.request(method, path, **extra)


@pytest.mark.parametrize(("method", "path"), [*READS, *WRITES])
def test_every_route_needs_a_session_when_the_login_is_on(build, method, path):
    client = build()

    reply = send(client, method, path)

    assert reply.status_code == 401
    assert reply.json() == {"detail": "Log in first."}


def test_nothing_is_started_or_stored_without_a_session(build, scans_started):
    client = build()

    send(client, "POST", "/api/scans")
    send(client, "POST", "/api/imports/prowler")

    assert scans_started == []
    owner = logged_in(build)
    assert owner.get("/api/scans").json() == []
    assert owner.get("/api/imports").json() == []


def test_health_the_login_and_me_are_open(build):
    client = build()

    assert client.get("/api/health").status_code == 200
    assert client.get("/api/auth/me").status_code == 401
    assert log_in(client, "owner", OWNER).status_code == 200
    assert client.post("/api/auth/logout").status_code == 204


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_the_interactive_docs_are_off_when_the_login_is_on(build, path):
    client = logged_in(build)

    assert client.get(path).status_code == 404


def test_a_wrong_password_gives_the_same_answer_whatever_the_role(build):
    answers = []
    for role, password in [("owner", "wrong"), ("viewer", "wrong"), ("owner", VIEWER)]:
        reply = log_in(build(), role, password)
        answers.append((reply.status_code, reply.json(), "set-cookie" in reply.headers))
    no_viewer = log_in(build(VIEWER_PASSWORD_HASH=None), "viewer", VIEWER)
    answers.append((no_viewer.status_code, no_viewer.json(), "set-cookie" in no_viewer.headers))

    assert set(map(str, answers)) == {str((401, {"detail": WRONG}, False))}


def test_the_owner_password_does_not_open_the_viewer_role_and_the_reverse(build):
    client = build()

    assert log_in(client, "viewer", OWNER).status_code == 401
    assert log_in(client, "owner", VIEWER).status_code == 401


def test_a_login_with_a_role_that_does_not_exist_is_refused(build):
    reply = log_in(build(), "admin", OWNER)

    assert reply.status_code == 422


def test_me_says_the_role_of_the_session(build):
    assert logged_in(build, "owner").get("/api/auth/me").json() == {
        "auth_enabled": True,
        "role": "owner",
    }
    assert logged_in(build, "viewer").get("/api/auth/me").json() == {
        "auth_enabled": True,
        "role": "viewer",
    }


def test_the_cookie_is_http_only_strict_and_not_secure_locally(build):
    reply = log_in(build(), "owner", OWNER)

    cookie = reply.headers["set-cookie"].lower()
    assert cookie.startswith(f"{COOKIE_NAME}=")
    assert "httponly" in cookie
    assert "samesite=strict" in cookie
    assert "path=/" in cookie
    assert "max-age=28800" in cookie
    assert "secure" not in cookie.replace("samesite", "")


def test_the_cookie_is_secure_when_cookie_secure_is_true_and_lasts_session_hours(build):
    reply = log_in(build(COOKIE_SECURE="true", SESSION_HOURS="2"), "viewer", VIEWER)

    cookie = reply.headers["set-cookie"].lower()
    assert "; secure" in cookie
    assert "httponly" in cookie
    assert "max-age=7200" in cookie


def test_the_token_in_the_cookie_is_signed_and_holds_only_the_role_and_an_expiry(build):
    client = logged_in(build, "viewer")

    token = client.cookies.get(COOKIE_NAME)

    assert token.count(".") == 1
    assert OWNER not in token and VIEWER not in token


def test_the_owner_can_use_every_route(build):
    client = logged_in(build)
    finding = a_finding(client)
    other_file = to_bytes([entry(check="c9")])

    assert send(client, "POST", "/api/imports/prowler", content=other_file).status_code == 200
    assert client.patch(f"/api/findings/{finding}/disposition", json=DISMISS).status_code == 200
    assert client.delete(f"/api/findings/{finding}/disposition").status_code == 200
    assert client.post(f"/api/findings/{finding}/fix").status_code == 200
    for method, path in READS:
        assert send(client, method, path).status_code != 401
    assert client.post("/api/scans").status_code == 202


@pytest.mark.parametrize(("method", "path"), WRITES)
def test_a_viewer_gets_403_on_every_write_route(build, method, path):
    client = logged_in(build, "viewer")

    reply = send(client, method, path)

    assert reply.status_code == 403
    assert reply.json() == {"detail": "Viewing only."}


def test_a_viewer_can_read_and_a_blocked_write_changes_nothing(build, scans_started):
    client = logged_in(build, "viewer")
    finding = a_finding(client)

    for method, path in READS[:5]:
        assert client.request(method, path).status_code in (200, 404)
    client.post("/api/scans")
    client.patch(f"/api/findings/{finding}/disposition", json=DISMISS)
    client.post("/api/imports/prowler", content=to_bytes([entry(check="c9")]), headers=JSON)

    assert scans_started == []
    assert client.get("/api/scans").json() == []
    assert client.get(f"/api/findings/{finding}").json()["disposition"] == "none"
    assert len(client.get("/api/imports").json()) == 1


def test_a_viewer_is_stopped_before_the_body_is_read_or_checked(build):
    client = logged_in(build, "viewer")

    reply = client.patch("/api/findings/x/disposition", json={"nonsense": True})

    assert reply.status_code == 403


def test_logout_clears_the_cookie_and_the_session_stops_working(build):
    client = logged_in(build)
    assert client.get("/api/scans").status_code == 200

    reply = client.post("/api/auth/logout")

    assert reply.status_code == 204
    cookie = reply.headers["set-cookie"].lower()
    assert "max-age=0" in cookie or "expires=thu, 01 jan 1970" in cookie
    assert "httponly" in cookie and "samesite=strict" in cookie
    assert client.get("/api/scans").status_code == 401
    assert client.get("/api/auth/me").status_code == 401


def test_logout_works_without_a_session_and_for_a_viewer(build):
    assert build().post("/api/auth/logout").status_code == 204
    assert logged_in(build, "viewer").post("/api/auth/logout").status_code == 204


def cookie_for(token: str) -> dict:
    return {"Cookie": f"{COOKIE_NAME}={token}"}


def test_a_token_made_with_the_secret_is_accepted(build):
    token = make_token("owner", SECRET, hours=1)

    assert build().get("/api/scans", headers=cookie_for(token)).status_code == 200


def test_an_expired_token_is_refused(build):
    token = make_token("owner", SECRET, hours=1, now=time.time() - 2 * 3600)

    assert build().get("/api/scans", headers=cookie_for(token)).status_code == 401


def test_a_token_that_was_changed_or_signed_with_another_secret_is_refused(build):
    client = build()
    token = make_token("viewer", SECRET, hours=1)
    other = make_token("owner", SECRET + "x", hours=1)
    owner_payload = make_token("owner", SECRET, hours=1).split(".")[0]
    swapped = owner_payload + "." + token.split(".")[1]

    for bad in (other, swapped, token[:-2] + "AA", "garbage", ""):
        assert client.get("/api/scans", headers=cookie_for(bad)).status_code == 401


def test_after_five_wrong_passwords_the_address_gets_429_with_a_wait_time(build):
    client = build()

    for _ in range(5):
        assert log_in(client, "owner", "wrong").status_code == 401
    reply = log_in(client, "owner", "wrong")
    right = log_in(client, "owner", OWNER)

    assert reply.status_code == 429
    assert 0 < int(reply.headers["retry-after"]) <= 300
    assert f"in {reply.headers['retry-after']} seconds" in reply.json()["detail"]
    assert right.status_code == 429
    assert "set-cookie" not in right.headers


def test_the_limit_is_for_one_address_and_a_good_login_resets_the_count(build):
    client = build()
    for _ in range(4):
        log_in(client, "owner", "wrong")
    assert log_in(client, "owner", OWNER).status_code == 200
    for _ in range(4):
        log_in(client, "owner", "wrong")
    other = TestClient(client.app, client=("198.51.100.9", 50000))

    assert log_in(client, "owner", "wrong").status_code == 401
    for _ in range(6):
        log_in(client, "owner", "wrong")
    assert log_in(client, "owner", "wrong").status_code == 429
    assert log_in(other, "owner", OWNER).status_code == 200


def test_a_forwarded_for_header_is_ignored_unless_a_setting_says_to_trust_it(build):
    client = build()

    for number in range(6):
        reply = client.post(
            "/api/auth/login",
            json={"role": "owner", "password": "wrong"},
            headers={"X-Forwarded-For": f"10.0.0.{number}"},
        )

    assert reply.status_code == 429


def test_a_forwarded_for_header_counts_when_the_setting_trusts_it(build):
    client = build(TRUST_FORWARDED_FOR="true")

    def attempt(forwarded: str):
        headers = {"X-Forwarded-For": f"6.6.6.6, {forwarded}"}
        body = {"role": "owner", "password": "wrong"}
        return client.post("/api/auth/login", json=body, headers=headers)

    for _ in range(5):
        assert attempt("10.0.0.1").status_code == 401

    assert attempt("10.0.0.1").status_code == 429
    assert attempt("10.0.0.2").status_code == 401


def test_cors_allows_credentials_for_the_configured_origin_only(build):
    client = build()
    preflight = {"Origin": ALLOWED, "Access-Control-Request-Method": "POST"}

    allowed = client.options("/api/scans", headers=preflight)
    foreign = client.options("/api/scans", headers={**preflight, "Origin": OTHER})

    assert allowed.headers["access-control-allow-origin"] == ALLOWED
    assert allowed.headers["access-control-allow-credentials"] == "true"
    assert foreign.status_code == 400
    assert "access-control-allow-origin" not in foreign.headers


def test_a_401_still_carries_the_cors_headers_so_the_dashboard_can_read_it(build):
    reply = build().get("/api/scans", headers={"Origin": ALLOWED})

    assert reply.status_code == 401
    assert reply.headers["access-control-allow-origin"] == ALLOWED
    assert reply.headers["access-control-allow-credentials"] == "true"


def test_cors_never_uses_a_wildcard(build):
    client = logged_in(build)

    for origin in (ALLOWED, OTHER, "null", "*"):
        reply = client.get("/api/health", headers={"Origin": origin})
        assert reply.headers.get("access-control-allow-origin") != "*"


def test_the_origin_check_still_refuses_a_write_from_another_origin_even_with_a_session(
    build, scans_started
):
    client = logged_in(build)

    reply = client.post("/api/scans", headers={"Origin": OTHER})

    assert reply.status_code == 403
    assert "another origin" in reply.json()["detail"]
    assert scans_started == []


def test_a_login_from_another_origin_is_refused(build):
    reply = build().post(
        "/api/auth/login", json={"role": "owner", "password": OWNER}, headers={"Origin": OTHER}
    )

    assert reply.status_code == 403
    assert "set-cookie" not in reply.headers


def test_no_password_or_token_is_logged(build, caplog):
    caplog.set_level(logging.DEBUG)
    client = build()

    log_in(client, "owner", "a wrong password nobody should see")
    log_in(client, "owner", OWNER)
    token = client.cookies.get(COOKIE_NAME)
    client.get("/api/scans")
    client.post("/api/auth/logout")
    build().get("/api/scans", headers=cookie_for("a-bad-token-value"))

    assert "a wrong password nobody should see" not in caplog.text
    assert OWNER not in caplog.text
    assert token and token not in caplog.text
    assert "a-bad-token-value" not in caplog.text


@pytest.mark.parametrize(
    ("env", "message"),
    [
        ({"OWNER_PASSWORD_HASH": None}, "OWNER_PASSWORD_HASH is not set"),
        ({"OWNER_PASSWORD_HASH": "plain"}, "OWNER_PASSWORD_HASH"),
        ({"SESSION_SECRET": None}, "SESSION_SECRET is not set"),
        ({"SESSION_SECRET": "short"}, "SESSION_SECRET is too weak"),
    ],
)
def test_the_server_does_not_start_with_missing_or_weak_settings(build, env, message):
    with pytest.raises(AuthConfigError, match=message):
        build(**env)


def test_with_the_login_off_nothing_changes(build, monkeypatch):
    client = build(AUTH_ENABLED=None, OWNER_PASSWORD_HASH=None, SESSION_SECRET=None)

    assert client.get("/api/scans").status_code == 200
    assert client.post("/api/scans").status_code == 202
    assert client.get("/api/auth/me").json() == {"auth_enabled": False, "role": "owner"}
    assert log_in(client, "owner", OWNER).status_code == 404
    assert client.post("/api/auth/logout").status_code == 204
    assert client.get("/docs").status_code == 200
    assert client.get("/openapi.json").status_code == 200
    assert "set-cookie" not in client.get("/api/scans").headers


def test_with_the_login_off_a_viewer_cookie_makes_no_difference(build):
    client = build(AUTH_ENABLED="false")
    token = make_token("viewer", SECRET, hours=1)

    assert client.post("/api/scans", headers=cookie_for(token)).status_code == 202
