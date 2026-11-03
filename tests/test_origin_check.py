import pytest
from fastapi.testclient import TestClient
from prowler_data import entry, to_bytes

from cloudshield.api.app import create_app, same_origin
from cloudshield.config import Settings
from cloudshield.db.models import Base
from cloudshield.db.session import make_engine
from cloudshield.imports.importer import import_parsed
from cloudshield.imports.parser import parse_bytes

ALLOWED = "http://localhost:5173"
OTHER = "https://evil.example"
JSON = {"Content-Type": "application/json"}


@pytest.fixture
def scans_started():
    return []


@pytest.fixture
def client(tmp_path, monkeypatch, scans_started):
    monkeypatch.setenv("FRONTEND_ORIGIN", ALLOWED)
    monkeypatch.setenv("AWS_REGION", "ap-southeast-2")
    url = f"sqlite:///{tmp_path / 'test.db'}"
    Base.metadata.create_all(make_engine(url))

    def scan(regions):
        scans_started.append(regions)
        return {"resources": [], "errors": []}

    return TestClient(create_app(database_url=url, scan_function=scan, load_env=False))


def from_origin(origin):
    return {"Origin": origin}


def finding_id(client) -> str:
    with client.app.state.session_factory() as session:
        import_parsed(session, parse_bytes(to_bytes([entry(severity="High")])), "local")
    return client.get("/api/findings").json()[0]["finding_id"]


def test_the_default_frontend_origin_is_localhost_5173(monkeypatch):
    monkeypatch.delenv("FRONTEND_ORIGIN", raising=False)

    assert Settings().frontend_origin == "http://localhost:5173"


def test_a_scan_from_another_origin_is_refused_and_starts_nothing(client, scans_started):
    reply = client.post("/api/scans", headers=from_origin(OTHER))

    assert reply.status_code == 403
    assert "http://localhost:5173" in reply.json()["detail"]
    assert client.get("/api/scans").json() == []
    assert scans_started == []


def test_a_fix_from_another_origin_is_refused_and_makes_nothing(client):
    finding = finding_id(client)

    reply = client.post(f"/api/findings/{finding}/fix", headers=from_origin(OTHER))

    assert reply.status_code == 403
    assert client.get(f"/api/findings/{finding}/fix").status_code == 404


def test_an_upload_from_another_origin_is_refused_and_imports_nothing(client):
    body = to_bytes([entry()])

    reply = client.post(
        "/api/imports/prowler", content=body, headers={**JSON, **from_origin(OTHER)}
    )

    assert reply.status_code == 403
    assert client.get("/api/imports").json() == []
    assert client.get("/api/findings").json() == []


def test_a_dismissal_from_another_origin_is_refused_and_changes_nothing(client):
    finding = finding_id(client)
    body = {"disposition": "accepted", "disposition_reason": "This is accepted on purpose."}

    reply = client.patch(
        f"/api/findings/{finding}/disposition", json=body, headers=from_origin(OTHER)
    )

    assert reply.status_code == 403
    assert client.get(f"/api/findings/{finding}").json()["disposition"] == "none"


def test_a_delete_from_another_origin_is_refused(client):
    finding = finding_id(client)

    reply = client.delete(f"/api/findings/{finding}/disposition", headers=from_origin(OTHER))

    assert reply.status_code == 403


def test_the_configured_origin_is_allowed(client, scans_started):
    finding = finding_id(client)
    body = {"disposition": "accepted", "disposition_reason": "This is accepted on purpose."}

    upload = client.post(
        "/api/imports/prowler",
        content=to_bytes([entry(check="c9")]),
        headers={**JSON, **from_origin(ALLOWED)},
    )
    dismissed = client.patch(
        f"/api/findings/{finding}/disposition", json=body, headers=from_origin(ALLOWED)
    )
    started = client.post("/api/scans", headers=from_origin(ALLOWED))

    assert upload.status_code == 200
    assert dismissed.status_code == 200
    assert started.status_code == 202


def test_a_request_with_no_origin_is_allowed(client):
    finding = finding_id(client)
    body = {"disposition": "accepted", "disposition_reason": "This is accepted on purpose."}

    assert client.post("/api/scans").status_code == 202
    assert client.patch(f"/api/findings/{finding}/disposition", json=body).status_code == 200


def test_a_read_from_another_origin_is_not_refused(client):
    assert client.get("/api/scans", headers=from_origin(OTHER)).status_code == 200
    assert client.get("/api/health", headers=from_origin(OTHER)).status_code == 200


def test_a_preflight_is_left_to_the_cors_rules(client):
    headers = {**from_origin(OTHER), "Access-Control-Request-Method": "POST"}

    reply = client.options("/api/scans", headers=headers)

    assert reply.status_code != 403
    assert "access-control-allow-origin" not in reply.headers


@pytest.mark.parametrize(
    "origin",
    [
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "https://localhost:5173",
        "http://localhost",
        "http://localhost.evil.example:5173",
        "http://localhost:abc",
        "null",
        "",
    ],
)
def test_only_the_exact_scheme_host_and_port_match(client, origin):
    assert client.post("/api/scans", headers=from_origin(origin)).status_code == 403


@pytest.mark.parametrize("origin", ["HTTP://LOCALHOST:5173", "http://localhost:5173/"])
def test_case_and_a_trailing_slash_do_not_matter(client, origin):
    assert client.post("/api/scans", headers=from_origin(origin)).status_code == 202


def test_a_default_port_is_the_same_as_no_port():
    assert same_origin("https://app.example", "https://app.example:443")
    assert same_origin("http://app.example:80", "http://app.example")
    assert not same_origin("http://app.example", "https://app.example")
