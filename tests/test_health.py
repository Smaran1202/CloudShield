from fastapi.testclient import TestClient

from cloudshield.api.app import create_app


def test_health_returns_ok_and_version():
    client = TestClient(create_app(load_env=False))

    response = client.get("/api/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["version"]


def test_cors_allows_only_the_frontend_origin(monkeypatch):
    monkeypatch.setenv("FRONTEND_ORIGIN", "http://localhost:5173")
    client = TestClient(create_app(load_env=False))

    allowed = client.get("/api/health", headers={"Origin": "http://localhost:5173"})
    other = client.get("/api/health", headers={"Origin": "http://evil.example"})

    assert allowed.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert "access-control-allow-origin" not in other.headers


def test_cors_allows_the_frontend_to_post(monkeypatch):
    monkeypatch.setenv("FRONTEND_ORIGIN", "http://localhost:5173")
    client = TestClient(create_app(load_env=False))

    response = client.options(
        "/api/scans",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"
