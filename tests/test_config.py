from cloudshield.config import Settings


def test_defaults_when_environment_is_empty(monkeypatch):
    for name in [
        "DATABASE_URL",
        "GEMINI_API_KEY",
        "GEMINI_MODEL",
        "GEMINI_FALLBACK_MODEL",
        "EMBEDDING_MODEL",
        "FRONTEND_ORIGIN",
    ]:
        monkeypatch.delenv(name, raising=False)

    settings = Settings()

    assert settings.database_url == "sqlite:///cloudshield.db"
    assert settings.frontend_origin == "http://localhost:5173"
    assert settings.gemini_api_key is None
    assert settings.gemini_model is None
    assert settings.gemini_fallback_model is None
    assert settings.embedding_model is None


def test_environment_overrides_defaults(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///other.db")
    monkeypatch.setenv("FRONTEND_ORIGIN", "http://localhost:3000")

    settings = Settings()

    assert settings.database_url == "sqlite:///other.db"
    assert settings.frontend_origin == "http://localhost:3000"
