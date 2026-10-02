from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "sqlite:///cloudshield.db"
    gemini_api_key: str | None = None
    gemini_model: str | None = None
    gemini_fallback_model: str | None = None
    embedding_model: str | None = None
    frontend_origin: str = "http://localhost:5173"
