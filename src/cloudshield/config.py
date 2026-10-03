from pathlib import Path

from dotenv import load_dotenv
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "sqlite:///cloudshield.db"
    aws_region: str | None = None
    gemini_api_key: str | None = None
    gemini_model: str | None = None
    gemini_fallback_model: str | None = None
    embedding_model: str | None = None
    ai_max_calls_per_hour: int = 30
    frontend_origin: str = "http://localhost:5173"


def load_env_file() -> None:
    # override=False: a variable that is already set in the shell wins over the file.
    load_dotenv(Path.cwd() / ".env", override=False)
