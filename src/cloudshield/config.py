from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # A blank line such as PROWLER_TIMEOUT_SECONDS= (as in .env.example) means "use the default".
    model_config = SettingsConfigDict(env_ignore_empty=True)

    database_url: str = "sqlite:///cloudshield.db"
    aws_region: str | None = None
    gemini_api_key: str | None = None
    gemini_model: str | None = None
    gemini_fallback_model: str | None = None
    embedding_model: str | None = None
    ai_max_calls_per_hour: int = 30
    frontend_origin: str = "http://localhost:5173"
    # Comma separated names of identities that belong to CloudShield itself, such as its scanner
    # user. Findings about them are suggested as not applicable, never dismissed automatically.
    cloudshield_own_identities: str = ""
    # Extended checks: CloudShield runs Prowler as a separate program that you install yourself.
    # PROWLER_PYTHON is a Python that has prowler installed. PROWLER_COMMAND is a JSON list used
    # when it is empty.
    prowler_python: str = ""
    prowler_command: str = '["prowler"]'
    prowler_services: str = "s3 ec2 iam"
    prowler_timeout_seconds: int = 1800
    # local runs the Prowler above. docker runs the Prowler container instead.
    prowler_mode: Literal["local", "docker"] = "local"
    # A pinned version tag (for example toniblyx/prowler:5.44.0) is more reproducible than latest.
    prowler_docker_image: str = "toniblyx/prowler:latest"
    # The docker program, or its full path when it is not on the PATH of the server.
    docker_command: str = "docker"
    cloudshield_data_dir: str = "./data"
    keep_raw_output: bool = False


def load_env_file() -> None:
    # override=False: a variable that is already set in the shell wins over the file.
    load_dotenv(Path.cwd() / ".env", override=False)
