from pathlib import Path

from cloudshield.config import Settings

ENV_EXAMPLE = Path(__file__).resolve().parents[1] / ".env.example"


def names_in_env_example() -> list[str]:
    lines = ENV_EXAMPLE.read_text(encoding="utf-8").splitlines()
    return [line.split("=")[0] for line in lines if "=" in line and not line.startswith("#")]


def test_every_name_in_env_example_is_blank_in_the_file():
    for line in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.startswith("#"):
            assert line.split("=", 1)[1] == "", line


def test_a_copy_of_env_example_with_every_value_blank_loads_with_all_defaults(monkeypatch):
    names = names_in_env_example()
    assert "PROWLER_TIMEOUT_SECONDS" in names
    assert "PROWLER_MODE" in names
    for name in names:
        monkeypatch.delenv(name, raising=False)
    defaults = Settings().model_dump()

    for name in names:
        monkeypatch.setenv(name, "")
    blank = Settings().model_dump()

    assert blank == defaults
    assert blank["prowler_timeout_seconds"] == 1800
    assert blank["prowler_mode"] == "local"
    assert blank["keep_raw_output"] is False


def test_a_value_that_is_set_still_wins_over_the_default(monkeypatch):
    monkeypatch.setenv("PROWLER_TIMEOUT_SECONDS", "60")
    monkeypatch.setenv("PROWLER_MODE", "docker")

    settings = Settings()

    assert settings.prowler_timeout_seconds == 60
    assert settings.prowler_mode == "docker"
