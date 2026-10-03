import os
import re
from pathlib import Path

import httpx
from moto import mock_aws

from cloudshield.api.app import create_app
from cloudshield.config import load_env_file
from cloudshield.fixes import __main__ as fixes_main
from cloudshield.fixes.ai_check import run_ai_check
from cloudshield.scanner.__main__ import main as scanner_main

ROOT = Path(__file__).resolve().parents[1]


def use_env_file(tmp_path, monkeypatch, text: str) -> None:
    # Work on a copy of the environment so nothing the file sets leaks into other tests, and
    # use a temporary working directory so the real .env is never read.
    monkeypatch.setattr(os, "environ", os.environ.copy())
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text(text, encoding="utf-8")


def ok_transport() -> httpx.MockTransport:
    body = {"candidates": [{"content": {"parts": [{"text": "ok"}]}}]}
    return httpx.MockTransport(lambda request: httpx.Response(200, json=body))


def test_a_dot_env_in_the_working_directory_is_loaded(tmp_path, monkeypatch):
    use_env_file(tmp_path, monkeypatch, "GEMINI_MODEL=model-from-file\n")

    load_env_file()

    assert os.environ["GEMINI_MODEL"] == "model-from-file"


def test_a_variable_already_in_the_environment_is_not_overridden(tmp_path, monkeypatch):
    use_env_file(tmp_path, monkeypatch, "GEMINI_MODEL=model-from-file\nAWS_REGION=eu-west-1\n")
    monkeypatch.setenv("GEMINI_MODEL", "model-from-shell")

    load_env_file()

    assert os.environ["GEMINI_MODEL"] == "model-from-shell"
    assert os.environ["AWS_REGION"] == "eu-west-1"


def test_a_missing_dot_env_is_not_an_error(tmp_path, monkeypatch):
    use_env_file(tmp_path, monkeypatch, "")
    (tmp_path / ".env").unlink()
    before = dict(os.environ)

    load_env_file()

    assert dict(os.environ) == before


def test_create_app_reads_the_dot_env_by_default(tmp_path, monkeypatch):
    use_env_file(tmp_path, monkeypatch, "FRONTEND_ORIGIN=http://localhost:9999\n")

    app = create_app()

    assert app.state.settings.frontend_origin == "http://localhost:9999"


def test_create_app_does_not_read_the_dot_env_when_load_env_is_false(tmp_path, monkeypatch):
    use_env_file(tmp_path, monkeypatch, "FRONTEND_ORIGIN=http://localhost:9999\n")

    app = create_app(load_env=False)

    assert app.state.settings.frontend_origin == "http://localhost:5173"


def test_create_app_keeps_a_variable_that_is_already_set(tmp_path, monkeypatch):
    use_env_file(tmp_path, monkeypatch, "FRONTEND_ORIGIN=http://localhost:9999\n")
    monkeypatch.setenv("FRONTEND_ORIGIN", "http://localhost:3000")

    app = create_app()

    assert app.state.settings.frontend_origin == "http://localhost:3000"


@mock_aws
def test_the_scanner_command_reads_the_dot_env(tmp_path, monkeypatch, capsys):
    use_env_file(tmp_path, monkeypatch, "AWS_REGION=eu-west-1\n")

    exit_code = scanner_main([])

    assert exit_code == 0
    assert "Regions scanned: eu-west-1" in capsys.readouterr().out


def test_the_fixes_command_reads_the_dot_env(tmp_path, monkeypatch, capsys):
    use_env_file(tmp_path, monkeypatch, "GEMINI_API_KEY=not-a-real-key\nGEMINI_MODEL=model-a\n")
    transport = ok_transport()
    monkeypatch.setattr(fixes_main, "run_ai_check", lambda c: run_ai_check(c, transport))

    exit_code = fixes_main.main(["ai-check"])

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "GEMINI_API_KEY: set (length 14)" in output
    assert "model-a: ok" in output
    assert "not-a-real-key" not in output


def test_the_fixes_command_prefers_a_variable_set_in_the_shell(tmp_path, monkeypatch, capsys):
    use_env_file(tmp_path, monkeypatch, "GEMINI_API_KEY=not-a-real-key\nGEMINI_MODEL=model-a\n")
    monkeypatch.setenv("GEMINI_MODEL", "shell-model")
    transport = ok_transport()
    monkeypatch.setattr(fixes_main, "run_ai_check", lambda c: run_ai_check(c, transport))

    fixes_main.main(["ai-check"])

    output = capsys.readouterr().out
    assert "GEMINI_MODEL: shell-model" in output
    assert "model-a" not in output


def test_the_example_file_lists_names_only():
    lines = (ROOT / ".env.example").read_text(encoding="utf-8").splitlines()

    entries = [line for line in lines if line.strip() and not line.startswith("#")]

    assert entries
    assert all(re.fullmatch(r"[A-Z_]+=", line) for line in entries)
