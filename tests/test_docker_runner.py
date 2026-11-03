import re
import threading
import time
from functools import partial
from pathlib import Path

import pytest
from botocore.exceptions import BotoCoreError
from fake_docker import TIMEOUT, FakeDocker, fake_credentials, no_credentials_please
from fake_prowler import FakePopen, FakeProcess, Killer, settings_for
from fastapi.testclient import TestClient

from cloudshield.api.app import create_app
from cloudshield.db.models import Base
from cloudshield.db.session import make_engine
from cloudshield.imports import __main__ as import_cli
from cloudshield.imports import runner
from cloudshield.imports.runner import (
    DOCKER_DOWN_HINT,
    DOCKER_ENV,
    DOCKER_IMAGE_HINT,
    DOCKER_MISSING_HINT,
    ONEDRIVE_WARNING,
    ExtendedError,
    check_runner,
    docker_environment,
    profile_credentials,
    run_prowler,
)

REGIONS = ["ap-southeast-2"]
DOCKER = "C:/docker/docker.exe"


def docker_settings(tmp_path, **overrides):
    return settings_for(tmp_path, prowler_mode="docker", docker_command=DOCKER, **overrides)


def run(tmp_path, popen=None, docker=None, kill=None, environ=None, credentials=None, **settings):
    configured = docker_settings(tmp_path)
    for name, value in settings.items():
        setattr(configured, name, value)
    return run_prowler(
        configured,
        REGIONS,
        popen=popen or FakePopen(),
        kill=kill or Killer(),
        environ={"PATH": "/bin"} if environ is None else environ,
        poll_seconds=0.01,
        run=docker or FakeDocker(),
        credentials=credentials or fake_credentials(),
    )


def container_name(popen) -> str:
    return popen.argv[4]


def test_the_docker_command_is_exactly_the_agreed_list(tmp_path):
    popen = FakePopen()

    output = run(tmp_path, popen)

    argv = popen.argv
    run_dir = Path(popen.calls[0]["cwd"]).resolve()
    assert re.fullmatch(r"cloudshield-[0-9a-f]{32}", container_name(popen))
    assert argv == [
        DOCKER,
        "run",
        "--rm",
        "--name",
        container_name(popen),
        "-v",
        f"{run_dir}:/home/prowler/output",
        "-e",
        "AWS_ACCESS_KEY_ID",
        "-e",
        "AWS_SECRET_ACCESS_KEY",
        "-e",
        "AWS_SESSION_TOKEN",
        "toniblyx/prowler:latest",
        "aws",
        "-f",
        "ap-southeast-2",
        "--services",
        "s3",
        "ec2",
        "iam",
        "-M",
        "json-ocsf",
        "-b",
        "-z",
    ]
    assert output.mode == "docker"
    assert output.image == "toniblyx/prowler:latest"


def test_the_command_is_a_list_with_no_credential_values_no_shell_and_no_aws_folder(tmp_path):
    popen = FakePopen()

    run(tmp_path, popen, credentials=fake_credentials(token="fake-session-token"))

    call = popen.calls[0]
    text = " ".join(call["argv"])
    assert all(isinstance(part, str) for part in call["argv"])
    assert "shell" not in call
    for secret in ("AKIAFAKEFAKEFAKE1234", "fake-secret-value-for-tests", "fake-session-token"):
        assert secret not in text
    assert ".aws" not in text
    assert "-o" not in call["argv"]


def test_the_flags_come_from_the_same_function_as_the_cloudshell_command(tmp_path):
    popen = FakePopen()
    run(tmp_path, popen)

    flags = popen.argv[popen.argv.index("aws") :]

    assert flags == ["aws", "-f", "ap-southeast-2", "--services", "s3", "ec2", "iam"] + [
        "-M",
        "json-ocsf",
        "-b",
        "-z",
    ]


def test_the_child_environment_is_the_docker_allowlist_plus_the_aws_credentials(tmp_path):
    popen = FakePopen()
    environ = {
        "PATH": "/bin",
        "DOCKER_HOST": "tcp://engine:2375",
        "GEMINI_API_KEY": "fake-gemini-secret",
        "DATABASE_URL": "sqlite:///x.db",
        "AWS_PROFILE": "scanner",
        "AWS_SECRET_ACCESS_KEY": "fake-from-the-shell",
        "SOMETHING_SECRET": "fake-secret",
    }

    run(tmp_path, popen, environ=environ)

    assert popen.calls[0]["env"] == {
        "PATH": "/bin",
        "DOCKER_HOST": "tcp://engine:2375",
        "AWS_ACCESS_KEY_ID": "AKIAFAKEFAKEFAKE1234",
        "AWS_SECRET_ACCESS_KEY": "fake-secret-value-for-tests",
    }
    assert "fake-gemini-secret" not in str(popen.calls)


def test_the_docker_allowlist_is_exactly_the_agreed_list():
    assert set(DOCKER_ENV) == {
        "PATH",
        "SYSTEMROOT",
        "SYSTEMDRIVE",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "HOME",
        "APPDATA",
        "LOCALAPPDATA",
        "XDG_RUNTIME_DIR",
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "DOCKER_CONFIG",
        "DOCKER_CERT_PATH",
        "DOCKER_TLS",
        "DOCKER_TLS_VERIFY",
    }
    only = docker_environment({"GEMINI_API_KEY": "x", "AWS_PROFILE": "p", "TEMP": "t"})
    assert only == {"TEMP": "t"}


def test_no_session_token_variable_when_the_profile_has_none(tmp_path):
    popen = FakePopen()

    run(tmp_path, popen)

    assert "AWS_SESSION_TOKEN" not in popen.calls[0]["env"]


def test_the_session_token_is_passed_when_the_profile_has_one(tmp_path):
    popen = FakePopen()

    run(tmp_path, popen, credentials=fake_credentials(token="fake-session-token"))

    assert popen.calls[0]["env"]["AWS_SESSION_TOKEN"] == "fake-session-token"


def test_a_name_that_is_not_plain_is_refused_before_credentials_or_docker_are_used(tmp_path):
    popen = FakePopen()
    docker = FakeDocker()

    with pytest.raises(ExtendedError):
        run(tmp_path, popen, docker, credentials=no_credentials_please, prowler_services="s3;rm")

    assert popen.calls == []
    assert docker.calls == []


@pytest.mark.parametrize("image", ["--privileged", "-x", "a b", ""])
def test_an_image_name_that_could_be_an_option_is_refused(tmp_path, image):
    popen = FakePopen()

    with pytest.raises(ExtendedError, match="PROWLER_DOCKER_IMAGE"):
        run(tmp_path, popen, credentials=no_credentials_please, prowler_docker_image=image)

    assert popen.calls == []


def test_a_timeout_kills_the_client_and_stops_the_container(tmp_path):
    process = FakeProcess(hang=True)
    killer = Killer()
    docker = FakeDocker()
    popen = FakePopen(process)

    with pytest.raises(ExtendedError, match="did not finish within"):
        run(tmp_path, popen, docker, killer, prowler_timeout_seconds=0.05)

    name = container_name(popen)
    assert killer.killed == [process]
    assert ["kill", name] in docker.words()
    assert ["rm", "-f", name] in docker.words()


def test_a_cancel_kills_the_client_and_stops_the_container(tmp_path):
    process = FakeProcess(hang=True)
    killer = Killer()
    docker = FakeDocker()
    popen = FakePopen(process)
    cancel = threading.Event()
    cancel.set()

    with pytest.raises(ExtendedError, match="cancelled"):
        run_prowler(
            docker_settings(tmp_path),
            REGIONS,
            popen=popen,
            kill=killer,
            cancel=cancel,
            environ={"PATH": "/bin"},
            poll_seconds=0.01,
            run=docker,
            credentials=fake_credentials(),
        )

    assert killer.killed == [process]
    assert ["rm", "-f", container_name(popen)] in docker.words()


def test_the_container_is_removed_in_the_end_even_after_a_normal_run(tmp_path):
    docker = FakeDocker()
    popen = FakePopen()

    run(tmp_path, popen, docker)

    assert docker.words()[-1] == ["rm", "-f", container_name(popen)]
    assert all("credential" not in str(call) for call in docker.calls)
    assert "AWS_ACCESS_KEY_ID" not in docker.calls[0]["env"]


def test_docker_missing_when_a_run_starts_is_unavailable_with_the_path_hint(tmp_path):
    docker = FakeDocker()
    popen = FakePopen(error=FileNotFoundError(2, "No such file"))

    with pytest.raises(ExtendedError) as caught:
        run(tmp_path, popen, docker)

    assert caught.value.status == "unavailable"
    assert caught.value.message == "Docker was not found."
    assert "DOCKER_COMMAND" in caught.value.hint
    assert ["rm", "-f", container_name_from(docker)] in docker.words()


def container_name_from(docker) -> str:
    return docker.calls[0]["argv"][-1]


def test_an_engine_that_is_not_running_is_reported_from_the_client_output(tmp_path):
    err = b"error during connect: this error may indicate that the docker daemon is not running"
    popen = FakePopen(FakeProcess(code=1, err=err))

    with pytest.raises(ExtendedError) as caught:
        run(tmp_path, popen)

    assert caught.value.status == "unavailable"
    assert caught.value.hint == DOCKER_DOWN_HINT


def test_the_run_folder_is_removed_unless_kept_and_failures_are_redacted(tmp_path):
    popen = FakePopen(FakeProcess(code=1, err=b"key AKIAABCDEFGHIJKLMNOP account 123456789012"))

    with pytest.raises(ExtendedError) as caught:
        run(tmp_path, popen)

    assert "AKIAABCDEFGHIJKLMNOP" not in caught.value.message
    assert not list((tmp_path / "data" / "runs").iterdir())
    run(tmp_path, FakePopen(), keep_raw_output=True)
    assert len(list((tmp_path / "data" / "runs").iterdir())) == 1


def test_failed_checks_exit_code_3_is_not_a_failure(tmp_path):
    assert run(tmp_path, FakePopen(FakeProcess(code=3))).file_name.endswith(".ocsf.json")


def test_local_mode_does_not_touch_docker_or_credentials(tmp_path):
    popen = FakePopen()
    docker = FakeDocker()

    output = run_prowler(
        settings_for(tmp_path),
        REGIONS,
        popen=popen,
        kill=Killer(),
        environ={"PATH": "/bin"},
        poll_seconds=0.01,
        run=docker,
        credentials=no_credentials_please,
    )

    assert popen.argv[0] == "C:/tools/venv/Scripts/python.exe"
    assert "-o" in popen.argv
    assert docker.calls == []
    assert output.mode == "local"
    assert output.image is None


# status


def check(tmp_path, docker, **settings):
    return check_runner(docker_settings(tmp_path, **settings), docker)


def test_status_ready_when_the_engine_answers_and_the_image_is_here(tmp_path):
    docker = FakeDocker()

    status = check(tmp_path, docker)

    assert status.available is True
    assert status.reason is None
    assert status.hint is None
    assert "toniblyx/prowler:latest" in status.version
    assert docker.calls[0]["timeout"] == 10
    assert docker.words() == [
        ["version", "--format", "{{.Server.Version}}"],
        ["image", "inspect", "toniblyx/prowler:latest"],
    ]


def test_status_docker_not_found_suggests_the_full_path(tmp_path):
    status = check(tmp_path, FakeDocker(error=FileNotFoundError(2, "x")))

    assert status.available is False
    assert status.reason == "Docker was not found."
    assert status.hint == DOCKER_MISSING_HINT
    assert "DOCKER_COMMAND" in status.hint
    assert "terminal" in status.hint


def test_status_engine_not_running(tmp_path):
    status = check(tmp_path, FakeDocker(version_code=1))

    assert status.available is False
    assert "engine is not running" in status.reason
    assert status.hint == DOCKER_DOWN_HINT


def test_status_engine_that_does_not_answer_cannot_hang_the_check(tmp_path):
    status = check(tmp_path, FakeDocker(error=TIMEOUT))

    assert status.available is False
    assert "did not answer" in status.reason


def test_status_image_not_downloaded_can_still_run_and_says_the_first_run_downloads(tmp_path):
    docker = FakeDocker(image_code=1)

    status = check(tmp_path, docker)

    assert status.available is True
    assert "not downloaded" in status.reason
    assert status.hint == DOCKER_IMAGE_HINT
    assert "several minutes" in status.hint


def test_status_never_starts_a_container_or_pulls_an_image(tmp_path):
    docker = FakeDocker(image_code=1)

    check(tmp_path, docker)

    assert [words[0] for words in docker.words()] == ["version", "image"]
    assert "pull" not in str(docker.words())
    assert "run" not in [words[0] for words in docker.words()]


def test_status_docker_is_asked_without_secrets(tmp_path, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "fake-gemini-secret")
    docker = FakeDocker()

    check(tmp_path, docker)

    assert all("GEMINI_API_KEY" not in call["env"] for call in docker.calls)


def test_status_warns_when_the_data_folder_is_inside_onedrive(tmp_path):
    status = check(tmp_path, FakeDocker(), cloudshield_data_dir="C:/Users/x/OneDrive/Desktop/data")

    assert status.warning == ONEDRIVE_WARNING
    assert "CLOUDSHIELD_DATA_DIR" in status.warning


def test_status_has_no_warning_for_a_folder_outside_onedrive(tmp_path):
    assert check(tmp_path, FakeDocker()).warning is None


def test_the_onedrive_warning_is_for_docker_mode_only(tmp_path):
    local = settings_for(tmp_path, cloudshield_data_dir="C:/Users/x/OneDrive/data")

    class Local:
        returncode = 0
        stdout = b"Prowler 5.44.0"
        stderr = b""

    assert check_runner(local, lambda argv, **kwargs: Local()).warning is None


def test_the_cli_check_says_what_to_do_when_docker_cannot_run(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("PROWLER_MODE", "docker")
    monkeypatch.setenv("DOCKER_COMMAND", str(tmp_path / "no-such-docker.exe"))
    monkeypatch.setenv("CLOUDSHIELD_DATA_DIR", str(tmp_path / "data"))

    code = import_cli.main(["check-runner"], load_env=False)

    printed = capsys.readouterr().out
    assert code == 1
    assert "Docker was not found." in printed
    assert "DOCKER_COMMAND" in printed


# a whole scan


def test_a_full_scan_in_docker_mode_records_the_version_the_mode_and_the_image(tmp_path):
    url = f"sqlite:///{tmp_path / 'test.db'}"
    Base.metadata.create_all(make_engine(url))
    popen = FakePopen()
    extended = partial(
        run_prowler,
        docker_settings(tmp_path),
        popen=popen,
        kill=Killer(),
        environ={"PATH": "/bin"},
        poll_seconds=0.01,
        run=FakeDocker(),
        credentials=fake_credentials(),
    )
    app = create_app(
        database_url=url,
        scan_function=lambda regions: {"resources": [], "errors": []},
        load_env=False,
        extended_function=extended,
    )
    client = TestClient(app)

    started = client.post("/api/scans", json={"regions": REGIONS, "extended": True}).json()
    scan = wait_until_done(client, started["id"])

    imports = client.get("/api/imports").json()
    assert scan["extended_status"] == "ok"
    assert imports[0]["origin"] == "dashboard"
    assert imports[0]["tool_version"] == "5.44.0"
    assert imports[0]["run_mode"] == "docker"
    assert imports[0]["run_image"] == "toniblyx/prowler:latest"


def wait_until_done(client, scan_id: int) -> dict:
    for _ in range(400):
        scan = client.get(f"/api/scans/{scan_id}").json()
        if scan["status"] in ("completed", "failed"):
            return scan
        time.sleep(0.01)
    raise AssertionError("the scan did not end")


# the real credential reader. The fake keys come from conftest.py and from the tests themselves.


@pytest.fixture
def no_aws_files(tmp_path, monkeypatch):
    # Points boto3 away from any real ~/.aws folder.
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "no-credentials"))
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "no-config"))
    for name in (
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_ROLE_ARN",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    ):
        monkeypatch.delenv(name, raising=False)


def test_the_profile_has_no_session_token_variable_when_it_has_no_token(no_aws_files):
    values = profile_credentials()

    assert values == {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing"}
    assert "AWS_SESSION_TOKEN" not in values


def test_the_profile_has_a_session_token_variable_when_it_has_a_token(no_aws_files, monkeypatch):
    monkeypatch.setenv("AWS_SESSION_TOKEN", "fake-token-for-the-test")

    values = profile_credentials()

    assert values["AWS_SESSION_TOKEN"] == "fake-token-for-the-test"
    assert set(values) == {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"}


def test_no_credentials_at_all_is_a_clear_unavailable_error(no_aws_files, monkeypatch):
    monkeypatch.delenv("AWS_ACCESS_KEY_ID")
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY")

    with pytest.raises(ExtendedError) as caught:
        profile_credentials()

    assert caught.value.status == "unavailable"
    assert caught.value.message == "No AWS credentials were found."
    assert "AWS_PROFILE" in caught.value.hint


def test_a_botocore_error_is_a_clear_failed_error_with_no_details_from_the_library(monkeypatch):
    class Broken:
        def get_credentials(self):
            raise BotoCoreError()

    monkeypatch.setattr(runner.boto3, "Session", Broken)

    with pytest.raises(ExtendedError) as caught:
        profile_credentials()

    assert caught.value.status == "failed"
    assert "BotoCoreError" in caught.value.message
    assert "AWS_PROFILE" in caught.value.hint


def test_with_the_real_reader_no_secret_is_in_an_argument_list(tmp_path, monkeypatch, no_aws_files):
    secrets = {
        "AWS_ACCESS_KEY_ID": "AKIAFAKEFAKEFAKE1234",
        "AWS_SECRET_ACCESS_KEY": "fake-secret-for-the-test",
        "AWS_SESSION_TOKEN": "fake-token-for-the-test",
    }
    for name, value in secrets.items():
        monkeypatch.setenv(name, value)
    popen = FakePopen()
    docker = FakeDocker()

    run_prowler(
        docker_settings(tmp_path),
        REGIONS,
        popen=popen,
        kill=Killer(),
        environ={"PATH": "/bin"},
        poll_seconds=0.01,
        run=docker,
    )

    argument_lists = [popen.argv, *(call["argv"] for call in docker.calls)]
    for argv in argument_lists:
        for value in secrets.values():
            assert all(value not in part for part in argv)
    assert {name: popen.calls[0]["env"][name] for name in secrets} == secrets
    assert all(name not in call["env"] for call in docker.calls for name in secrets)
