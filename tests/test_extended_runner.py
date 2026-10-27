import logging
import subprocess
import threading
from pathlib import Path

import pytest
from fake_prowler import FakePopen, FakeProcess, Killer, results_file, settings_for

from cloudshield.imports import runner
from cloudshield.imports.runner import (
    ALLOWED_ENV,
    BLOCKED_HINT,
    ExtendedError,
    RunnerStatus,
    StatusCache,
    build_argv,
    check_runner,
    child_environment,
    cloudshell_command,
    run_prowler,
)

REGIONS = ["ap-southeast-2"]
PYTHON = "C:/tools/venv/Scripts/python.exe"


def run(tmp_path, popen=None, regions=REGIONS, kill=None, timeout=None, **settings):
    configured = settings_for(tmp_path, **settings)
    if timeout is not None:
        configured.prowler_timeout_seconds = timeout
    return run_prowler(
        configured,
        regions,
        popen=popen or FakePopen(),
        kill=kill or Killer(),
        poll_seconds=0.01,
    )


def run_dirs(tmp_path) -> list[Path]:
    runs = tmp_path / "data" / "runs"
    return list(runs.iterdir()) if runs.exists() else []


def test_a_run_returns_the_results_file(tmp_path):
    popen = FakePopen()

    output = run(tmp_path, popen)

    assert output.file_name == "prowler-output-1.ocsf.json"
    assert output.content == results_file()
    assert output.services == ["s3", "ec2", "iam"]
    assert output.regions == REGIONS
    assert output.duration_seconds >= 0
    assert output.saw_permission_errors is False


def test_the_command_is_a_list_with_only_checked_values_and_no_shell(tmp_path):
    popen = FakePopen()

    run(tmp_path, popen, regions=["ap-southeast-2", "us-east-1"])

    call = popen.calls[0]
    run_dir = call["cwd"]
    assert call["argv"] == [
        PYTHON,
        "-m",
        "prowler",
        "aws",
        "-f",
        "ap-southeast-2",
        "us-east-1",
        "--services",
        "s3",
        "ec2",
        "iam",
        "-M",
        "json-ocsf",
        "-o",
        str(Path(run_dir).resolve()),
        "-b",
        "-z",
    ]
    assert all(isinstance(part, str) for part in call["argv"])
    assert "shell" not in call
    assert call["stdin"] == subprocess.DEVNULL


def test_the_run_happens_in_its_own_folder_under_the_data_directory(tmp_path):
    popen = FakePopen()

    run(tmp_path, popen)

    run_dir = Path(popen.calls[0]["cwd"])
    assert run_dir.parent == tmp_path / "data" / "runs"
    assert len(run_dir.name) == 32


def test_the_command_setting_is_used_when_there_is_no_python(tmp_path):
    popen = FakePopen()

    run(tmp_path, popen, prowler_python="", prowler_command='["docker", "run", "prowler"]')

    assert popen.argv[:4] == ["docker", "run", "prowler", "aws"]


def test_the_default_command_is_prowler(tmp_path):
    popen = FakePopen()

    run(tmp_path, popen, prowler_python="", prowler_command='["prowler"]')

    assert popen.argv[:2] == ["prowler", "aws"]


@pytest.mark.parametrize("command", ["not json", '"prowler"', "[]", "[1]", '[""]'])
def test_a_command_that_is_not_a_list_of_words_is_refused(tmp_path, command):
    popen = FakePopen()

    with pytest.raises(ExtendedError) as caught:
        run(tmp_path, popen, prowler_python="", prowler_command=command)

    assert caught.value.status == "unavailable"
    assert popen.calls == []


@pytest.mark.parametrize("region", ["us east", "US-EAST-1", "a;b", "--help", "x&&y", "a$(b)", ""])
def test_a_region_that_is_not_plain_is_refused_and_nothing_is_started(tmp_path, region):
    popen = FakePopen()

    with pytest.raises(ExtendedError) as caught:
        run(tmp_path, popen, regions=[region])

    assert caught.value.status == "failed"
    assert popen.calls == []


@pytest.mark.parametrize("services", ["s3;rm", "S3", "s3 && ec2", "../iam", "s3 $(x)"])
def test_a_service_that_is_not_plain_is_refused_and_nothing_is_started(tmp_path, services):
    popen = FakePopen()

    with pytest.raises(ExtendedError):
        run(tmp_path, popen, prowler_services=services)

    assert popen.calls == []


def test_no_regions_or_no_services_is_refused(tmp_path):
    with pytest.raises(ExtendedError, match="No region"):
        run(tmp_path, regions=[])
    with pytest.raises(ExtendedError, match="SERVICES"):
        run(tmp_path, prowler_services="  ")


def test_the_child_gets_only_the_allowed_variables(tmp_path):
    popen = FakePopen()
    environ = {
        "PATH": "/bin",
        "AWS_PROFILE": "scanner",
        "AWS_REGION": "ap-southeast-2",
        "GEMINI_API_KEY": "fake-gemini-secret",
        "DATABASE_URL": "sqlite:///x.db",
        "AWS_SECRET_ACCESS_KEY": "fake-aws-secret",
        "AWS_SESSION_TOKEN": "fake-token",
        "SOMETHING_SECRET": "fake-secret",
    }

    run_prowler(
        settings_for(tmp_path),
        REGIONS,
        popen=popen,
        kill=Killer(),
        environ=environ,
        poll_seconds=0.01,
    )

    env = popen.calls[0]["env"]
    assert env == {
        "PATH": "/bin",
        "AWS_PROFILE": "scanner",
        "AWS_REGION": "ap-southeast-2",
        "PYTHONIOENCODING": "utf-8",
    }
    assert "fake-gemini-secret" not in str(popen.calls)
    assert "fake-aws-secret" not in str(popen.calls)


def test_the_allowed_variables_are_exactly_the_agreed_list():
    assert set(ALLOWED_ENV) == {
        "PATH",
        "SYSTEMROOT",
        "SYSTEMDRIVE",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "HOME",
        "HOMEDRIVE",
        "HOMEPATH",
        "APPDATA",
        "LOCALAPPDATA",
        "PYTHONIOENCODING",
        "AWS_PROFILE",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "AWS_SHARED_CREDENTIALS_FILE",
        "AWS_CONFIG_FILE",
    }
    only = child_environment({"GEMINI_API_KEY": "x", "TEMP": "t"})
    assert only == {"TEMP": "t", "PYTHONIOENCODING": "utf-8"}


def test_the_child_always_writes_utf_8_so_the_progress_bar_cannot_crash_it():
    assert child_environment({"PYTHONIOENCODING": "cp1252"})["PYTHONIOENCODING"] == "utf-8"
    assert child_environment({})["PYTHONIOENCODING"] == "utf-8"


def test_the_real_environment_is_filtered_when_none_is_given(tmp_path, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "fake-gemini-secret")
    monkeypatch.setenv("AWS_PROFILE", "scanner")
    popen = FakePopen()

    run(tmp_path, popen)

    assert "GEMINI_API_KEY" not in popen.calls[0]["env"]
    assert popen.calls[0]["env"]["AWS_PROFILE"] == "scanner"


def test_failed_checks_exit_code_3_is_not_a_failure(tmp_path):
    popen = FakePopen(FakeProcess(code=3))

    assert run(tmp_path, popen).file_name.endswith(".ocsf.json")


def test_a_non_zero_exit_gives_the_redacted_tail_of_the_output(tmp_path):
    err = b"starting\nerror for account 123456789012 with key AKIAABCDEFGHIJKLMNOP\nboom"
    popen = FakePopen(FakeProcess(code=1, err=err))

    with pytest.raises(ExtendedError) as caught:
        run(tmp_path, popen)

    error = caught.value
    assert error.status == "failed"
    assert "exit code 1" in error.message
    assert "boom" in error.message
    assert "123456789012" not in error.message
    assert "AKIAABCDEFGHIJKLMNOP" not in error.message


def test_huge_output_is_cut_to_a_short_tail(tmp_path):
    err = b"x" * 5_000_000 + b"THE-END"
    popen = FakePopen(FakeProcess(code=2, err=err, out=b"y" * 3_000_000))

    with pytest.raises(ExtendedError) as caught:
        run(tmp_path, popen)

    assert len(caught.value.message) < 1000
    assert "THE-END" in caught.value.message


def test_access_denied_output_gives_the_permissions_hint(tmp_path):
    popen = FakePopen(FakeProcess(code=1, err=b"An error occurred (AccessDenied) when calling X"))

    with pytest.raises(ExtendedError) as caught:
        run(tmp_path, popen)

    assert "SecurityAudit" in caught.value.hint
    assert "ViewOnlyAccess" in caught.value.hint


def test_a_successful_run_that_saw_permission_errors_says_so(tmp_path):
    popen = FakePopen(FakeProcess(code=0, err=b"UnauthorizedOperation for ec2"))

    assert run(tmp_path, popen).saw_permission_errors is True


def test_a_python_without_prowler_is_reported_as_unavailable(tmp_path):
    popen = FakePopen(FakeProcess(code=1, err=b"No module named prowler"))

    with pytest.raises(ExtendedError) as caught:
        run(tmp_path, popen)

    assert caught.value.status == "unavailable"
    assert "PROWLER_PYTHON" in caught.value.message


def test_a_run_that_takes_too_long_is_stopped_with_everything_it_started(tmp_path):
    process = FakeProcess(hang=True)
    killer = Killer()

    with pytest.raises(ExtendedError) as caught:
        run(tmp_path, FakePopen(process), kill=killer, timeout=0.05)

    assert killer.killed == [process]
    assert "did not finish within" in caught.value.message
    assert run_dirs(tmp_path) == []


def test_a_cancelled_run_is_stopped(tmp_path):
    process = FakeProcess(hang=True)
    killer = Killer()
    cancel = threading.Event()
    cancel.set()

    with pytest.raises(ExtendedError, match="cancelled"):
        run_prowler(
            settings_for(tmp_path),
            REGIONS,
            popen=FakePopen(process),
            kill=killer,
            cancel=cancel,
            poll_seconds=0.01,
        )

    assert killer.killed == [process]


def test_the_child_is_started_in_its_own_process_group(tmp_path):
    popen = FakePopen()

    run(tmp_path, popen)

    call = popen.calls[0]
    assert call.get("creationflags") == getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", None) or (
        call.get("start_new_session") is True
    )


def test_a_missing_program_is_unavailable_with_a_hint(tmp_path):
    popen = FakePopen(error=FileNotFoundError(2, "No such file"))

    with pytest.raises(ExtendedError) as caught:
        run(tmp_path, popen)

    assert caught.value.status == "unavailable"
    assert "not found" in caught.value.message
    assert "PROWLER_PYTHON" in caught.value.hint
    assert "Docker" in caught.value.hint


def test_a_program_blocked_by_a_windows_policy_is_unavailable(tmp_path):
    blocked = OSError(1, "An Application Control policy has blocked this file")
    blocked.winerror = 4551
    popen = FakePopen(error=blocked)

    with pytest.raises(ExtendedError) as caught:
        run(tmp_path, popen)

    assert caught.value.status == "unavailable"
    assert "security policy" in caught.value.message
    assert caught.value.hint == BLOCKED_HINT
    assert caught.value.blocked is True


def test_a_permission_error_is_reported_as_blocked(tmp_path):
    popen = FakePopen(error=PermissionError(13, "Access is denied"))

    with pytest.raises(ExtendedError) as caught:
        run(tmp_path, popen)

    assert caught.value.status == "unavailable"
    assert "security policy" in caught.value.message


def test_no_results_file_is_a_clear_error(tmp_path):
    with pytest.raises(ExtendedError, match="no results file"):
        run(tmp_path, FakePopen(files={}))


def test_several_results_files_are_a_clear_error(tmp_path):
    files = {"a.ocsf.json": b"[]", "b.ocsf.json": b"[]"}

    with pytest.raises(ExtendedError, match="more than one"):
        run(tmp_path, FakePopen(files=files))


def test_other_files_in_the_folder_are_ignored(tmp_path):
    files = {"x.ocsf.json": results_file(), "x.csv": b"a,b", "x.html": b"<html>"}

    assert run(tmp_path, FakePopen(files=files)).file_name == "x.ocsf.json"


def test_the_run_folder_is_removed_after_success_and_after_failure(tmp_path):
    run(tmp_path, FakePopen())
    assert run_dirs(tmp_path) == []

    with pytest.raises(ExtendedError):
        run(tmp_path, FakePopen(FakeProcess(code=1)))
    assert run_dirs(tmp_path) == []

    with pytest.raises(ExtendedError):
        run(tmp_path, FakePopen(files={}))
    assert run_dirs(tmp_path) == []


def test_the_run_folder_is_kept_only_when_asked(tmp_path):
    run(tmp_path, FakePopen(), keep_raw_output=True)

    kept = run_dirs(tmp_path)
    assert len(kept) == 1
    assert [f.name for f in kept[0].iterdir()] == ["prowler-output-1.ocsf.json"]


def test_a_second_run_at_the_same_time_is_refused(tmp_path):
    popen = FakePopen()
    assert runner.RUN_LOCK.acquire(blocking=False)
    try:
        with pytest.raises(ExtendedError, match="already running"):
            run(tmp_path, popen)
    finally:
        runner.RUN_LOCK.release()

    assert popen.calls == []
    run(tmp_path, popen)


def test_nothing_secret_reaches_the_log(tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    err = b"key AKIAABCDEFGHIJKLMNOP account 123456789012"

    with pytest.raises(ExtendedError):
        run(tmp_path, FakePopen(FakeProcess(code=1, err=err)))

    assert "AKIAABCDEFGHIJKLMNOP" not in caplog.text
    assert "123456789012" not in caplog.text


def test_build_argv_is_the_same_list_the_runner_uses(tmp_path):
    argv = build_argv(settings_for(tmp_path), REGIONS, tmp_path)

    assert argv[:3] == [PYTHON, "-m", "prowler"]
    assert argv[-2:] == ["-b", "-z"]


# check-runner


class Done:
    def __init__(self, code=0, out=b"", err=b""):
        self.returncode = code
        self.stdout = out
        self.stderr = err


def asking(done=None, error=None):
    calls = []

    def run_version(argv, **kwargs):
        calls.append((argv, kwargs))
        if error is not None:
            raise error
        return done

    run_version.calls = calls
    return run_version


def test_check_runner_reports_the_version_and_starts_no_scan(tmp_path):
    ask = asking(Done(out=b"Prowler 5.44.0\n"))

    status = check_runner(settings_for(tmp_path), ask)

    assert status == RunnerStatus(True, "Prowler 5.44.0", None, None)
    argv, kwargs = ask.calls[0]
    assert argv == [PYTHON, "-m", "prowler", "--version"]
    assert "aws" not in argv
    assert kwargs["timeout"] == 60
    assert "GEMINI_API_KEY" not in kwargs["env"]


@pytest.mark.parametrize(
    ("error", "words"),
    [
        (FileNotFoundError(2, "x"), "not found"),
        (PermissionError(13, "x"), "security policy"),
        (subprocess.TimeoutExpired("prowler", 60), "did not answer"),
    ],
)
def test_check_runner_says_exactly_why_it_cannot_run(tmp_path, error, words):
    status = check_runner(settings_for(tmp_path), asking(error=error))

    assert status.available is False
    assert words in status.reason
    assert status.hint


def test_check_runner_reports_a_python_without_prowler(tmp_path):
    ask = asking(Done(code=1, err=b"No module named prowler"))

    status = check_runner(settings_for(tmp_path), ask)

    assert status.available is False
    assert "PROWLER_PYTHON" in status.reason


def test_check_runner_reports_a_bad_command_setting(tmp_path):
    settings = settings_for(tmp_path, prowler_python="", prowler_command="nope")

    status = check_runner(settings, asking())

    assert status.available is False
    assert "PROWLER_COMMAND" in status.reason


# status cache


def test_the_status_is_asked_once_a_minute():
    now = [0.0]
    asked = []

    def ask() -> RunnerStatus:
        asked.append(now[0])
        return RunnerStatus(True, f"v{len(asked)}", None, None)

    cache = StatusCache(ask, 60, clock=lambda: now[0])

    assert cache.get().version == "v1"
    now[0] = 59
    assert cache.get().version == "v1"
    now[0] = 61
    assert cache.get().version == "v2"
    assert asked == [0.0, 61]


BLOCKED_OUTPUT = (
    b"ImportError: DLL load failed while importing rpds: An Application Control "
    b"policy has blocked this file."
)


def test_a_library_blocked_while_prowler_loads_is_reported_as_blocked(tmp_path):
    popen = FakePopen(FakeProcess(code=1, err=BLOCKED_OUTPUT))

    with pytest.raises(ExtendedError) as caught:
        run(tmp_path, popen)

    assert caught.value.status == "unavailable"
    assert caught.value.blocked is True
    assert caught.value.hint == BLOCKED_HINT
    assert "exit code" not in caught.value.message


def test_check_runner_reports_a_blocked_library_with_the_blocked_hint(tmp_path):
    status = check_runner(settings_for(tmp_path), asking(Done(code=1, err=BLOCKED_OUTPUT)))

    assert status.available is False
    assert status.blocked is True
    assert status.hint == (
        "This computer blocks Prowler. Run it elsewhere, for example in AWS CloudShell, "
        "then import the file here."
    )


def test_check_runner_does_not_call_other_failures_blocked(tmp_path):
    status = check_runner(settings_for(tmp_path), asking(error=FileNotFoundError(2, "x")))

    assert status.blocked is False


def test_the_cloudshell_command_uses_the_same_flags_as_a_run(tmp_path):
    settings = settings_for(tmp_path, prowler_services="s3 iam")

    command = cloudshell_command(settings, ["ap-southeast-2", "us-east-1"])

    assert command == (
        "prowler aws -f ap-southeast-2 us-east-1 --services s3 iam "
        "-M json-ocsf -o prowler-out -b -z"
    )


def test_the_cloudshell_command_refuses_a_name_that_could_be_an_option(tmp_path):
    with pytest.raises(ExtendedError):
        cloudshell_command(settings_for(tmp_path), ["--evil"])
