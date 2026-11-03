import json
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path

import boto3
from botocore.exceptions import BotoCoreError

from cloudshield.config import Settings
from cloudshield.fixes.explain import redact
from cloudshield.imports.parser import MAX_BYTES

logger = logging.getLogger(__name__)

# Only these variables reach Prowler. Everything else, such as GEMINI_API_KEY, stays behind.
ALLOWED_ENV = (
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
)
# What the docker client needs to find the engine and its own settings (Docker's documented
# environment variables). The AWS credentials are added on top of these, and nothing else.
DOCKER_ENV = (
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
)
# The folder the Prowler image writes to (its working directory is /home/prowler).
CONTAINER_OUTPUT_DIR = "/home/prowler/output"
DOCKER_CHECK_SECONDS = 10
DOCKER_STOP_SECONDS = 10
# A name never starts with "-", so it can never be read as another option.
NAME = re.compile(r"^[a-z0-9][a-z0-9-]*$")
IMAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]*$")
DOCKER_DOWN_WORDS = re.compile(
    r"Cannot connect to the Docker daemon|error during connect|failed to connect to the docker API",
    re.IGNORECASE,
)
TAIL_BYTES = 8000
MESSAGE_CHARS = 600
POLL_SECONDS = 0.5
VERSION_TIMEOUT_SECONDS = 60
# Windows error 4551: an application control policy blocked the file.
BLOCKED_WINERROR = 4551
BLOCKED_WORDS = re.compile(r"Application Control policy", re.IGNORECASE)
EXPIRED_WORDS = re.compile(r"ExpiredToken(?:Exception)?", re.IGNORECASE)
PERMISSION_WORDS = re.compile(
    r"AccessDenied|UnauthorizedOperation|AuthFailure|not authorized|AccessDeniedException"
    r"|ExpiredToken(?:Exception)?",
    re.IGNORECASE,
)

INSTALL_HINT = (
    "Install Prowler in a virtual environment and set PROWLER_PYTHON to that Python, or use "
    "Docker or WSL. See docs/extended-checks.md."
)
BLOCKED_HINT = (
    "This computer blocks Prowler. Run it elsewhere, for example in AWS CloudShell, "
    "then import the file here."
)
DOCKER_MISSING_HINT = (
    "Set DOCKER_COMMAND to the full path of docker, for example "
    "C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe, or start the server from a "
    "terminal where the docker command works."
)
DOCKER_DOWN_HINT = "Start Docker Desktop, wait until it says the engine is running, then try again."
DOCKER_IMAGE_HINT = "The first run downloads the image and may take several minutes."
ONEDRIVE_WARNING = (
    "The data folder is inside OneDrive, and Docker may fail to mount it. Set "
    "CLOUDSHIELD_DATA_DIR to a folder outside OneDrive, for example "
    "C:\\Users\\<name>\\cloudshield-data."
)
INSTALL_COMMAND = "pip install prowler"
# The folder, inside AWS CloudShell, that the results are written to.
CLOUDSHELL_OUTPUT_DIR = "prowler-out"
PERMISSION_HINT = (
    "Prowler reported errors, probably missing read permissions; attach SecurityAudit and "
    "ViewOnlyAccess to the scanner user."
)
EXPIRED_HINT = (
    "The AWS credentials expired during the run. Sign in to AWS again and rerun the extended "
    "checks."
)

# Only one extended run at a time.
RUN_LOCK = threading.Lock()


class ExtendedError(Exception):
    """The extended checks could not run or did not finish. `status` is failed or unavailable."""

    def __init__(self, status: str, message: str, hint: str, blocked: bool = False):
        super().__init__(message)
        self.status = status
        self.message = message
        self.hint = hint
        # True when an operating-system policy stops Prowler from running on this computer.
        self.blocked = blocked


@dataclass(frozen=True)
class RunOutput:
    file_name: str
    content: bytes
    duration_seconds: float
    services: list[str]
    regions: list[str]
    saw_permission_errors: bool
    saw_expired_credentials: bool = False
    mode: str = "local"
    image: str | None = None


@dataclass(frozen=True)
class RunnerStatus:
    available: bool
    version: str | None
    reason: str | None
    hint: str | None
    blocked: bool = False
    warning: str | None = None


def base_command(settings: Settings) -> list[str]:
    """The program that starts Prowler: a Python with the prowler module, or a command."""
    if settings.prowler_python.strip():
        return [settings.prowler_python.strip(), "-m", "prowler"]
    problem = ExtendedError(
        "unavailable", "PROWLER_COMMAND is not a JSON list.", 'Write it like ["prowler"].'
    )
    try:
        command = json.loads(settings.prowler_command or '["prowler"]')
    except json.JSONDecodeError as exc:
        raise problem from exc
    valid = isinstance(command, list) and command
    if not valid or not all(isinstance(part, str) and part for part in command):
        raise problem
    return command


def checked_names(values: list[str], what: str) -> list[str]:
    for value in values:
        if not NAME.fullmatch(value):
            raise ExtendedError("failed", f"A {what} name is not valid.", "Use only a-z, 0-9, -.")
    return values


def prowler_arguments(
    services: list[str], regions: list[str], output_dir: str | None
) -> list[str]:
    """The part of the command after the program that starts Prowler. The container has no -o:
    it writes to its own output folder, which is the mounted one."""
    output = ["-o", output_dir] if output_dir else []
    return ["aws", "-f", *regions, "--services", *services, "-M", "json-ocsf", *output, "-b", "-z"]


def checked_settings(settings: Settings, regions: list[str]) -> list[str]:
    """The services to check, after the services and regions have been validated."""
    services = checked_names(settings.prowler_services.split(), "service")
    if not services:
        raise ExtendedError(
            "failed", "PROWLER_SERVICES is empty.", "Set it to, for example, s3 ec2 iam."
        )
    if not regions:
        raise ExtendedError("failed", "No region was given.", "Set AWS_REGION or send regions.")
    checked_names(regions, "region")
    return services


def build_argv(settings: Settings, regions: list[str], run_dir: Path) -> list[str]:
    """The whole command as a list. It is never joined into a shell string."""
    services = checked_settings(settings, regions)
    return [*base_command(settings), *prowler_arguments(services, regions, str(run_dir))]


def docker_program(settings: Settings) -> str:
    return settings.docker_command.strip() or "docker"


def checked_image(settings: Settings) -> str:
    # The image is a positional argument; a leading "-" would be read as a docker option.
    if not IMAGE.fullmatch(settings.prowler_docker_image):
        raise ExtendedError(
            "failed",
            "PROWLER_DOCKER_IMAGE is not a valid image name.",
            "Use for example toniblyx/prowler:latest.",
        )
    return settings.prowler_docker_image


def build_docker_argv(
    settings: Settings, regions: list[str], run_dir: Path, container: str
) -> list[str]:
    """The docker command as a list. The credential values are not in it: `-e NAME` makes docker
    read them from its own environment."""
    services = checked_settings(settings, regions)
    return [
        docker_program(settings),
        "run",
        "--rm",
        "--name",
        container,
        "-v",
        f"{run_dir}:{CONTAINER_OUTPUT_DIR}",
        "-e",
        "AWS_ACCESS_KEY_ID",
        "-e",
        "AWS_SECRET_ACCESS_KEY",
        "-e",
        "AWS_SESSION_TOKEN",
        checked_image(settings),
        *prowler_arguments(services, regions, None),
    ]


def profile_credentials() -> dict[str, str]:
    """The credentials of the profile the server uses (the standard boto3 chain)."""
    try:
        credentials = boto3.Session().get_credentials()
        frozen = credentials.get_frozen_credentials() if credentials else None
    except BotoCoreError as exc:
        raise ExtendedError(
            "failed",
            f"The AWS credentials could not be read ({type(exc).__name__}).",
            "Check AWS_PROFILE on the server, and sign in again if it uses single sign-on.",
        ) from exc
    if frozen is None:
        raise ExtendedError(
            "unavailable", "No AWS credentials were found.", "Set AWS_PROFILE on the server."
        )
    values = {"AWS_ACCESS_KEY_ID": frozen.access_key, "AWS_SECRET_ACCESS_KEY": frozen.secret_key}
    if frozen.token:
        values["AWS_SESSION_TOKEN"] = frozen.token
    return values


def docker_environment(
    environ: Mapping[str, str], credentials: Mapping[str, str] | None = None
) -> dict[str, str]:
    env = {name: environ[name] for name in DOCKER_ENV if name in environ}
    return {**env, **(credentials or {})}


def stop_container(
    settings: Settings, name: str, environ: Mapping[str, str], run: Callable = subprocess.run
) -> None:
    """Stops and removes the container by name. Stopping the client does not stop it."""
    env = docker_environment(environ)
    for args in (["kill", name], ["rm", "-f", name]):
        try:
            run(
                [docker_program(settings), *args],
                env=env,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=DOCKER_STOP_SECONDS,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            logger.warning("Could not run docker %s for container %s", args[0], name)


def cloudshell_command(settings: Settings, regions: list[str]) -> str:
    """The same command as a line to paste into AWS CloudShell, where Prowler is on the path."""
    services = checked_settings(settings, regions)
    return " ".join(["prowler", *prowler_arguments(services, regions, CLOUDSHELL_OUTPUT_DIR)])


def child_environment(environ: Mapping[str, str]) -> dict[str, str]:
    env = {name: environ[name] for name in ALLOWED_ENV if name in environ}
    # Prowler's progress bar prints characters that the Windows code page (cp1252) cannot
    # encode, which crashes it when its output goes to a pipe. UTF-8 avoids that.
    env["PYTHONIOENCODING"] = "utf-8"
    return env


class Tail:
    """Reads a stream in a thread and keeps only the last few thousand bytes of it."""

    def __init__(self, stream):
        self.data = b""
        self.thread = threading.Thread(target=self.read, args=(stream,), daemon=True)
        self.thread.start()

    def read(self, stream) -> None:
        while chunk := stream.read(4096):
            self.data = (self.data + chunk)[-TAIL_BYTES:]

    def text(self) -> str:
        self.thread.join(timeout=5)
        return redact(self.data.decode("utf-8", errors="replace")).strip()


def kill_tree(process) -> None:
    """Stops Prowler and everything it started."""
    if sys.platform == "win32":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            capture_output=True,
            check=False,
        )
    else:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass  # it has already ended


def start_options() -> dict:
    # The child gets its own process group, so the whole tree can be stopped together.
    if sys.platform == "win32":
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def describe_start_failure(exc: OSError, docker: bool = False) -> ExtendedError:
    program = "Docker" if docker else "Prowler"
    if isinstance(exc, FileNotFoundError):
        hint = DOCKER_MISSING_HINT if docker else INSTALL_HINT
        return ExtendedError("unavailable", f"{program} was not found.", hint)
    if isinstance(exc, PermissionError) or getattr(exc, "winerror", None) == BLOCKED_WINERROR:
        return ExtendedError(
            "unavailable",
            f"This computer's security policy blocked {program} from starting.",
            BLOCKED_HINT,
            blocked=True,
        )
    message = f"{program} could not be started: {exc.strerror or exc}."
    return ExtendedError("failed", message, DOCKER_MISSING_HINT if docker else INSTALL_HINT)


def failure_for(code: int, tail: str) -> ExtendedError:
    if DOCKER_DOWN_WORDS.search(tail):
        return ExtendedError(
            "unavailable", "Docker is installed but its engine is not running.", DOCKER_DOWN_HINT
        )
    if BLOCKED_WORDS.search(tail):
        # Prowler started, but one of its libraries was blocked while it was loading.
        return ExtendedError(
            "unavailable",
            "This computer's security policy blocked a file that Prowler needs.",
            BLOCKED_HINT,
            blocked=True,
        )
    if "No module named prowler" in tail:
        return ExtendedError(
            "unavailable",
            "The Python in PROWLER_PYTHON does not have Prowler installed.",
            INSTALL_HINT,
        )
    shown = tail[-MESSAGE_CHARS:]
    hint = "See docs/extended-checks.md."
    if EXPIRED_WORDS.search(tail):
        hint = EXPIRED_HINT
    elif PERMISSION_WORDS.search(tail):
        hint = PERMISSION_HINT
    message = f"Prowler stopped with exit code {code}. Last output: {shown}"
    return ExtendedError("failed", message, hint)


def find_output(run_dir: Path) -> Path:
    files = sorted(run_dir.rglob("*.ocsf.json"))
    if not files:
        raise ExtendedError(
            "failed",
            "Prowler finished but wrote no results file.",
            "Check the services and regions in the settings. See docs/extended-checks.md.",
        )
    if len(files) > 1:
        raise ExtendedError(
            "failed",
            "Prowler wrote more than one results file, so CloudShield cannot tell which to use.",
            "Delete the run folders under CLOUDSHIELD_DATA_DIR/runs and try again.",
        )
    # The size is checked before reading, so a huge file is never loaded.
    if files[0].stat().st_size > MAX_BYTES:
        raise ExtendedError(
            "failed",
            "Prowler wrote a results file over 50 MB, which is too large to import.",
            "Run fewer services or regions. See docs/extended-checks.md.",
        )
    return files[0]


def run_prowler(
    settings: Settings,
    regions: list[str],
    popen: Callable = subprocess.Popen,
    kill: Callable = kill_tree,
    cancel: threading.Event | None = None,
    environ: Mapping[str, str] | None = None,
    poll_seconds: float = POLL_SECONDS,
    run: Callable = subprocess.run,
    credentials: Callable[[], dict[str, str]] = profile_credentials,
) -> RunOutput:
    """Runs the extended checks and returns the results file. Raises ExtendedError otherwise.

    In docker mode `run` is used to stop the container, and `credentials` gives the AWS
    credentials that go into the docker client's environment."""
    if not RUN_LOCK.acquire(blocking=False):
        raise ExtendedError(
            "failed", "Extended checks are already running.", "Wait for them to end."
        )
    run_dir = Path(settings.cloudshield_data_dir) / "runs" / uuid.uuid4().hex
    environ = os.environ if environ is None else environ
    container = None
    try:
        run_dir.mkdir(parents=True)
        stop = kill
        if settings.prowler_mode == "docker":
            name = f"cloudshield-{uuid.uuid4().hex}"
            argv = build_docker_argv(settings, regions, run_dir.resolve(), name)
            env = docker_environment(environ, credentials())
            container = name

            def kill_both(process) -> None:
                kill(process)
                stop_container(settings, name, environ, run)

            stop = kill_both
        else:
            argv = build_argv(settings, regions, run_dir.resolve())
            env = child_environment(environ)
        return run_in(settings, regions, argv, env, run_dir, popen, stop, cancel, poll_seconds)
    finally:
        # Also when nothing went wrong, in case the client ended but the container did not.
        if container:
            stop_container(settings, container, environ, run)
        RUN_LOCK.release()
        if not settings.keep_raw_output:
            shutil.rmtree(run_dir, ignore_errors=True)


def run_in(
    settings: Settings,
    regions: list[str],
    argv: list[str],
    env: dict[str, str],
    run_dir: Path,
    popen: Callable,
    kill: Callable,
    cancel: threading.Event | None,
    poll_seconds: float,
) -> RunOutput:
    started = time.monotonic()
    docker = settings.prowler_mode == "docker"
    try:
        process = popen(
            argv,
            cwd=run_dir,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            **start_options(),
        )
    except OSError as exc:
        raise describe_start_failure(exc, docker) from exc
    out, err = Tail(process.stdout), Tail(process.stderr)
    logger.info("Extended checks started for %d region(s)", len(regions))

    while True:
        try:
            code = process.wait(timeout=poll_seconds)
            break
        except subprocess.TimeoutExpired:
            if cancel is not None and cancel.is_set():
                kill(process)
                raise ExtendedError("failed", "The extended checks were cancelled.", "") from None
            if time.monotonic() - started >= settings.prowler_timeout_seconds:
                kill(process)
                raise ExtendedError(
                    "failed",
                    f"Prowler did not finish within {settings.prowler_timeout_seconds} seconds "
                    "and was stopped.",
                    "Run fewer services or regions, or raise PROWLER_TIMEOUT_SECONDS.",
                ) from None

    tail = (out.text() + "\n" + err.text()).strip()
    if code not in (0, 3):
        raise failure_for(code, tail)
    path = find_output(run_dir)
    return RunOutput(
        file_name=path.name,
        content=path.read_bytes(),
        duration_seconds=round(time.monotonic() - started, 1),
        services=settings.prowler_services.split(),
        regions=list(regions),
        saw_permission_errors=bool(PERMISSION_WORDS.search(tail)),
        saw_expired_credentials=bool(EXPIRED_WORDS.search(tail)),
        mode=settings.prowler_mode,
        image=settings.prowler_docker_image if docker else None,
    )


def onedrive_warning(settings: Settings) -> str | None:
    parts = Path(settings.cloudshield_data_dir).resolve().parts
    return ONEDRIVE_WARNING if any("onedrive" in part.lower() for part in parts) else None


def check_docker(settings: Settings, run: Callable) -> RunnerStatus:
    """Asks docker whether its engine answers and whether the image is here. It starts no
    container and downloads nothing."""
    env = docker_environment(os.environ)

    def ask(*args: str):
        return run(
            [docker_program(settings), *args],
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=DOCKER_CHECK_SECONDS,
            check=False,
        )

    try:
        image = checked_image(settings)
        if ask("version", "--format", "{{.Server.Version}}").returncode != 0:
            return RunnerStatus(
                False, None, "Docker is installed but its engine is not running.", DOCKER_DOWN_HINT
            )
        present = ask("image", "inspect", image).returncode == 0
    except ExtendedError as exc:
        return RunnerStatus(False, None, exc.message, exc.hint)
    except subprocess.TimeoutExpired:
        reason = f"Docker did not answer within {DOCKER_CHECK_SECONDS} seconds."
        return RunnerStatus(False, None, reason, DOCKER_DOWN_HINT)
    except OSError as exc:
        error = describe_start_failure(exc, docker=True)
        return RunnerStatus(False, None, error.message, error.hint, error.blocked)
    if not present:
        reason = f"The image {image} is not downloaded yet."
        return RunnerStatus(True, f"Docker, image {image}", reason, DOCKER_IMAGE_HINT)
    return RunnerStatus(True, f"Docker, image {image}", None, None)


def check_runner(settings: Settings, run: Callable = subprocess.run) -> RunnerStatus:
    """Whether the extended checks can run here, in the configured mode. It starts no scan."""
    if settings.prowler_mode == "docker":
        return replace(check_docker(settings, run), warning=onedrive_warning(settings))
    return check_local(settings, run)


def check_local(settings: Settings, run: Callable) -> RunnerStatus:
    """Asks Prowler for its version."""
    try:
        argv = [*base_command(settings), "--version"]
        done = run(
            argv,
            env=child_environment(os.environ),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=VERSION_TIMEOUT_SECONDS,
            check=False,
        )
    except ExtendedError as exc:
        return RunnerStatus(False, None, exc.message, exc.hint, exc.blocked)
    except subprocess.TimeoutExpired:
        reason = f"Prowler did not answer within {VERSION_TIMEOUT_SECONDS} seconds."
        return RunnerStatus(False, None, reason, INSTALL_HINT)
    except OSError as exc:
        error = describe_start_failure(exc)
        return RunnerStatus(False, None, error.message, error.hint, error.blocked)

    text = redact((done.stdout + done.stderr).decode("utf-8", errors="replace")).strip()
    if done.returncode != 0:
        error = failure_for(done.returncode, text)
        return RunnerStatus(False, None, error.message, error.hint, error.blocked)
    first = next((line.strip() for line in text.splitlines() if line.strip()), "")
    return RunnerStatus(True, first[:100] or "unknown version", None, None)


class StatusCache:
    """Remembers the answer of check_runner for a minute, so the dashboard can ask often."""

    def __init__(
        self,
        check: Callable[[], RunnerStatus],
        seconds: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.check = check
        self.seconds = seconds
        self.clock = clock
        self.lock = threading.Lock()
        self.answer: RunnerStatus | None = None
        self.asked_at = 0.0

    def get(self) -> RunnerStatus:
        with self.lock:
            if self.answer is None or self.clock() - self.asked_at >= self.seconds:
                self.answer = self.check()
                self.asked_at = self.clock()
            return self.answer
