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
from dataclasses import dataclass
from pathlib import Path

from cloudshield.config import Settings
from cloudshield.fixes.explain import redact

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
# A name never starts with "-", so it can never be read as another option.
NAME = re.compile(r"^[a-z0-9][a-z0-9-]*$")
TAIL_BYTES = 8000
MESSAGE_CHARS = 600
POLL_SECONDS = 0.5
VERSION_TIMEOUT_SECONDS = 60
# Windows error 4551: an application control policy blocked the file.
BLOCKED_WINERROR = 4551
BLOCKED_WORDS = re.compile(r"Application Control policy", re.IGNORECASE)
PERMISSION_WORDS = re.compile(
    r"AccessDenied|UnauthorizedOperation|AuthFailure|not authorized|AccessDeniedException",
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
INSTALL_COMMAND = "pip install prowler"
# The folder, inside AWS CloudShell, that the results are written to.
CLOUDSHELL_OUTPUT_DIR = "prowler-out"
PERMISSION_HINT = (
    "Prowler reported errors, probably missing read permissions; attach SecurityAudit and "
    "ViewOnlyAccess to the scanner user."
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


@dataclass(frozen=True)
class RunnerStatus:
    available: bool
    version: str | None
    reason: str | None
    hint: str | None
    blocked: bool = False


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


def prowler_arguments(services: list[str], regions: list[str], output_dir: str) -> list[str]:
    """The part of the command after the program that starts Prowler."""
    return [
        "aws",
        "-f",
        *regions,
        "--services",
        *services,
        "-M",
        "json-ocsf",
        "-o",
        output_dir,
        "-b",
        "-z",
    ]


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


def describe_start_failure(exc: OSError) -> ExtendedError:
    if isinstance(exc, FileNotFoundError):
        return ExtendedError("unavailable", "Prowler was not found.", INSTALL_HINT)
    if isinstance(exc, PermissionError) or getattr(exc, "winerror", None) == BLOCKED_WINERROR:
        return ExtendedError(
            "unavailable",
            "This computer's security policy blocked Prowler from starting.",
            BLOCKED_HINT,
            blocked=True,
        )
    message = f"Prowler could not be started: {exc.strerror or exc}."
    return ExtendedError("failed", message, INSTALL_HINT)


def failure_for(code: int, tail: str) -> ExtendedError:
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
    hint = PERMISSION_HINT if PERMISSION_WORDS.search(tail) else "See docs/extended-checks.md."
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
    return files[0]


def run_prowler(
    settings: Settings,
    regions: list[str],
    popen: Callable = subprocess.Popen,
    kill: Callable = kill_tree,
    cancel: threading.Event | None = None,
    environ: Mapping[str, str] | None = None,
    poll_seconds: float = POLL_SECONDS,
) -> RunOutput:
    """Runs the extended checks and returns the results file. Raises ExtendedError otherwise."""
    if not RUN_LOCK.acquire(blocking=False):
        raise ExtendedError(
            "failed", "Extended checks are already running.", "Wait for them to end."
        )
    run_dir = Path(settings.cloudshield_data_dir) / "runs" / uuid.uuid4().hex
    try:
        run_dir.mkdir(parents=True)
        argv = build_argv(settings, regions, run_dir.resolve())
        return run_in(settings, regions, argv, run_dir, popen, kill, cancel, environ, poll_seconds)
    finally:
        RUN_LOCK.release()
        if not settings.keep_raw_output:
            shutil.rmtree(run_dir, ignore_errors=True)


def run_in(
    settings: Settings,
    regions: list[str],
    argv: list[str],
    run_dir: Path,
    popen: Callable,
    kill: Callable,
    cancel: threading.Event | None,
    environ: Mapping[str, str] | None,
    poll_seconds: float,
) -> RunOutput:
    started = time.monotonic()
    try:
        process = popen(
            argv,
            cwd=run_dir,
            env=child_environment(os.environ if environ is None else environ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            **start_options(),
        )
    except OSError as exc:
        raise describe_start_failure(exc) from exc
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
    )


def check_runner(settings: Settings, run: Callable = subprocess.run) -> RunnerStatus:
    """Asks Prowler for its version. It starts no scan."""
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
