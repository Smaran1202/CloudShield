import io
import subprocess
from pathlib import Path

from prowler_data import entry, to_bytes

from cloudshield.config import Settings

# A stand-in for the Prowler program. No real program is started and nothing touches a network.


def results_file() -> bytes:
    return to_bytes([entry(), entry(check="c2", status="PASS"), entry(check="c3", uid=None)])


def settings_for(tmp_path, **overrides) -> Settings:
    values = {
        "prowler_python": "C:/tools/venv/Scripts/python.exe",
        "cloudshield_data_dir": str(tmp_path / "data"),
        "prowler_timeout_seconds": 5,
    }
    return Settings(**{**values, **overrides})


class FakeProcess:
    def __init__(self, code=0, out=b"", err=b"", hang=False, pid=4242):
        self.stdout = io.BytesIO(out)
        self.stderr = io.BytesIO(err)
        self.code = code
        self.hang = hang
        self.pid = pid

    def wait(self, timeout=None):
        if self.hang:
            raise subprocess.TimeoutExpired("prowler", timeout)
        return self.code


class FakePopen:
    """Records how it was called. `files` are written into the run directory, like Prowler."""

    def __init__(self, process=None, files=None, error=None):
        self.process = process or FakeProcess()
        self.files = {"prowler-output-1.ocsf.json": results_file()} if files is None else files
        self.error = error
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append({"argv": argv, **kwargs})
        if self.error is not None:
            raise self.error
        for name, content in self.files.items():
            Path(kwargs["cwd"], name).write_bytes(content)
        return self.process

    @property
    def argv(self):
        return self.calls[0]["argv"]


class Killer:
    def __init__(self):
        self.killed = []

    def __call__(self, process):
        self.killed.append(process)
