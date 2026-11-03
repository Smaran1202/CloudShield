import subprocess

# A stand-in for the docker program. No real docker is started and no container exists.


class Done:
    def __init__(self, code=0):
        self.returncode = code
        self.stdout = b""
        self.stderr = b""


class FakeDocker:
    """Records every call. `version_code` and `image_code` are the exit codes of
    `docker version` and `docker image inspect`."""

    def __init__(self, version_code=0, image_code=0, error=None):
        self.version_code = version_code
        self.image_code = image_code
        self.error = error
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append({"argv": argv, **kwargs})
        if self.error is not None:
            raise self.error
        if argv[1] == "version":
            return Done(self.version_code)
        if argv[1:3] == ["image", "inspect"]:
            return Done(self.image_code)
        return Done(0)

    def words(self) -> list[list[str]]:
        """The arguments after the program, for each call."""
        return [call["argv"][1:] for call in self.calls]


def fake_credentials(token=None):
    def read() -> dict[str, str]:
        values = {
            "AWS_ACCESS_KEY_ID": "AKIAFAKEFAKEFAKE1234",
            "AWS_SECRET_ACCESS_KEY": "fake-secret-value-for-tests",
        }
        if token:
            values["AWS_SESSION_TOKEN"] = token
        return values

    return read


def no_credentials_please():
    raise AssertionError("the credentials must not be read here")


TIMEOUT = subprocess.TimeoutExpired("docker", 10)
