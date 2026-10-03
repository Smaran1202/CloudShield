import socket

import pytest
from botocore.client import BaseClient
from botocore.exceptions import ClientError

LOCAL_HOSTS = ("127.0.0.1", "::1", "localhost")


@pytest.fixture(autouse=True)
def safe_aws_environment(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch):
    # Nothing from the machine's environment may reach a test. Tests that need a setting
    # set it themselves.
    names = [
        "GEMINI_API_KEY",
        "GEMINI_MODEL",
        "GEMINI_FALLBACK_MODEL",
        "AI_MAX_CALLS_PER_HOUR",
        "AWS_PROFILE",
        "AWS_REGION",
    ]
    for name in names:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def block_network(monkeypatch):
    # Only the machine itself may be reached. A test that tries anything else fails loudly.
    real_getaddrinfo = socket.getaddrinfo
    real_connect = socket.socket.connect

    def guarded_getaddrinfo(host, *args, **kwargs):
        if host not in (None, *LOCAL_HOSTS):
            raise RuntimeError(f"Network call blocked in tests: {host}")
        return real_getaddrinfo(host, *args, **kwargs)

    def guarded_connect(self, address):
        host = address[0] if isinstance(address, tuple) else address
        if host not in LOCAL_HOSTS:
            raise RuntimeError(f"Network call blocked in tests: {host}")
        return real_connect(self, address)

    monkeypatch.setattr(socket, "getaddrinfo", guarded_getaddrinfo)
    monkeypatch.setattr(socket.socket, "connect", guarded_connect)


@pytest.fixture
def deny(monkeypatch):
    def deny_operation(operation: str) -> None:
        real_call = BaseClient._make_api_call

        def fake_call(self, operation_name, params):
            if operation_name == operation:
                error = {"Code": "AccessDenied", "Message": "denied"}
                raise ClientError({"Error": error}, operation_name)
            return real_call(self, operation_name, params)

        monkeypatch.setattr(BaseClient, "_make_api_call", fake_call)

    return deny_operation
