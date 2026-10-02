import pytest
from botocore.client import BaseClient
from botocore.exceptions import ClientError


@pytest.fixture(autouse=True)
def safe_aws_environment(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")


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