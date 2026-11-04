from collections.abc import Iterator
from contextlib import contextmanager
from unittest.mock import patch

from botocore.client import BaseClient
from botocore.exceptions import ClientError

# Every AWS call the scanner makes: (botocore service name, operation, the response key the
# scanner reads). tests/test_experiments_e1.py checks this list against a real scan, so a call
# added to the scanner without being added here fails a test.
CALLS = [
    ("s3", "ListBuckets", "Buckets"),
    ("s3", "GetBucketLocation", "LocationConstraint"),
    ("s3", "GetPublicAccessBlock", "PublicAccessBlockConfiguration"),
    ("s3", "GetBucketEncryption", "ServerSideEncryptionConfiguration"),
    ("s3", "GetBucketVersioning", "Status"),
    ("s3", "GetBucketPolicy", "Policy"),
    ("ec2", "DescribeInstances", "Reservations"),
    ("ec2", "DescribeSecurityGroups", "SecurityGroups"),
    ("iam", "ListPolicies", "Policies"),
    ("iam", "GetPolicyVersion", "PolicyVersion"),
    ("iam", "ListEntitiesForPolicy", "PolicyUsers"),
    ("iam", "GetInstanceProfile", "InstanceProfile"),
    ("iam", "ListAttachedRolePolicies", "AttachedPolicies"),
    ("iam", "ListRolePolicies", "PolicyNames"),
    ("iam", "GetRolePolicy", "PolicyDocument"),
    ("iam", "GetPolicy", "Policy"),
    ("sts", "GetCallerIdentity", "Account"),
    ("s3control", "GetPublicAccessBlock", "PublicAccessBlockConfiguration"),
]

# The error code is our choice for each service. The scanner treats every ClientError alike.
THROTTLING_CODE = {
    "s3": "SlowDown",
    "s3control": "SlowDown",
    "ec2": "RequestLimitExceeded",
    "iam": "Throttling",
    "sts": "Throttling",
}


class Fault:
    """One fault on one call. hits counts how often it fired, so a fault that was never reached
    can be told apart from one that did nothing."""

    def __init__(self, service: str, operation: str, kind: str, key: str | None = None):
        self.service = service
        self.operation = operation
        self.kind = kind  # access_denied, throttling or missing_key
        self.key = key  # missing_key: the response key to remove
        self.hits = 0


@contextmanager
def inject(fault: Fault) -> Iterator[Fault]:
    real_call = BaseClient._make_api_call

    def fake_call(self, operation_name, params):
        service = self.meta.service_model.service_name
        if (service, operation_name) != (fault.service, fault.operation):
            return real_call(self, operation_name, params)
        fault.hits += 1
        if fault.kind == "missing_key":
            response = real_call(self, operation_name, params)
            response.pop(fault.key, None)
            return response
        code = "AccessDenied" if fault.kind == "access_denied" else THROTTLING_CODE[service]
        error = {"Code": code, "Message": f"injected {fault.kind}"}
        raise ClientError({"Error": error}, operation_name)

    with patch.object(BaseClient, "_make_api_call", fake_call):
        yield fault


@contextmanager
def recording() -> Iterator[set[tuple[str, str]]]:
    """Collects (service, operation) for every call made inside the block."""
    calls: set[tuple[str, str]] = set()
    real_call = BaseClient._make_api_call

    def spy_call(self, operation_name, params):
        calls.add((self.meta.service_model.service_name, operation_name))
        return real_call(self, operation_name, params)

    with patch.object(BaseClient, "_make_api_call", spy_call):
        yield calls
