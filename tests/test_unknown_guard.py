import copy
from typing import NamedTuple

import pytest
from sqlalchemy import select

from cloudshield.db import store
from cloudshield.db.models import Base, FindingRow
from cloudshield.db.session import make_engine, make_session_factory
from cloudshield.risk.scoring import score_findings
from cloudshield.rules import ALL_RULES, run_rules
from cloudshield.rules.unknown import DOCUMENT_RULES, NEEDS, missing_attribute
from cloudshield.scanner.common import make_resource

REGIONS = ["us-east-1"]
NOTE = "Not resolved: "
POLICY_ARN = "arn:aws:iam::123456789012:policy/p"
ROLE_ARN = "arn:aws:iam::123456789012:role/r"
ALL_OFF = {
    "BlockPublicAcls": False,
    "IgnorePublicAcls": False,
    "BlockPublicPolicy": False,
    "RestrictPublicBuckets": False,
}
ALL_ON = {name: True for name in ALL_OFF}
KMS = [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]
OPEN_SSH = {
    "IpProtocol": "tcp",
    "FromPort": 22,
    "ToPort": 22,
    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
    "Ipv6Ranges": [],
}
PRIVATE_SSH = {**OPEN_SSH, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}


def document(action, resource="*") -> dict:
    statement = {"Effect": "Allow", "Action": action, "Resource": resource}
    return {"Version": "2012-10-17", "Statement": [statement]}


EVERYTHING = document("*")
PASS_ROLE = document(["iam:PassRole", "ec2:RunInstances"])
BENIGN = document("ec2:DescribeInstances")
NO_STATEMENTS = {"Version": "2012-10-17", "Statement": []}


def altered(resource: dict, drop=(), **attributes) -> dict:
    changed = copy.deepcopy(resource)
    for name in drop:
        del changed["attributes"][name]
    changed["attributes"].update(attributes)
    return changed


BUCKET = make_resource(
    "b",
    "S3",
    "us-east-1",
    "b",
    {
        "public_access_block": ALL_OFF,
        "encryption": None,
        "versioning": "Disabled",
        "policy": None,
    },
)
GROUP = make_resource("sg-1", "Security Group", "us-east-1", "g", {"inbound": [OPEN_SSH]})
POLICY = make_resource(POLICY_ARN, "IAM Policy", None, "p", {"document": EVERYTHING})
ENTRY = {"name": "p", "arn": POLICY_ARN, "document": PASS_ROLE}
ROLE = make_resource(
    ROLE_ARN, "IAM Role", None, "r", {"attached_policies": [ENTRY], "inline_policies": []}
)


class Case(NamedTuple):
    name: str
    rule: str
    bad: dict  # a resource that breaks the rule
    absent: list  # (label, resource) with a key left out and no error recorded
    empty: dict  # the attribute is there, with a value that means "not configured" or "none"
    empty_still_fails: bool  # whether that value still breaks the rule
    fine: dict  # a resource that does not break the rule


CASES = [
    Case(
        "s3-public-access-block",
        "CIS-S3-001",
        BUCKET,
        [("key", altered(BUCKET, drop=["public_access_block"]))],
        altered(BUCKET, public_access_block=None),
        True,
        altered(BUCKET, public_access_block=ALL_ON),
    ),
    Case(
        "s3-encryption",
        "CIS-S3-002",
        BUCKET,
        [("key", altered(BUCKET, drop=["encryption"]))],
        altered(BUCKET, encryption=[]),
        True,
        altered(BUCKET, encryption=KMS),
    ),
    Case(
        "s3-versioning",
        "CIS-S3-003",
        BUCKET,
        [("key", altered(BUCKET, drop=["versioning"]))],
        altered(BUCKET, versioning=None),
        True,
        altered(BUCKET, versioning="Enabled"),
    ),
    Case(
        "security-group",
        "CIS-SG-001",
        GROUP,
        [("key", altered(GROUP, drop=["inbound"]))],
        altered(GROUP, inbound=[]),
        False,
        altered(GROUP, inbound=[PRIVATE_SSH]),
    ),
    Case(
        "iam-policy-wildcard",
        "CIS-IAM-001",
        POLICY,
        [("key", altered(POLICY, drop=["document"]))],
        altered(POLICY, document=NO_STATEMENTS),
        False,
        altered(POLICY, document=BENIGN),
    ),
    Case(
        "iam-policy-privesc",
        "SX-IAM-PRIVESC-001",
        POLICY,
        [("key", altered(POLICY, drop=["document"]))],
        altered(POLICY, document=NO_STATEMENTS),
        False,
        altered(POLICY, document=BENIGN),
    ),
    Case(
        "iam-role-privesc",
        "SX-IAM-PRIVESC-001",
        ROLE,
        [
            ("attached-key", altered(ROLE, drop=["attached_policies"])),
            ("inline-key", altered(ROLE, drop=["inline_policies"])),
            ("document-key", altered(ROLE, attached_policies=[{"name": "p", "arn": POLICY_ARN}])),
        ],
        altered(ROLE, attached_policies=[], inline_policies=[]),
        False,
        altered(ROLE, attached_policies=[{**ENTRY, "document": BENIGN}]),
    ),
]
ABSENT = [pytest.param(c, r, id=f"{c.name}-{label}") for c in CASES for label, r in c.absent]
BY_NAME = [pytest.param(c, id=c.name) for c in CASES]


@pytest.fixture
def session(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'test.db'}")
    Base.metadata.create_all(engine)
    with make_session_factory(engine)() as session:
        yield session


def scan(session, resource: dict) -> None:
    """A scan that read the one resource and recorded no error."""
    result = {"resources": [resource], "errors": []}
    findings = score_findings(run_rules([resource]), result, REGIONS)
    store.save_result(session, store.create_scan(session, REGIONS).id, result, findings)


def finding(session, case: Case) -> FindingRow:
    query = select(FindingRow).where(
        FindingRow.rule_id == case.rule, FindingRow.resource_id == case.bad["resource_id"]
    )
    return session.scalars(query).one()


def notes(row: FindingRow) -> list[str]:
    return [i["fact"] for i in row.evidence["items"] if i["fact"].startswith(NOTE)]


@pytest.mark.parametrize("case", BY_NAME)
def test_the_starting_scan_opens_a_finding_for_the_rule(session, case):
    scan(session, case.bad)

    row = finding(session, case)

    assert row.status == "OPEN"
    assert notes(row) == []


@pytest.mark.parametrize(("case", "resource"), ABSENT)
def test_an_absent_key_is_unknown_so_the_finding_stays_open_and_says_so(session, case, resource):
    scan(session, case.bad)

    scan(session, resource)

    row = finding(session, case)
    assert row.status == "OPEN"
    assert row.resolved_at is None
    assert row.resolution_reason is None
    [note] = [i for i in row.evidence["items"] if i["fact"].startswith(NOTE)]
    assert note["certainty"] == "unknown"
    assert "cannot tell whether this was fixed" in note["fact"]


@pytest.mark.parametrize(("case", "resource"), ABSENT)
def test_the_note_is_added_once_however_many_scans_find_the_key_absent(session, case, resource):
    scan(session, case.bad)

    scan(session, resource)
    scan(session, resource)

    assert len(notes(finding(session, case))) == 1


@pytest.mark.parametrize("case", BY_NAME)
def test_a_none_or_empty_value_is_a_reading_as_before(session, case):
    scan(session, case.bad)

    scan(session, case.empty)

    row = finding(session, case)
    assert notes(row) == []
    if case.empty_still_fails:
        assert row.status == "OPEN"
        assert row.resolution_reason is None
    else:
        assert row.status == "RESOLVED"
        assert row.resolution_reason == "no longer detected"


@pytest.mark.parametrize("case", BY_NAME)
def test_a_value_that_is_fine_resolves_the_finding_as_before(session, case):
    scan(session, case.bad)

    scan(session, case.fine)

    row = finding(session, case)
    assert row.status == "RESOLVED"
    assert row.resolution_reason == "no longer detected"
    assert notes(row) == []


@pytest.mark.parametrize(("case", "resource"), ABSENT)
def test_a_later_scan_that_reads_the_value_can_resolve_it_and_the_note_goes(
    session, case, resource
):
    scan(session, case.bad)
    scan(session, resource)

    scan(session, case.fine)

    row = finding(session, case)
    assert row.status == "RESOLVED"
    assert notes(row) == []


@pytest.mark.parametrize(("case", "resource"), ABSENT)
def test_a_later_scan_that_finds_it_again_drops_the_note(session, case, resource):
    scan(session, case.bad)
    scan(session, resource)

    scan(session, case.bad)

    row = finding(session, case)
    assert row.status == "OPEN"
    assert notes(row) == []


def test_every_own_rule_is_covered_by_the_guard():
    covered = {*NEEDS, *DOCUMENT_RULES}

    assert {rule.id for rule in ALL_RULES} == covered


def test_a_rule_the_guard_does_not_know_is_never_blocked():
    assert missing_attribute("SX-NEW-001", BUCKET) is None
