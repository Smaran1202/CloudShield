from cloudshield.rules import run_rules
from cloudshield.rules.evidence import build_evidence
from cloudshield.scanner.common import make_resource

ALL_ON = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}
AES = [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
OPEN_SSH = {
    "IpProtocol": "tcp",
    "FromPort": 22,
    "ToPort": 22,
    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
    "Ipv6Ranges": [],
}


def evidence_for(resources: list[dict], rule_id: str) -> list[dict]:
    finding = next(f for f in run_rules(resources) if f.rule_id == rule_id)
    return finding.evidence["items"]


def bucket(**attributes) -> dict:
    return make_resource("my-bucket", "S3", "us-east-1", "my-bucket", attributes)


def test_public_access_block_evidence_lists_the_four_settings_with_their_source():
    block = {**ALL_ON, "BlockPublicPolicy": False}

    items = evidence_for([bucket(public_access_block=block)], "CIS-S3-001")

    assert [i["fact"] for i in items] == list(ALL_ON)
    policy = next(i for i in items if i["fact"] == "BlockPublicPolicy")
    assert policy == {
        "fact": "BlockPublicPolicy",
        "value": False,
        "source": "attributes.public_access_block.BlockPublicPolicy",
        "certainty": "verified",
    }


def test_missing_public_access_block_evidence_is_a_single_item_with_no_value():
    items = evidence_for([bucket(public_access_block=None)], "CIS-S3-001")

    assert len(items) == 1
    assert items[0]["value"] is None
    assert items[0]["source"] == "attributes.public_access_block"


def test_encryption_evidence_shows_the_algorithm():
    items = evidence_for([bucket(encryption=AES)], "CIS-S3-002")

    assert items[0]["value"] == ["AES256"]
    assert items[0]["certainty"] == "verified"
    assert "SSEAlgorithm" in items[0]["source"]


def test_versioning_evidence_shows_the_status():
    items = evidence_for([bucket(versioning="Suspended")], "CIS-S3-003")

    assert items == [
        {
            "fact": "Versioning status",
            "value": "Suspended",
            "source": "attributes.versioning",
            "certainty": "verified",
        }
    ]


def test_security_group_evidence_shows_the_open_rule_with_port_and_cidr():
    group = make_resource(
        "sg-1", "Security Group", "ap-southeast-2", "web", {"inbound": [OPEN_SSH], "outbound": []}
    )

    items = evidence_for([group], "CIS-SG-001")

    assert items[0]["fact"] == "Inbound rule exposes SSH (port 22)"
    assert items[0]["value"] == {
        "protocol": "tcp",
        "from_port": 22,
        "to_port": 22,
        "cidrs": ["0.0.0.0/0"],
    }
    assert items[0]["source"] == "attributes.inbound"
    assert items[0]["certainty"] == "verified"


def test_wildcard_policy_evidence_points_at_the_statement():
    document = {
        "Statement": [
            {"Effect": "Allow", "Action": "s3:GetBucketLocation", "Resource": "*"},
            {"Effect": "Allow", "Action": "s3:PutObject", "Resource": "*", "Sid": "Writes"},
        ]
    }
    policy = make_resource("arn:p", "IAM Policy", None, "p", {"document": document})

    items = evidence_for([policy], "CIS-IAM-001")

    assert len(items) == 1
    assert items[0]["source"] == "attributes.document.Statement[1]"
    assert items[0]["value"]["sid"] == "Writes"
    assert items[0]["value"]["non_read_only_actions"] == ["s3:PutObject"]
    assert items[0]["certainty"] == "verified"


def test_privilege_escalation_evidence_for_a_policy_is_heuristic():
    statement = {"Effect": "Allow", "Action": "iam:CreateAccessKey", "Resource": "*"}
    document = {"Statement": [statement]}
    policy = make_resource("arn:p", "IAM Policy", None, "p", {"document": document})

    items = evidence_for([policy], "SX-IAM-PRIVESC-001")

    assert items[0]["fact"] == "Creating a new user access key"
    assert items[0]["value"]["permissions"] == ["iam:CreateAccessKey"]
    assert items[0]["source"] == "attributes.document"
    assert items[0]["certainty"] == "heuristic"


def test_privilege_escalation_evidence_for_a_role_points_at_its_policies():
    document = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    role = make_resource(
        "arn:r",
        "IAM Role",
        None,
        "r",
        {
            "attached_policies": [{"name": "p", "arn": "arn:p", "document": document}],
            "inline_policies": [],
        },
    )

    items = evidence_for([role], "SX-IAM-PRIVESC-001")

    assert "attached_policies" in items[0]["source"]
    assert items[-1]["fact"] == "Full wildcard"
    assert all(item["certainty"] == "heuristic" for item in items)


def test_every_evidence_item_has_fact_value_source_and_certainty():
    resources = [
        bucket(public_access_block=None, encryption=AES, versioning="Disabled"),
        make_resource("sg-1", "Security Group", "r", "g", {"inbound": [OPEN_SSH], "outbound": []}),
        make_resource(
            "arn:p",
            "IAM Policy",
            None,
            "p",
            {"document": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}},
        ),
    ]

    for finding in run_rules(resources):
        assert finding.evidence["items"], finding.rule_id
        for item in finding.evidence["items"]:
            assert set(item) == {"fact", "value", "source", "certainty"}
            assert item["certainty"] in ("verified", "heuristic", "unknown")


def test_unknown_rule_has_empty_evidence():
    assert build_evidence("NOT-A-RULE", {}, "S3") == {"items": []}
