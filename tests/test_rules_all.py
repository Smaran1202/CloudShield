import re

from cloudshield.rules import ALL_RULES, run_rules
from cloudshield.rules.rule import Hit, Rule, of_type
from cloudshield.scanner.common import make_resource

ALL_ON = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}
ALL_OFF = {name: False for name in ALL_ON}
READ_ONLY_POLICY_ARN = "arn:aws:iam::123456789012:policy/read-only"
AES = [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
WILDCARD_POLICY_ARN = "arn:aws:iam::123456789012:policy/wildcard"


def bucket(name: str, block: dict, versioning: str) -> dict:
    attributes = {
        "public_access_block": block,
        "encryption": AES,
        "versioning": versioning,
        "policy": None,
    }
    return make_resource(name, "S3", "us-east-1", name, attributes)


def scan_like_resources() -> list[dict]:
    open_ssh = {
        "IpProtocol": "tcp",
        "FromPort": 22,
        "ToPort": 22,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        "Ipv6Ranges": [],
    }
    wildcard_document = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }
    read_only_statement = {
        "Effect": "Allow",
        "Action": ["ec2:Describe*", "iam:Get*"],
        "Resource": "*",
    }
    read_only_document = {"Version": "2012-10-17", "Statement": [read_only_statement]}
    return [
        bucket("default-bucket", ALL_ON, "Disabled"),
        bucket("open-bucket", ALL_OFF, "Disabled"),
        bucket("versioned-bucket", ALL_ON, "Enabled"),
        make_resource(
            "sg-0open",
            "Security Group",
            "ap-southeast-2",
            "open-ssh",
            {"vpc_id": "vpc-1", "inbound": [open_ssh], "outbound": []},
        ),
        make_resource(
            WILDCARD_POLICY_ARN,
            "IAM Policy",
            None,
            "wildcard",
            {"arn": WILDCARD_POLICY_ARN, "document": wildcard_document},
        ),
        make_resource(
            READ_ONLY_POLICY_ARN,
            "IAM Policy",
            None,
            "read-only",
            {"arn": READ_ONLY_POLICY_ARN, "document": read_only_document},
        ),
    ]


def ids_for(findings, rule_id: str) -> list[str]:
    return [f.resource_id for f in findings if f.rule_id == rule_id]


def test_all_rules_on_a_scan_shaped_resource_list_give_the_expected_findings():
    findings = run_rules(scan_like_resources())

    assert ids_for(findings, "CIS-S3-001") == ["open-bucket"]
    assert ids_for(findings, "CIS-S3-002") == ["default-bucket", "open-bucket", "versioned-bucket"]
    assert ids_for(findings, "CIS-S3-003") == ["default-bucket", "open-bucket"]
    assert ids_for(findings, "CIS-SG-001") == ["sg-0open"]
    assert ids_for(findings, "CIS-IAM-001") == [WILDCARD_POLICY_ARN]
    assert ids_for(findings, "SX-IAM-PRIVESC-001") == [WILDCARD_POLICY_ARN]
    assert len(findings) == 1 + 3 + 2 + 1 + 1 + 1


def test_privesc_finding_for_a_wildcard_policy_lists_all_methods_and_says_why():
    findings = run_rules(scan_like_resources())

    finding = next(f for f in findings if f.rule_id == "SX-IAM-PRIVESC-001")
    assert len(finding.details["methods"]) == 15
    assert "implies all methods" in finding.details["note"]


def test_read_only_policy_with_resource_star_produces_no_findings():
    findings = run_rules(scan_like_resources())

    assert READ_ONLY_POLICY_ARN not in {f.resource_id for f in findings}


def test_iam_001_severity_is_high_for_action_star_and_medium_for_resource_star_only():
    writes = {"Statement": [{"Effect": "Allow", "Action": "s3:PutObject", "Resource": "*"}]}
    resources = scan_like_resources() + [
        make_resource("arn:p2", "IAM Policy", None, "p2", {"document": writes})
    ]

    findings = run_rules(resources)

    severity = {f.resource_id: f.severity for f in findings if f.rule_id == "CIS-IAM-001"}
    assert severity == {WILDCARD_POLICY_ARN: "HIGH", "arn:p2": "MEDIUM"}


def test_info_rules_do_not_count_toward_risk_and_others_do():
    for rule in ALL_RULES:
        assert rule.counts_toward_risk == (rule.severity != "INFO"), rule.id

    assert next(r for r in ALL_RULES if r.id == "CIS-S3-002").severity == "INFO"


def test_findings_carry_the_rule_metadata_and_start_open():
    findings = run_rules(scan_like_resources())

    finding = next(f for f in findings if f.rule_id == "CIS-S3-001")
    assert finding.severity == "HIGH"
    assert finding.category == "Storage"
    assert finding.status == "OPEN"
    assert finding.resource_type == "S3"
    assert finding.details["settings_off"] == list(ALL_OFF)


def test_finding_ids_are_the_same_on_every_run():
    first = [f.finding_id for f in run_rules(scan_like_resources())]
    second = [f.finding_id for f in run_rules(scan_like_resources())]

    assert first == second
    assert all(re.fullmatch(r"F-[A-Z0-9-]+-[0-9a-f]{8}", i) for i in first)
    assert len(set(first)) == len(first)


def test_adding_a_resource_does_not_change_existing_finding_ids():
    before = {f.finding_id for f in run_rules(scan_like_resources())}
    extra = bucket("another-bucket", ALL_OFF, "Disabled")

    after = {f.finding_id for f in run_rules(scan_like_resources() + [extra])}

    assert before < after


def test_resources_with_unknown_attributes_produce_no_findings():
    resources = [
        make_resource("b", "S3", None, "b", {}),
        make_resource("sg-1", "Security Group", "ap-southeast-2", "g", {}),
        make_resource("arn:p", "IAM Policy", None, "p", {}),
        make_resource("arn:r", "IAM Role", None, "r", {"instance_profile_arns": []}),
    ]

    assert run_rules(resources) == []


def flag_every_instance(resources: list[dict]) -> list[Hit]:
    return [Hit(r, {}) for r in of_type(resources, "EC2")]


def test_terminated_instances_are_not_passed_to_rules():
    rule = Rule("T-001", "t", "INFO", "Compute", "d", "f", flag_every_instance)
    running = make_resource("i-1", "EC2", "ap-southeast-2", "a", {"state": "running"})
    terminated = make_resource("i-2", "EC2", "ap-southeast-2", "b", {"state": "terminated"})

    findings = run_rules([running, terminated], rules=[rule])

    assert [f.resource_id for f in findings] == ["i-1"]
