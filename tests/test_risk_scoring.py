from cloudshield.findings import Finding
from cloudshield.risk.scoring import BASE_SCORES, score_findings
from cloudshield.rules import run_rules
from cloudshield.scanner.common import make_resource

REGION = "ap-southeast-2"
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
OPEN_SSH_V6 = {**OPEN_SSH, "IpRanges": [], "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}
CLOSED_SSH = {**OPEN_SSH, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}
WILDCARD = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}


def bucket(**attributes) -> dict:
    attributes.setdefault("versioning", "Enabled")
    return make_resource("my-bucket", "S3", "us-east-1", "my-bucket", attributes)


def group(*inbound) -> dict:
    attributes = {"vpc_id": "vpc-1", "inbound": list(inbound), "outbound": []}
    return make_resource("sg-1", "Security Group", REGION, "web", attributes)


def instance(state="running", groups=("sg-1",)) -> dict:
    attributes = {"state": state, "security_group_ids": list(groups), "has_public_ip": True}
    return make_resource("i-1", "EC2", REGION, "i-1", {**attributes, "instance_profile_arn": None})


def policy(attached_to=None) -> dict:
    attributes = {"document": WILDCARD}
    if attached_to is not None:
        attributes["attached_to"] = attached_to
    return make_resource("arn:aws:iam::1:policy/p", "IAM Policy", None, "p", attributes)


def scored(resources, errors=(), regions=(REGION, "us-east-1")) -> list[Finding]:
    result = {"resources": resources, "errors": list(errors)}
    return score_findings(run_rules(resources), result, list(regions))


def one(findings, rule_id: str) -> Finding:
    return next(f for f in findings if f.rule_id == rule_id)


def factor(finding: Finding, name: str) -> dict:
    return next(f for f in finding.risk_factors if f["factor"] == name)


def synthetic(severity: str, resource: dict, rule_id="CIS-SG-001") -> list[Finding]:
    finding = Finding(
        finding_id="F-test",
        rule_id=rule_id,
        resource_id=resource["resource_id"],
        resource_type=resource["resource_type"],
        title="t",
        severity=severity,
        category="c",
        status="OPEN",
        details={},
    )
    result = {"resources": [resource], "errors": []}
    return score_findings([finding], result, [REGION])


def test_base_score_depends_only_on_severity_when_there_are_no_adjustments():
    role = make_resource("arn:aws:iam::1:role/r", "IAM Role", None, "r", {})

    scores = {s: synthetic(s, role, "CIS-IAM-001")[0].risk_score for s in BASE_SCORES}

    assert scores == {"CRITICAL": 90, "HIGH": 70, "MEDIUM": 40, "LOW": 20, "INFO": 5}


def test_findings_on_a_resource_type_with_no_factors_have_an_empty_factor_list():
    role = make_resource("arn:aws:iam::1:role/r", "IAM Role", None, "r", {})

    assert synthetic("HIGH", role, "CIS-IAM-001")[0].risk_factors == []


def test_info_rules_are_excluded_from_scores():
    findings = scored([bucket(public_access_block=ALL_ON, encryption=AES)])

    finding = one(findings, "CIS-S3-002")
    assert finding.severity == "INFO"
    assert finding.risk_score is None
    assert finding.risk_factors == []


def test_s3_with_incomplete_block_public_access_gets_the_exposure_adjustment():
    block = {**ALL_ON, "BlockPublicPolicy": False}

    finding = one(scored([bucket(public_access_block=block)]), "CIS-S3-001")

    assert finding.risk_score == 85
    assert factor(finding, "exposure")["adjustment"] == 15
    assert factor(finding, "exposure")["certainty"] == "verified"
    assert "BlockPublicPolicy" in factor(finding, "exposure")["reason"]


def test_s3_with_no_public_access_block_at_all_gets_the_exposure_adjustment():
    finding = one(scored([bucket(public_access_block=None)]), "CIS-S3-001")

    assert finding.risk_score == 85
    assert "missing" in factor(finding, "exposure")["reason"]


def test_exposure_also_raises_other_findings_on_the_same_bucket():
    block = {**ALL_ON, "BlockPublicPolicy": False}

    finding = one(scored([bucket(public_access_block=block, versioning="Disabled")]), "CIS-S3-003")

    assert finding.risk_score == 55


def test_s3_with_full_block_public_access_gets_zero_exposure():
    finding = one(scored([bucket(public_access_block=ALL_ON, versioning="Disabled")]), "CIS-S3-003")

    assert finding.risk_score == 40
    assert factor(finding, "exposure")["adjustment"] == 0
    assert factor(finding, "exposure")["certainty"] == "verified"


def test_unknown_public_access_block_adds_nothing_and_says_unknown():
    finding = one(scored([bucket(versioning="Disabled")]), "CIS-S3-003")

    assert finding.risk_score == 40
    assert factor(finding, "exposure")["adjustment"] == 0
    assert factor(finding, "exposure")["certainty"] == "unknown"


def test_security_group_open_to_ipv4_internet_gets_the_exposure_adjustment():
    finding = one(scored([group(OPEN_SSH)]), "CIS-SG-001")

    assert factor(finding, "exposure")["adjustment"] == 15
    assert factor(finding, "exposure")["certainty"] == "verified"


def test_security_group_open_to_ipv6_internet_gets_the_exposure_adjustment():
    finding = one(scored([group(OPEN_SSH_V6)]), "CIS-SG-001")

    assert factor(finding, "exposure")["adjustment"] == 15


def test_security_group_with_no_open_rule_gets_zero_exposure():
    finding = synthetic("HIGH", group(CLOSED_SSH))[0]

    assert factor(finding, "exposure")["adjustment"] == 0
    assert factor(finding, "exposure")["certainty"] == "verified"


def test_security_group_attached_to_a_running_instance_gets_the_attached_adjustment():
    finding = one(scored([group(OPEN_SSH), instance("running")]), "CIS-SG-001")

    assert finding.risk_score == 95
    assert factor(finding, "attached")["adjustment"] == 10
    assert factor(finding, "attached")["certainty"] == "verified"
    assert "i-1" in factor(finding, "attached")["reason"]


def test_unattached_security_group_gets_zero_and_the_reason_says_so():
    resources = [group(OPEN_SSH), instance("running", groups=("sg-other",))]

    finding = one(scored(resources), "CIS-SG-001")

    assert finding.risk_score == 85
    assert factor(finding, "attached")["adjustment"] == 0
    assert "Not attached" in factor(finding, "attached")["reason"]
    assert factor(finding, "attached")["certainty"] == "heuristic"


def test_security_group_attached_only_to_a_stopped_instance_counts_as_unattached():
    finding = one(scored([group(OPEN_SSH), instance("stopped")]), "CIS-SG-001")

    assert factor(finding, "attached")["adjustment"] == 0


def test_attached_is_unknown_when_the_ec2_scan_had_errors():
    error = {"service": "ec2", "region": REGION, "resource": None, "message": "AccessDenied"}

    finding = one(scored([group(OPEN_SSH)], errors=[error]), "CIS-SG-001")

    assert finding.risk_score == 85
    assert factor(finding, "attached")["adjustment"] == 0
    assert factor(finding, "attached")["certainty"] == "unknown"


def test_attached_is_unknown_when_the_groups_region_was_not_scanned():
    finding = one(scored([group(OPEN_SSH)], regions=["us-east-1"]), "CIS-SG-001")

    assert factor(finding, "attached")["certainty"] == "unknown"
    assert factor(finding, "attached")["adjustment"] == 0


def test_policy_attached_to_a_role_gets_the_privilege_adjustment():
    attached_to = {"users": [], "roles": ["app"], "groups": []}

    findings = scored([policy(attached_to)])

    assert one(findings, "CIS-IAM-001").risk_score == 80
    assert one(findings, "SX-IAM-PRIVESC-001").risk_score == 80
    assert factor(one(findings, "CIS-IAM-001"), "privilege")["certainty"] == "verified"


def test_policy_attached_to_a_user_or_a_group_gets_the_privilege_adjustment():
    for attached_to in (
        {"users": ["alice"], "roles": [], "groups": []},
        {"users": [], "roles": [], "groups": ["admins"]},
    ):
        finding = one(scored([policy(attached_to)]), "CIS-IAM-001")

        assert factor(finding, "privilege")["adjustment"] == 10


def test_unattached_policy_gets_zero_and_the_reason_says_so():
    finding = one(scored([policy({"users": [], "roles": [], "groups": []})]), "CIS-IAM-001")

    assert finding.risk_score == 70
    assert factor(finding, "privilege")["adjustment"] == 0
    assert "Not attached" in factor(finding, "privilege")["reason"]


def test_unknown_attachment_says_unknown_and_adds_nothing():
    finding = one(scored([policy()]), "CIS-IAM-001")

    assert finding.risk_score == 70
    assert factor(finding, "privilege")["adjustment"] == 0
    assert factor(finding, "privilege")["certainty"] == "unknown"


def test_privilege_adjustment_is_not_applied_to_role_findings():
    role = make_resource(
        "arn:aws:iam::1:role/r",
        "IAM Role",
        None,
        "r",
        {
            "instance_profile_arns": [],
            "attached_policies": [{"name": "p", "arn": "a", "document": WILDCARD}],
            "inline_policies": [],
        },
    )

    finding = one(scored([role]), "SX-IAM-PRIVESC-001")

    assert finding.risk_score == 70
    assert finding.risk_factors == []


def test_score_is_capped_at_100():
    findings = synthetic("CRITICAL", group(OPEN_SSH))
    resources = [group(OPEN_SSH), instance("running")]
    result = {"resources": resources, "errors": []}

    capped = score_findings(findings, result, [REGION])[0]

    assert 90 + 15 + 10 == 115
    assert capped.risk_score == 100


def test_unknown_factors_never_add_risk():
    error = {"service": "ec2", "region": REGION, "resource": None, "message": "AccessDenied"}
    unknown_everything = [
        scored([bucket(versioning="Disabled")]),
        scored([group(OPEN_SSH)], errors=[error]),
        scored([policy()]),
    ]

    for findings in unknown_everything:
        for finding in findings:
            for item in finding.risk_factors:
                if item["certainty"] == "unknown":
                    assert item["adjustment"] == 0
