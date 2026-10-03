from cloudshield.fixes.blast import blast_radius

PUBLIC_READ = {
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::my-bucket/*",
}


def bucket(**attributes) -> dict:
    return {
        "resource_id": "my-bucket",
        "resource_type": "S3",
        "region": "us-east-1",
        "attributes": attributes,
    }


def finding(rule_id: str, details=None) -> dict:
    return {"rule_id": rule_id, "details": details or {}}


def instance(instance_id="i-1", state="running", groups=("sg-1",)) -> dict:
    attributes = {"state": state, "security_group_ids": list(groups)}
    return {"resource_id": instance_id, "resource_type": "EC2", "attributes": attributes}


def group() -> dict:
    return {
        "resource_id": "sg-1",
        "resource_type": "Security Group",
        "region": "ap-southeast-2",
        "attributes": {},
    }


def ssh_rule(protocol="tcp") -> dict:
    return {"rules": [{"protocol": protocol, "exposes": "SSH (port 22)"}]}


def policy(**attributes) -> dict:
    arn = "arn:aws:iam::1:policy/p"
    return {
        "resource_id": arn,
        "resource_type": "IAM Policy",
        "region": None,
        "attributes": attributes,
    }


def fact_named(blast: dict, name: str) -> dict:
    return next(f for f in blast["factors"] if f["fact"] == name)


def test_public_read_policy_makes_enabling_the_block_high_and_is_verified():
    resource = bucket(policy={"Statement": [PUBLIC_READ]})

    blast = blast_radius(finding("CIS-S3-001"), resource, [])

    statement = fact_named(blast, "Bucket policy allows a public principal")
    assert blast["level"] == "high"
    assert statement["certainty"] == "verified"
    assert statement["source"] == "attributes.policy.Statement[0]"
    assert statement["value"] == {"actions": ["s3:GetObject"], "has_condition": False}
    assert "public reads" in blast["notes"][0]


def test_public_policy_with_a_non_read_action_is_medium():
    write = {**PUBLIC_READ, "Action": "s3:PutObject"}

    blast = blast_radius(finding("CIS-S3-001"), bucket(policy={"Statement": [write]}), [])

    assert blast["level"] == "medium"


def test_public_principal_given_as_an_aws_star_dict_counts_as_public():
    statement = {**PUBLIC_READ, "Principal": {"AWS": "*"}}

    blast = blast_radius(finding("CIS-S3-001"), bucket(policy={"Statement": statement}), [])

    assert blast["level"] == "high"


def test_policy_that_only_allows_named_principals_is_not_public():
    private = {**PUBLIC_READ, "Principal": {"AWS": "arn:aws:iam::1:role/app"}}

    blast = blast_radius(finding("CIS-S3-001"), bucket(policy={"Statement": [private]}), [])

    assert blast["level"] == "unknown"
    assert fact_named(blast, "Bucket policy")["value"] == "no public allow statement"


def test_bucket_with_no_policy_is_still_unknown_because_website_hosting_is_not_collected():
    blast = blast_radius(finding("CIS-S3-001"), bucket(policy=None), [])

    assert blast["level"] == "unknown"
    assert fact_named(blast, "Bucket policy")["value"] == "none"
    website = fact_named(blast, "Static website hosting")
    assert website["certainty"] == "unknown"
    assert website["value"] is None


def test_unreadable_bucket_policy_is_unknown():
    blast = blast_radius(finding("CIS-S3-001"), bucket(), [])

    assert blast["level"] == "unknown"
    assert fact_named(blast, "Bucket policy")["certainty"] == "unknown"


def test_versioning_is_low_with_a_note_that_storage_cost_grows():
    blast = blast_radius(finding("CIS-S3-003", {"versioning": "Disabled"}), bucket(), [])

    assert blast["level"] == "low"
    assert "Storage cost grows" in blast["notes"][0]


def test_kms_encryption_is_unknown_because_the_key_is_not_chosen():
    blast = blast_radius(finding("CIS-S3-002"), bucket(), [])

    assert blast["level"] == "unknown"
    assert blast["factors"][0]["certainty"] == "unknown"


def test_security_group_with_a_running_instance_is_medium_and_suggests_session_manager():
    blast = blast_radius(finding("CIS-SG-001", ssh_rule()), group(), [instance()])

    running = fact_named(blast, "Running instances using this group")
    assert blast["level"] == "medium"
    assert running["value"] == ["i-1"]
    assert running["certainty"] == "verified"
    assert fact_named(blast, "Who connects to these ports")["certainty"] == "unknown"
    assert any("Session Manager" in note for note in blast["notes"])


def test_security_group_with_only_stopped_or_other_instances_is_unknown_not_low():
    others = [instance("i-2", "stopped"), instance("i-3", "running", groups=("sg-other",))]

    blast = blast_radius(finding("CIS-SG-001", ssh_rule()), group(), others)

    assert blast["level"] == "unknown"
    assert fact_named(blast, "Running instances using this group")["value"] == []


def test_allow_all_rule_adds_a_note():
    blast = blast_radius(finding("CIS-SG-001", ssh_rule("-1")), group(), [instance()])

    assert any("all traffic" in note for note in blast["notes"])


def test_policy_attached_to_a_role_is_high():
    attached = {"users": [], "roles": ["app"], "groups": []}

    blast = blast_radius(finding("CIS-IAM-001"), policy(attached_to=attached), [])

    assert blast["level"] == "high"
    assert fact_named(blast, "Attached to")["value"] == attached
    assert fact_named(blast, "Attached to")["certainty"] == "verified"


def test_unattached_policy_is_low_but_usage_is_still_unknown():
    attached = {"users": [], "roles": [], "groups": []}

    blast = blast_radius(finding("CIS-IAM-001"), policy(attached_to=attached), [])

    usage = fact_named(blast, "Actual use of the permissions")
    assert blast["level"] == "low"
    assert usage["certainty"] == "unknown"
    assert "Usage is unknown" in blast["notes"][0]


def test_policy_with_unknown_attachment_is_unknown():
    blast = blast_radius(finding("SX-IAM-PRIVESC-001"), policy(), [])

    assert blast["level"] == "unknown"
    assert fact_named(blast, "Attached to")["certainty"] == "unknown"


def test_role_used_by_an_instance_profile_is_high():
    arn = "arn:aws:iam::1:role/app"
    attributes = {"instance_profile_arns": ["arn:aws:iam::1:instance-profile/app"]}
    role = {
        "resource_id": arn,
        "resource_type": "IAM Role",
        "region": None,
        "attributes": attributes,
    }

    blast = blast_radius(finding("SX-IAM-PRIVESC-001"), role, [])

    assert blast["level"] == "high"


def test_unknown_data_is_never_reported_as_low():
    cases = [
        blast_radius(finding("CIS-S3-001"), bucket(policy=None), []),
        blast_radius(finding("CIS-S3-001"), bucket(), []),
        blast_radius(finding("CIS-SG-001", ssh_rule()), group(), []),
        blast_radius(finding("CIS-IAM-001"), policy(), []),
    ]

    assert [case["level"] for case in cases] == ["unknown"] * 4


def test_blast_radius_shape_is_level_factors_and_notes():
    blast = blast_radius(finding("CIS-S3-003", {"versioning": "Disabled"}), bucket(), [])

    assert set(blast) == {"level", "factors", "notes"}
    assert all(set(f) == {"fact", "value", "source", "certainty"} for f in blast["factors"])
