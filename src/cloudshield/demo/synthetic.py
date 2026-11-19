import json

# A hand-written file shaped like imported scanner output (JSON-OCSF). No scanner produced it and
# it is not copied from any real output. The check ids are ones CloudShield already knows; the
# severities, resources and wording are made up for the demo.
ACCOUNT = "123456789012"
REGION = "us-east-1"
FILE_NAME = "synthetic-demo-import.json"
PRODUCT = "Prowler (synthetic demo file, not a real run)"


def bucket(name: str) -> tuple[str, str, str]:
    return f"arn:aws:s3:::{name}", "AwsS3Bucket", "s3"


def entry(
    check: str, status: str, severity: str, resource: tuple[str, str, str], detail: str
) -> dict:
    uid, kind, group = resource
    return {
        "message": detail,
        "metadata": {
            "event_code": check,
            "version": "1.5.0",
            "product": {"name": PRODUCT, "version": "demo"},
        },
        "severity": severity,
        "status_code": status,
        "status_detail": detail,
        "unmapped": {"categories": []},
        "finding_info": {
            "uid": f"demo-{check}-{uid}",
            "title": f"Demo check {check}",
            "desc": f"Made-up description of {check}.",
        },
        "cloud": {"account": {"uid": ACCOUNT}, "region": REGION},
        "remediation": {"desc": f"Made-up advice for {check}.", "references": []},
        "risk_details": f"Made-up risk text for {check}.",
        "resources": [{"uid": uid, "region": REGION, "group": {"name": group}, "type": kind}],
    }


def demo_entries() -> list[dict]:
    iam = f"arn:aws:iam::{ACCOUNT}"
    ec2 = f"arn:aws:ec2:{REGION}:{ACCOUNT}"
    return [
        # Our own rule fails on the same bucket: the imported finding is merged into ours.
        entry(
            "s3_bucket_level_public_access_block",
            "FAIL",
            "High",
            bucket("demo-public-site"),
            "Bucket demo-public-site does not block public access.",
        ),
        entry(
            "s3_bucket_object_versioning",
            "FAIL",
            "Medium",
            bucket("demo-public-site"),
            "Bucket demo-public-site has versioning off.",
        ),
        entry(
            "s3_bucket_kms_encryption",
            "FAIL",
            "Medium",
            bucket("demo-app-data"),
            "Bucket demo-app-data does not use a KMS key.",
        ),
        # Our own rule fails and this one passes: the two tools disagree.
        entry(
            "s3_bucket_level_public_access_block",
            "PASS",
            "High",
            bucket("demo-app-data"),
            "Bucket demo-app-data blocks public access.",
        ),
        entry(
            "s3_bucket_level_public_access_block",
            "PASS",
            "High",
            bucket("demo-backups"),
            "Bucket demo-backups blocks public access.",
        ),
        # Imported only: CloudShield has no rule for these.
        entry(
            "iam_password_policy_minimum_length_14",
            "FAIL",
            "Medium",
            (f"{iam}:password-policy", "AwsIamPasswordPolicy", "iam"),
            "The password policy minimum length is below 14.",
        ),
        entry(
            "iam_user_hardware_mfa_enabled",
            "FAIL",
            "Medium",
            (f"{iam}:user/demo-admin", "AwsIamUser", "iam"),
            "User demo-admin has no hardware MFA device.",
        ),
        entry(
            "ec2_networkacl_allow_ingress_tcp_port_22",
            "FAIL",
            "High",
            (f"{ec2}:network-acl/acl-0demo000000000001", "AwsEc2NetworkAcl", "ec2"),
            "Network ACL acl-0demo000000000001 allows SSH from anywhere.",
        ),
        entry(
            "iam_aws_attached_policy_no_administrative_privileges",
            "FAIL",
            "High",
            ("arn:aws:iam::aws:policy/AdministratorAccess", "AwsIamPolicy", "iam"),
            "The AWS managed policy AdministratorAccess is attached.",
        ),
        entry(
            "ec2_securitygroup_not_used",
            "FAIL",
            "Low",
            (f"{ec2}:security-group/sg-0demo000000000001", "AwsEc2SecurityGroup", "ec2"),
            "Security group sg-0demo000000000001 is not attached to anything.",
        ),
    ]


def demo_file() -> bytes:
    return json.dumps(demo_entries(), indent=2).encode("utf-8")
