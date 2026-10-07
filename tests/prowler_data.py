import json

# Hand-written test data shaped like Prowler JSON-OCSF output. It is not copied from any real
# output file.
ACCOUNT = "123456789012"
BUCKET_ARN = "arn:aws:s3:::my-bucket"
GROUP_ARN = f"arn:aws:ec2:ap-southeast-2:{ACCOUNT}:security-group/sg-0abc123"
POLICY_ARN = f"arn:aws:iam::{ACCOUNT}:policy/deploy"


def entry(
    check: str = "s3_bucket_public_access",
    status: str = "FAIL",
    severity: str | None = "High",
    severity_id: int = 4,
    uid: str | None = BUCKET_ARN,
    resource_type: str = "AwsS3Bucket",
    group: str = "s3",
    region: str = "ap-southeast-2",
    account: str = ACCOUNT,
    version: str = "1.5.0",
    title: str = "Bucket does not block public access",
    status_detail: str | None = None,
) -> dict:
    data = {
        "message": "ignored",
        "metadata": {
            "event_code": check,
            "version": version,
            "product": {"name": "Prowler", "version": "5.44.0"},
        },
        "severity_id": severity_id,
        "status": "New",
        "status_code": status,
        "status_detail": f"Detail for {check}." if status_detail is None else status_detail,
        "unmapped": {"categories": ["internet-exposed"]},
        "finding_info": {
            "uid": f"prowler-aws-{check}-{ACCOUNT}-{region}",
            "title": title,
            "desc": f"Description of {check}.",
        },
        "cloud": {"account": {"uid": account}, "region": region},
        "remediation": {
            "desc": f"Fix {check} like this.",
            "references": [f"https://example.com/{check}"],
        },
        "risk_details": f"Risk of {check}.",
        "resources": [],
    }
    if severity is not None:
        data["severity"] = severity
    if uid is not None:
        resource = {"uid": uid, "region": region, "group": {"name": group}, "type": resource_type}
        data["resources"] = [resource]
    return data


def to_bytes(entries: list) -> bytes:
    return json.dumps(entries).encode("utf-8")
