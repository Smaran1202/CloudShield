# Prowler names resources by ARN. These functions work out the resource id and type we use
# when we hold the same kind of resource. A resource we do not scan keeps its ARN.
ACCOUNT_LEVEL = {"account", "root", "password-policy"}
IAM_TYPES = {"policy": "IAM Policy", "role": "IAM Role", "user": "IAM User"}


def map_resource(
    uid: str | None, account_id: str | None, prowler_type: str = ""
) -> tuple[str, str]:
    """Returns (resource_id, resource_type) for the uid Prowler gave."""
    if not uid or uid == account_id:
        return account_id or "account", "Account"
    parts = uid.split(":", 5)
    if parts[0] != "arn" or len(parts) < 6:
        return uid, prowler_type or "Other"
    service, resource = parts[2], parts[5]

    if resource in ACCOUNT_LEVEL:
        return uid, "Account"
    if service == "s3":
        return resource.split("/")[0], "S3"
    if service == "ec2":
        kind, _, name = resource.partition("/")
        if kind == "security-group" and name:
            return name, "Security Group"
        if kind == "instance" and name:
            return name, "EC2"
        if kind == "network-acl":
            return uid, "Network ACL"
    if service == "iam":
        kind = resource.partition("/")[0]
        if kind in IAM_TYPES:
            return uid, IAM_TYPES[kind]
    return uid, prowler_type or "Other"
