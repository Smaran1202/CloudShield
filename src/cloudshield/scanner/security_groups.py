from cloudshield.scanner.common import attempt, list_all, make_resource


def collect_security_groups(session, region: str, errors: list) -> list[dict]:
    ec2 = session.client("ec2", region_name=region)
    where = {"service": "ec2", "region": region, "resource": None}
    groups, ok = attempt(errors, where, list_all, ec2, "describe_security_groups", "SecurityGroups")
    if not ok:
        return []

    resources = []
    for group in groups:
        attributes = {
            "vpc_id": group.get("VpcId"),
            "inbound": group["IpPermissions"],
            "outbound": group["IpPermissionsEgress"],
        }
        group_id = group["GroupId"]
        resources.append(
            make_resource(group_id, "Security Group", region, group["GroupName"], attributes)
        )
    return resources
