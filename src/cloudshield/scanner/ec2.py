from cloudshield.scanner.common import attempt, list_all, make_resource


def collect_instances(session, region: str, errors: list) -> list[dict]:
    ec2 = session.client("ec2", region_name=region)
    where = {"service": "ec2", "region": region, "resource": None}
    reservations, ok = attempt(errors, where, list_all, ec2, "describe_instances", "Reservations")
    if not ok:
        return []

    resources = []
    for reservation in reservations:
        for instance in reservation["Instances"]:
            tags = {tag["Key"]: tag["Value"] for tag in instance.get("Tags", [])}
            profile = instance.get("IamInstanceProfile")
            attributes = {
                "state": instance["State"]["Name"],
                "security_group_ids": [group["GroupId"] for group in instance["SecurityGroups"]],
                "has_public_ip": bool(instance.get("PublicIpAddress")),
                "instance_profile_arn": profile["Arn"] if profile else None,
            }
            instance_id = instance["InstanceId"]
            name = tags.get("Name", instance_id)
            resources.append(make_resource(instance_id, "EC2", region, name, attributes))
    return resources