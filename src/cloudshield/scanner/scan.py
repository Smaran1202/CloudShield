from cloudshield.scanner.ec2 import collect_instances
from cloudshield.scanner.iam import collect_policies, collect_roles
from cloudshield.scanner.s3 import collect_buckets
from cloudshield.scanner.security_groups import collect_security_groups


def scan_account(session, regions: list[str]) -> dict:
    errors = []
    resources = collect_buckets(session, errors)
    profile_arns = []
    for region in regions:
        instances = collect_instances(session, region, errors)
        resources += instances
        resources += collect_security_groups(session, region, errors)
        for instance in instances:
            profile_arn = instance["attributes"]["instance_profile_arn"]
            if profile_arn:
                profile_arns.append(profile_arn)
    resources += collect_policies(session, errors)
    resources += collect_roles(session, profile_arns, errors)
    return {"resources": resources, "errors": errors}
