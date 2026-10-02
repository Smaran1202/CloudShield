from cloudshield.scanner.common import attempt, list_all, make_resource


def collect_policies(session, errors: list) -> list[dict]:
    iam = session.client("iam")
    where = {"service": "iam", "region": None, "resource": None}
    policies, ok = attempt(errors, where, list_all, iam, "list_policies", "Policies", Scope="Local")
    if not ok:
        return []

    resources = []
    for policy in policies:
        arn = policy["Arn"]
        attributes = {"arn": arn, "default_version_id": policy["DefaultVersionId"]}
        document = fetch_document(iam, arn, policy["DefaultVersionId"], errors)
        if document is not None:
            attributes["document"] = document
        resources.append(make_resource(arn, "IAM Policy", None, policy["PolicyName"], attributes))
    return resources


def collect_roles(session, profile_arns: list[str], errors: list) -> list[dict]:
    iam = session.client("iam")
    roles = {}
    for profile_arn in sorted(set(profile_arns)):
        where = {"service": "iam", "region": None, "resource": profile_arn}
        profile_name = profile_arn.split("/")[-1]
        response, ok = attempt(
            errors, where, iam.get_instance_profile, InstanceProfileName=profile_name
        )
        if not ok:
            continue
        for role in response["InstanceProfile"]["Roles"]:
            if role["Arn"] not in roles:
                roles[role["Arn"]] = describe_role(iam, role, errors)
            roles[role["Arn"]]["attributes"]["instance_profile_arns"].append(profile_arn)
    return list(roles.values())


def describe_role(iam, role: dict, errors: list) -> dict:
    name = role["RoleName"]
    where = {"service": "iam", "region": None, "resource": role["Arn"]}
    attributes = {"instance_profile_arns": []}

    attached, ok = attempt(
        errors,
        where,
        list_all,
        iam,
        "list_attached_role_policies",
        "AttachedPolicies",
        RoleName=name,
    )
    if ok:
        attributes["attached_policies"] = [
            describe_attached_policy(iam, policy, errors) for policy in attached
        ]

    inline_names, ok = attempt(
        errors, where, list_all, iam, "list_role_policies", "PolicyNames", RoleName=name
    )
    if ok:
        inline = []
        for policy_name in inline_names:
            entry = {"name": policy_name}
            response, ok = attempt(
                errors, where, iam.get_role_policy, RoleName=name, PolicyName=policy_name
            )
            if ok:
                entry["document"] = response["PolicyDocument"]
            inline.append(entry)
        attributes["inline_policies"] = inline

    return make_resource(role["Arn"], "IAM Role", None, name, attributes)


def describe_attached_policy(iam, policy: dict, errors: list) -> dict:
    arn = policy["PolicyArn"]
    entry = {"name": policy["PolicyName"], "arn": arn}
    where = {"service": "iam", "region": None, "resource": arn}
    response, ok = attempt(errors, where, iam.get_policy, PolicyArn=arn)
    if ok:
        document = fetch_document(iam, arn, response["Policy"]["DefaultVersionId"], errors)
        if document is not None:
            entry["document"] = document
    return entry


def fetch_document(iam, arn: str, version_id: str, errors: list) -> dict | None:
    where = {"service": "iam", "region": None, "resource": arn}
    response, ok = attempt(
        errors, where, iam.get_policy_version, PolicyArn=arn, VersionId=version_id
    )
    return response["PolicyVersion"]["Document"] if ok else None