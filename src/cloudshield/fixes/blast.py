from cloudshield.rules.iam import as_list, matches, statements

# Blast radius is worked out from stored data only. When the data needed is missing the level
# is "unknown", never "low": unknown is not the same as safe.


def fact(name: str, value, source: str, certainty: str) -> dict:
    return {"fact": name, "value": value, "source": source, "certainty": certainty}


def blast(level: str, factors: list[dict], notes: list[str]) -> dict:
    return {"level": level, "factors": factors, "notes": notes}


def is_public_principal(statement: dict) -> bool:
    principal = statement.get("Principal")
    if principal == "*":
        return True
    return isinstance(principal, dict) and "*" in as_list(principal.get("AWS"))


def public_bucket_statements(policy: dict) -> list[tuple[int, dict]]:
    return [
        (index, statement)
        for index, statement in enumerate(statements(policy))
        if statement.get("Effect") == "Allow" and is_public_principal(statement)
    ]


def public_access_block_blast(finding: dict, resource: dict, instances: list[dict]) -> dict:
    attributes = resource["attributes"]
    factors = [
        fact("Static website hosting", None, "not collected", "unknown"),
        fact("Bucket and object ACLs", None, "not collected", "unknown"),
    ]
    notes = [
        "Website hosting, CloudFront origins and ACLs are not collected, so breakage there is "
        "unknown."
    ]
    if "policy" not in attributes:
        factors.insert(0, fact("Bucket policy", None, "attributes.policy", "unknown"))
        return blast("unknown", factors, notes)

    policy = attributes["policy"]
    public = public_bucket_statements(policy) if policy else []
    if not public:
        value = "none" if policy is None else "no public allow statement"
        factors.insert(0, fact("Bucket policy", value, "attributes.policy", "verified"))
        return blast("unknown", factors, notes)

    reads = False
    found = []
    for index, statement in public:
        actions = as_list(statement.get("Action"))
        reads = reads or any(matches(action, "s3:GetObject") for action in actions)
        value = {"actions": actions, "has_condition": "Condition" in statement}
        source = f"attributes.policy.Statement[{index}]"
        found.append(fact("Bucket policy allows a public principal", value, source, "verified"))
    notes.insert(0, "Enabling the block can break public reads that this policy allows.")
    return blast("high" if reads else "medium", found + factors, notes)


def kms_encryption_blast(finding: dict, resource: dict, instances: list[dict]) -> dict:
    factors = [fact("Permissions on the KMS key", None, "key not chosen yet", "unknown")]
    notes = [
        "Only new objects use the new default. Objects that already exist keep their encryption.",
        "Everything that writes or reads this bucket needs permission to use the KMS key.",
    ]
    return blast("unknown", factors, notes)


def versioning_blast(finding: dict, resource: dict, instances: list[dict]) -> dict:
    status = finding["details"]["versioning"]
    factors = [fact("Versioning status", status, "attributes.versioning", "verified")]
    notes = [
        "Storage cost grows, because old versions are kept until a lifecycle rule removes them.",
        "Enabling versioning does not change who can access the objects.",
    ]
    return blast("low", factors, notes)


def security_group_blast(finding: dict, resource: dict, instances: list[dict]) -> dict:
    group_id = resource["resource_id"]
    running = [
        i["resource_id"]
        for i in instances
        if i["attributes"].get("state") == "running"
        and group_id in i["attributes"].get("security_group_ids", [])
    ]
    source = "resources of type EC2, attributes.security_group_ids and attributes.state"
    factors = [
        fact("Running instances using this group", running, source, "verified"),
        fact("Who connects to these ports", None, "flow logs are not collected", "unknown"),
    ]
    notes = [
        "Use SSM Session Manager instead of SSH, so port 22 does not need to be open.",
        "Load balancers, databases and other services that use this group are not checked.",
    ]
    if any(rule["protocol"] == "-1" for rule in finding["details"]["rules"]):
        notes.append("A rule that allows all traffic may be carrying other traffic as well.")
    return blast("medium" if running else "unknown", factors, notes)


def policy_blast(finding: dict, resource: dict, instances: list[dict]) -> dict:
    attributes = resource["attributes"]
    usage = fact("Actual use of the permissions", None, "no access data collected", "unknown")
    notes = [
        "Usage is unknown: no CloudTrail or last-accessed data is collected, so removing "
        "permissions may break things that cannot be seen here."
    ]
    if resource["resource_type"] == "IAM Role":
        profiles = attributes.get("instance_profile_arns")
        if not profiles:
            return blast("unknown", [usage], notes)
        source = "attributes.instance_profile_arns"
        value = len(profiles)
        factors = [fact("Instance profiles using this role", value, source, "verified"), usage]
        return blast("high", factors, notes)

    attached_to = attributes.get("attached_to")
    if attached_to is None:
        factors = [fact("Attached to", None, "attributes.attached_to", "unknown"), usage]
        return blast("unknown", factors, notes)
    names = [name for kind in ("users", "roles", "groups") for name in attached_to[kind]]
    factors = [fact("Attached to", attached_to, "attributes.attached_to", "verified"), usage]
    return blast("high" if names else "low", factors, notes)


BUILDERS = {
    "CIS-S3-001": public_access_block_blast,
    "CIS-S3-002": kms_encryption_blast,
    "CIS-S3-003": versioning_blast,
    "CIS-SG-001": security_group_blast,
    "CIS-IAM-001": policy_blast,
    "SX-IAM-PRIVESC-001": policy_blast,
}


def blast_radius(finding: dict, resource: dict, instances: list[dict]) -> dict:
    builder = BUILDERS.get(finding["rule_id"])
    if builder is None:
        return blast("unknown", [], ["No blast radius analysis exists for this rule yet."])
    return builder(finding, resource, instances)
