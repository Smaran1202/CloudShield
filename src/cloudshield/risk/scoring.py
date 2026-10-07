from dataclasses import replace

from cloudshield.findings import Finding
from cloudshield.rules import ALL_RULES
from cloudshield.rules.s3 import BLOCK_SETTINGS
from cloudshield.rules.security_groups import open_sources

BASE_SCORES = {"CRITICAL": 90, "HIGH": 70, "MEDIUM": 40, "LOW": 20, "INFO": 5}
EXPOSURE_BONUS = 15
ATTACHED_BONUS = 10
PRIVILEGE_BONUS = 10
COUNTS_TOWARD_RISK = {rule.id: rule.counts_toward_risk for rule in ALL_RULES}


def factor(name: str, adjustment: int, reason: str, certainty: str) -> dict:
    return {"factor": name, "adjustment": adjustment, "reason": reason, "certainty": certainty}


def exposure_factor(resource: dict) -> dict | None:
    """+15 when the resource is configured to be reachable from the internet."""
    attributes = resource["attributes"]
    if resource["resource_type"] == "S3":
        if "public_access_block" not in attributes:
            reason = "The public access block could not be read, so exposure is unknown."
            return factor("exposure", 0, reason, "unknown")
        block = attributes["public_access_block"]
        off = [n for n in BLOCK_SETTINGS if block is None or not block.get(n)]
        if off:
            reason = f"Block Public Access is incomplete (off or missing: {', '.join(off)})."
            return factor("exposure", EXPOSURE_BONUS, reason, "verified")
        return factor("exposure", 0, "Block Public Access is fully enabled.", "verified")

    if resource["resource_type"] == "Security Group":
        if "inbound" not in attributes:
            reason = "The inbound rules could not be read, so exposure is unknown."
            return factor("exposure", 0, reason, "unknown")
        if any(open_sources(permission) for permission in attributes["inbound"]):
            reason = (
                "An inbound rule allows 0.0.0.0/0 or ::/0. This is the configuration only; "
                "whether it can be reached is not tested."
            )
            return factor("exposure", EXPOSURE_BONUS, reason, "verified")
        return factor("exposure", 0, "No inbound rule allows 0.0.0.0/0 or ::/0.", "verified")
    return None


def attached_factor(resource: dict, instances: list[dict], ec2_known: bool) -> dict | None:
    """+10 when a security group is attached to a running EC2 instance."""
    if resource["resource_type"] != "Security Group":
        return None
    if not ec2_known:
        reason = "EC2 data for this region is unknown (the EC2 scan had errors or skipped it)."
        return factor("attached", 0, reason, "unknown")
    running = [
        i["resource_id"]
        for i in instances
        if i["attributes"]["state"] == "running"
        and resource["resource_id"] in i["attributes"]["security_group_ids"]
    ]
    if running:
        reason = f"Attached to {len(running)} running EC2 instance(s): {', '.join(running[:3])}."
        return factor("attached", ATTACHED_BONUS, reason, "verified")
    reason = (
        "Not attached to any running EC2 instance in this scan. Other users of a security "
        "group, such as load balancers or databases, are not checked."
    )
    return factor("attached", 0, reason, "heuristic")


def privilege_factor(resource: dict) -> dict | None:
    """+10 when an IAM policy is attached to a user, role or group."""
    if resource["resource_type"] != "IAM Policy":
        return None
    attached_to = resource["attributes"].get("attached_to")
    if attached_to is None:
        reason = "Where the policy is attached could not be read, so this is unknown."
        return factor("privilege", 0, reason, "unknown")
    counts = {kind: len(names) for kind, names in attached_to.items()}
    if sum(counts.values()) == 0:
        return factor("privilege", 0, "Not attached to any user, role or group.", "verified")
    reason = (
        f"Attached to {counts['users']} user(s), {counts['roles']} role(s) "
        f"and {counts['groups']} group(s)."
    )
    return factor("privilege", PRIVILEGE_BONUS, reason, "verified")


def context_factors(resource: dict, instances: list[dict], ec2_known: bool) -> list[dict]:
    factors = [
        exposure_factor(resource),
        attached_factor(resource, instances, ec2_known),
        privilege_factor(resource),
    ]
    return [f for f in factors if f is not None]


def score_findings(findings: list[Finding], result: dict, regions: list[str]) -> list[Finding]:
    resources = {r["resource_id"]: r for r in result["resources"]}
    instances = [r for r in result["resources"] if r["resource_type"] == "EC2"]
    ec2_has_errors = any(error["service"] == "ec2" for error in result["errors"])

    scored = []
    for finding in findings:
        if not COUNTS_TOWARD_RISK.get(finding.rule_id, True):
            scored.append(finding)
            continue
        resource = resources[finding.resource_id]
        ec2_known = not ec2_has_errors and resource["region"] in regions
        factors = context_factors(resource, instances, ec2_known)
        score = BASE_SCORES[finding.severity] + sum(f["adjustment"] for f in factors)
        scored.append(replace(finding, risk_score=min(100, score), risk_factors=factors))
    return scored
