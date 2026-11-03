from dataclasses import replace

from cloudshield.findings import Finding
from cloudshield.rules import ALL_RULES
from cloudshield.rules.evidence import item
from cloudshield.rules.s3 import BLOCK_SETTINGS
from cloudshield.rules.security_groups import open_sources

BASE_SCORES = {"CRITICAL": 90, "HIGH": 70, "MEDIUM": 40, "LOW": 20, "INFO": 5}
EXPOSURE_BONUS = 15
ATTACHED_BONUS = 10
PRIVILEGE_BONUS = 10
COUNTS_TOWARD_RISK = {rule.id: rule.counts_toward_risk for rule in ALL_RULES}
ACCOUNT_BLOCK_REASON = (
    "Account-wide Block Public Access is on (read by the scan), so this bucket cannot be made "
    "public by an ACL or policy"
)
ACCOUNT_BLOCK_FACT = (
    "Account-wide Block Public Access is on, but this bucket's own setting is still off"
)


def factor(name: str, adjustment: int, reason: str, certainty: str) -> dict:
    return {"factor": name, "adjustment": adjustment, "reason": reason, "certainty": certainty}


def account_block_on(account_settings: dict) -> dict | None:
    """The account-wide Block Public Access settings, when the scan read them and all four are
    on. A failed, denied or missing read, or a setting that is off, gives None."""
    block = account_settings.get("s3_public_access_block")
    if block and all(block.get(name) is True for name in BLOCK_SETTINGS):
        return block
    return None


def is_mitigated(risk_factors: list[dict]) -> bool:
    """True when the exposure was left out because the account-wide block is on."""
    return any(
        f["factor"] == "exposure" and f["reason"] == ACCOUNT_BLOCK_REASON for f in risk_factors
    )


def exposure_factor(resource: dict, account_block: dict | None = None) -> dict | None:
    """+15 when the resource is configured to be reachable from the internet."""
    attributes = resource["attributes"]
    if resource["resource_type"] == "S3":
        if "public_access_block" not in attributes:
            reason = "The public access block could not be read, so exposure is unknown."
            return factor("exposure", 0, reason, "unknown")
        block = attributes["public_access_block"]
        off = [n for n in BLOCK_SETTINGS if block is None or not block.get(n)]
        if off and account_block is not None:
            return factor("exposure", 0, ACCOUNT_BLOCK_REASON, "verified")
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


def context_factors(
    resource: dict, instances: list[dict], ec2_known: bool, account_block: dict | None = None
) -> list[dict]:
    factors = [
        exposure_factor(resource, account_block),
        attached_factor(resource, instances, ec2_known),
        privilege_factor(resource),
    ]
    return [f for f in factors if f is not None]


def score_breakdown(
    severity: str, score: int | None, factors: list[dict], source: str, basis: str
) -> dict | None:
    """How a stored score was made, from the same numbers the scoring code used."""
    if score is None:
        return None
    base = BASE_SCORES[severity]
    adjustments = sum(f["adjustment"] for f in factors)
    return {
        "base": base,
        "base_source": "scanner" if source == "prowler" else "cloudshield",
        "adjustments": adjustments,
        "capped": base + adjustments > 100,
        "basis": basis,
    }


def score_findings(findings: list[Finding], result: dict, regions: list[str]) -> list[Finding]:
    resources = {r["resource_id"]: r for r in result["resources"]}
    instances = [r for r in result["resources"] if r["resource_type"] == "EC2"]
    ec2_has_errors = any(error["service"] == "ec2" for error in result["errors"])
    account_block = account_block_on(result.get("account_settings", {}))

    scored = []
    for finding in findings:
        if not COUNTS_TOWARD_RISK.get(finding.rule_id, True):
            scored.append(finding)
            continue
        resource = resources[finding.resource_id]
        ec2_known = not ec2_has_errors and resource["region"] in regions
        factors = context_factors(resource, instances, ec2_known, account_block)
        score = BASE_SCORES[finding.severity] + sum(f["adjustment"] for f in factors)
        evidence = finding.evidence
        if is_mitigated(factors):
            added = account_block_item(resource, account_block)
            evidence = {**evidence, "items": [*evidence["items"], added]}
        scored.append(
            replace(finding, risk_score=min(100, score), risk_factors=factors, evidence=evidence)
        )
    return scored


def account_block_item(resource: dict, account_block: dict) -> dict:
    """Evidence: the account-wide setting that was read, and the bucket's own settings that are
    still off."""
    own = resource["attributes"]["public_access_block"]
    off = [name for name in BLOCK_SETTINGS if own is None or not own.get(name)]
    value = {
        "account_wide": {name: account_block[name] for name in BLOCK_SETTINGS},
        "bucket_settings_off": off,
    }
    source = "account_settings.s3_public_access_block, attributes.public_access_block"
    return item(ACCOUNT_BLOCK_FACT, value, source)
