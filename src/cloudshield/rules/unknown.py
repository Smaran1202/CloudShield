from cloudshield.rules.privesc import policy_documents

# The attribute of a stored resource that each rule reads.
NEEDS = {
    "CIS-S3-001": "public_access_block",
    "CIS-S3-002": "encryption",
    "CIS-S3-003": "versioning",
    "CIS-SG-001": "inbound",
}
# These rules read policy documents: one for a policy, and for a role every attached and inline
# policy. policy_documents already says when any of them is unknown.
DOCUMENT_RULES = ("CIS-IAM-001", "SX-IAM-PRIVESC-001")


def missing_attribute(rule_id: str, resource: dict) -> str | None:
    """What the rule needs from this resource record and does not find, or None when it has it all.

    A key that is there with the value None or empty is a reading ("not configured", "no
    rules"), not an unknown. Only an absent key is unknown: the scanner leaves a key out when it
    could not read the value."""
    if rule_id in DOCUMENT_RULES:
        return "the policy documents" if policy_documents(resource) is None else None
    name = NEEDS.get(rule_id)
    if name is None or name in resource["attributes"]:
        return None
    return name
