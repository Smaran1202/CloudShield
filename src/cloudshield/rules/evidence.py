from cloudshield.rules.s3 import BLOCK_SETTINGS

# Evidence lists the resource facts a rule used. Facts read straight from the scan are
# "verified". A conclusion drawn from them that the scan cannot fully check is "heuristic".


def item(fact: str, value, source: str, certainty: str = "verified") -> dict:
    return {"fact": fact, "value": value, "source": source, "certainty": certainty}


def public_access_block(details: dict, resource_type: str) -> list[dict]:
    block = details["public_access_block"]
    if block is None:
        source = "attributes.public_access_block"
        return [item("No public access block is configured", None, source)]
    return [
        item(name, block.get(name), f"attributes.public_access_block.{name}")
        for name in BLOCK_SETTINGS
    ]


def kms_encryption(details: dict, resource_type: str) -> list[dict]:
    source = "attributes.encryption[].ApplyServerSideEncryptionByDefault.SSEAlgorithm"
    return [item("Default encryption algorithms", details["algorithms"], source)]


def versioning(details: dict, resource_type: str) -> list[dict]:
    return [item("Versioning status", details["versioning"], "attributes.versioning")]


def open_inbound_rules(details: dict, resource_type: str) -> list[dict]:
    items = []
    for rule in details["rules"]:
        value = {key: rule[key] for key in ("protocol", "from_port", "to_port", "cidrs")}
        items.append(item(f"Inbound rule exposes {rule['exposes']}", value, "attributes.inbound"))
    return items


def wildcard_statements(details: dict, resource_type: str) -> list[dict]:
    items = []
    for statement in details["statements"]:
        if statement["action_wildcard"]:
            fact = 'Statement allows Action "*"'
        else:
            fact = 'Statement allows non-read-only actions on Resource "*"'
        source = f"attributes.document.Statement[{statement['statement_index']}]"
        value = {
            "sid": statement["sid"],
            "action_wildcard": statement["action_wildcard"],
            "resource_wildcard": statement["resource_wildcard"],
            "non_read_only_actions": statement["non_read_only_actions"],
        }
        items.append(item(fact, value, source))
    return items


def privilege_escalation(details: dict, resource_type: str) -> list[dict]:
    # Permission boundaries, service control policies and resource policies are not evaluated,
    # so the conclusion that a method works is only a heuristic.
    if resource_type == "IAM Role":
        source = "attributes.attached_policies[].document, attributes.inline_policies[].document"
    else:
        source = "attributes.document"
    items = []
    for method in details["methods"]:
        value = {key: method[key] for key in ("permissions", "limited_to_resources", "conditional")}
        items.append(item(method["method"], value, source, "heuristic"))
    if "note" in details:
        items.append(item("Full wildcard", details["note"], source, "heuristic"))
    return items


BUILDERS = {
    "CIS-S3-001": public_access_block,
    "CIS-S3-002": kms_encryption,
    "CIS-S3-003": versioning,
    "CIS-SG-001": open_inbound_rules,
    "CIS-IAM-001": wildcard_statements,
    "SX-IAM-PRIVESC-001": privilege_escalation,
}


def build_evidence(rule_id: str, details: dict, resource_type: str) -> dict:
    builder = BUILDERS.get(rule_id)
    return {"items": builder(details, resource_type) if builder else []}
