from cloudshield.rules.rule import Hit, Rule, of_type

READ_ONLY_PREFIXES = ("get", "list", "describe")
# Read-only actions whose names do not start with Get, List or Describe.
READ_ONLY_ALLOWLIST = {
    "dynamodb:batchgetitem",
    "dynamodb:query",
    "dynamodb:scan",
    "logs:filterlogevents",
    "cloudtrail:lookupevents",
}


def as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def statements(document: dict) -> list[dict]:
    return as_list(document.get("Statement"))


def is_read_only(action: str) -> bool:
    name = action.split(":")[-1].lower()
    return name.startswith(READ_ONLY_PREFIXES) or action.lower() in READ_ONLY_ALLOWLIST


def check_wildcard_policies(resources: list[dict]) -> list[Hit]:
    hits = []
    for policy in of_type(resources, "IAM Policy"):
        document = policy["attributes"].get("document")
        if document is None:
            continue
        flagged = []
        for index, statement in enumerate(statements(document)):
            if statement.get("Effect") != "Allow":
                continue
            if "NotAction" in statement or "NotResource" in statement:
                continue
            actions = as_list(statement.get("Action"))
            action_wildcard = "*" in actions
            resource_wildcard = "*" in as_list(statement.get("Resource"))
            writes = [a for a in actions if not is_read_only(a)] if resource_wildcard else []
            if action_wildcard or writes:
                flagged.append(
                    {
                        "statement_index": index,
                        "sid": statement.get("Sid"),
                        "action_wildcard": action_wildcard,
                        "resource_wildcard": resource_wildcard,
                        "non_read_only_actions": writes,
                    }
                )
        if flagged:
            severity = "HIGH" if any(s["action_wildcard"] for s in flagged) else "MEDIUM"
            hits.append(Hit(policy, {"statements": flagged}, severity=severity))
    return hits


RULES = [
    Rule(
        id="CIS-IAM-001",
        title="IAM policy allows all actions or all resources",
        severity="HIGH",
        category="Identity",
        description=(
            'A customer-managed policy has an Allow statement with Action "*" (HIGH), or with '
            'Resource "*" and at least one action that is not read-only (MEDIUM). Read-only '
            "means the action starts with Get, List or Describe, or is in a short allowlist "
            "in the rule code. A policy whose actions are all read-only is not flagged for "
            'Resource "*". Statements that use NotAction or NotResource are skipped, because '
            "they cannot be judged by looking for a single wildcard."
        ),
        fix="Replace the wildcards with the specific actions and resources the policy needs.",
        check=check_wildcard_policies,
    ),
]
