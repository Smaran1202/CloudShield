import re

from cloudshield.rules.iam import as_list, statements
from cloudshield.rules.rule import Hit, Rule, of_type

# Method names and permissions from the Rhino Security Labs catalogue
# "AWS IAM Privilege Escalation - Methods and Mitigation".
METHODS = [
    ("Creating a new policy version", ["iam:CreatePolicyVersion"]),
    (
        "Setting the default policy version to an existing version",
        ["iam:SetDefaultPolicyVersion"],
    ),
    (
        "Creating an EC2 instance with an existing instance profile",
        ["iam:PassRole", "ec2:RunInstances"],
    ),
    (
        "Passing a role to a new Lambda function, then invoking it",
        ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
    ),
    ("Attaching a policy to a user", ["iam:AttachUserPolicy"]),
    ("Attaching a policy to a group", ["iam:AttachGroupPolicy"]),
    ("Attaching a policy to a role", ["iam:AttachRolePolicy"]),
    ("Creating or updating an inline policy for a user", ["iam:PutUserPolicy"]),
    ("Creating or updating an inline policy for a group", ["iam:PutGroupPolicy"]),
    ("Creating or updating an inline policy for a role", ["iam:PutRolePolicy"]),
    ("Creating a new user access key", ["iam:CreateAccessKey"]),
    ("Creating a new login profile", ["iam:CreateLoginProfile"]),
    ("Updating an existing login profile", ["iam:UpdateLoginProfile"]),
    ("Adding a user to a group", ["iam:AddUserToGroup"]),
    (
        "Updating the AssumeRolePolicyDocument of a role",
        ["iam:UpdateAssumeRolePolicy", "sts:AssumeRole"],
    ),
]


def matches(pattern: str, action: str) -> bool:
    regex = re.escape(pattern.lower()).replace(r"\*", ".*").replace(r"\?", ".")
    return re.fullmatch(regex, action.lower()) is not None


def policy_documents(entity: dict) -> list[dict] | None:
    """Every policy document that applies to the entity, or None if any is unknown."""
    attributes = entity["attributes"]
    if entity["resource_type"] == "IAM Policy":
        document = attributes.get("document")
        return None if document is None else [document]

    attached = attributes.get("attached_policies")
    inline = attributes.get("inline_policies")
    if attached is None or inline is None:
        return None
    documents = [policy.get("document") for policy in attached + inline]
    if any(document is None for document in documents):
        return None
    return documents


def split_statements(documents: list[dict]) -> tuple[list[dict], list[dict]]:
    # NotAction and NotResource statements are skipped: they cannot be matched against a
    # permission without knowing every action. Only a Deny that applies to every resource and
    # has no Condition is allowed to cancel a grant.
    allows, denies = [], []
    for document in documents:
        for statement in statements(document):
            if "NotAction" in statement or "NotResource" in statement:
                continue
            if statement.get("Effect") == "Allow":
                allows.append(statement)
            elif statement.get("Effect") == "Deny":
                if "Condition" not in statement and "*" in as_list(statement.get("Resource")):
                    denies.append(statement)
    return allows, denies


def grant_details(needed: list[str], allows: list[dict], denies: list[dict]) -> dict | None:
    granting_per_permission = []
    for permission in needed:
        if any(matches(p, permission) for d in denies for p in as_list(d.get("Action"))):
            return None
        granting = [
            s for s in allows if any(matches(p, permission) for p in as_list(s.get("Action")))
        ]
        if not granting:
            return None
        granting_per_permission.append(granting)

    everywhere = all(
        any("*" in as_list(s.get("Resource")) for s in granting)
        for granting in granting_per_permission
    )
    limited_to = set()
    for granting in granting_per_permission:
        for statement in granting:
            limited_to.update(r for r in as_list(statement.get("Resource")) if r != "*")
    return {
        "permissions": needed,
        "limited_to_resources": None if everywhere else sorted(limited_to),
        "conditional": any(
            all("Condition" in s for s in granting) for granting in granting_per_permission
        ),
    }


def check_privilege_escalation(resources: list[dict]) -> list[Hit]:
    hits = []
    for entity in of_type(resources, "IAM Policy") + of_type(resources, "IAM Role"):
        documents = policy_documents(entity)
        if documents is None:
            continue
        allows, denies = split_statements(documents)
        matched = []
        for method, needed in METHODS:
            details = grant_details(needed, allows, denies)
            if details:
                matched.append({"method": method, **details})
        if not matched:
            continue
        details = {"methods": matched}
        if any("*" in as_list(statement.get("Action")) for statement in allows):
            details["note"] = (
                'Action "*" allows every action, so it implies all methods that no Deny cancels.'
            )
        hits.append(Hit(entity, details))
    return hits


RULES = [
    Rule(
        id="SX-IAM-PRIVESC-001",
        title="IAM permissions allow privilege escalation",
        severity="HIGH",
        category="Identity",
        description=(
            "The policy, or the role's attached and inline policies together, allow every "
            "permission of at least one known IAM privilege escalation method from the public "
            "Rhino Security Labs catalogue. There is one finding per policy or role, and "
            "details.methods lists each matched method with its permissions. Wildcards are "
            "expanded, and an unconditional Deny on all resources cancels a grant. Each method "
            "says when the grant is limited to specific resources or has a Condition. A policy "
            'with Action "*" matches every method, and CIS-IAM-001 reports it too. NotAction '
            "and NotResource statements are skipped, and a role is skipped when any of its "
            "policies could not be read."
        ),
        fix="Remove the permissions, or limit them to specific resources and add conditions.",
        check=check_privilege_escalation,
    ),
]
