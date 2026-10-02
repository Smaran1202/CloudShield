from cloudshield.rules.privesc import METHODS, check_privilege_escalation
from cloudshield.scanner.common import make_resource

POLICY_ARN = "arn:aws:iam::123456789012:policy/p"
ROLE_ARN = "arn:aws:iam::123456789012:role/r"


def policy(*statements) -> dict:
    document = {"Version": "2012-10-17", "Statement": list(statements)}
    return make_resource(POLICY_ARN, "IAM Policy", None, "p", {"document": document})


def role(attached=(), inline=()) -> dict:
    def entry(statements) -> dict:
        return {"name": "x", "document": {"Statement": list(statements)}}

    attributes = {
        "attached_policies": [entry(s) for s in attached],
        "inline_policies": [entry(s) for s in inline],
    }
    return make_resource(ROLE_ARN, "IAM Role", None, "r", attributes)


def allow(actions, resource="*", **extra) -> dict:
    return {"Effect": "Allow", "Action": actions, "Resource": resource, **extra}


def deny(actions, resource="*", **extra) -> dict:
    return {"Effect": "Deny", "Action": actions, "Resource": resource, **extra}


def methods_found(resource: dict) -> list[str]:
    hits = check_privilege_escalation([resource])
    return [m["method"] for hit in hits for m in hit.details["methods"]]


def test_single_permission_method_is_found_with_its_permissions():
    hits = check_privilege_escalation([policy(allow("iam:CreatePolicyVersion"))])

    method = hits[0].details["methods"][0]
    assert len(hits) == 1
    assert method["method"] == "Creating a new policy version"
    assert method["permissions"] == ["iam:CreatePolicyVersion"]
    assert method["limited_to_resources"] is None
    assert method["conditional"] is False
    assert "note" not in hits[0].details


def test_many_matching_methods_give_one_finding_per_policy():
    hits = check_privilege_escalation([policy(allow("iam:*"))])

    assert len(hits) == 1
    assert len(hits[0].details["methods"]) > 5
    assert hits[0].variant == ""


def test_full_wildcard_finding_says_it_implies_all_methods():
    hits = check_privilege_escalation([policy(allow("*"))])

    assert len(hits) == 1
    assert len(hits[0].details["methods"]) == len(METHODS)
    assert "implies all methods" in hits[0].details["note"]


def test_pass_role_alone_is_not_a_finding():
    assert methods_found(policy(allow("iam:PassRole"))) == []


def test_run_instances_alone_is_not_a_finding():
    assert methods_found(policy(allow("ec2:RunInstances"))) == []


def test_pass_role_with_run_instances_is_a_finding():
    found = methods_found(policy(allow(["iam:PassRole", "ec2:RunInstances"])))

    assert found == ["Creating an EC2 instance with an existing instance profile"]


def test_lambda_combination_needs_all_three_permissions():
    two = policy(allow(["iam:PassRole", "lambda:CreateFunction"]))
    three = policy(allow(["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"]))

    assert methods_found(two) == []
    assert methods_found(three) == ["Passing a role to a new Lambda function, then invoking it"]


def test_update_assume_role_policy_needs_assume_role_too():
    only_update = policy(allow("iam:UpdateAssumeRolePolicy"))
    both = policy(allow(["iam:UpdateAssumeRolePolicy", "sts:AssumeRole"]))

    assert methods_found(only_update) == []
    assert methods_found(both) == ["Updating the AssumeRolePolicyDocument of a role"]


def test_service_wildcard_expands_to_the_iam_methods_only():
    found = methods_found(policy(allow("iam:*")))

    assert "Creating a new policy version" in found
    assert "Creating a new user access key" in found
    assert "Creating an EC2 instance with an existing instance profile" not in found


def test_partial_wildcard_matches_by_prefix():
    found = methods_found(policy(allow("iam:Attach*Policy")))

    assert found == [
        "Attaching a policy to a user",
        "Attaching a policy to a group",
        "Attaching a policy to a role",
    ]


def test_full_wildcard_finds_every_method():
    assert len(methods_found(policy(allow("*")))) == len(METHODS)


def test_matching_ignores_case():
    assert methods_found(policy(allow("IAM:createaccesskey"))) == ["Creating a new user access key"]


def test_explicit_deny_cancels_the_denied_method_only():
    found = methods_found(policy(allow("iam:*"), deny("iam:CreateAccessKey")))

    assert "Creating a new user access key" not in found
    assert "Creating a new policy version" in found


def test_deny_with_service_wildcard_cancels_every_method_that_needs_an_iam_action():
    assert methods_found(policy(allow("*"), deny("iam:*"))) == []


def test_deny_limited_to_one_resource_does_not_cancel_the_grant():
    scoped_deny = deny("iam:CreateAccessKey", resource="arn:aws:iam::123456789012:user/safe")

    found = methods_found(policy(allow("iam:CreateAccessKey"), scoped_deny))

    assert found == ["Creating a new user access key"]


def test_deny_with_a_condition_does_not_cancel_the_grant():
    condition = {"Bool": {"aws:MultiFactorAuthPresent": "false"}}
    conditional = deny("iam:CreateAccessKey", Condition=condition)

    assert methods_found(policy(allow("iam:CreateAccessKey"), conditional)) == [
        "Creating a new user access key"
    ]


def test_grant_limited_to_specific_resources_says_so():
    arn = "arn:aws:iam::123456789012:policy/target"

    hits = check_privilege_escalation([policy(allow("iam:CreatePolicyVersion", resource=arn))])

    assert hits[0].details["methods"][0]["limited_to_resources"] == [arn]


def test_grant_with_a_condition_is_marked_conditional():
    condition = {"StringEquals": {"aws:RequestedRegion": "ap-southeast-2"}}
    statement = allow("iam:CreateAccessKey", Condition=condition)

    hits = check_privilege_escalation([policy(statement)])

    assert hits[0].details["methods"][0]["conditional"] is True


def test_not_action_statements_are_skipped():
    statement = {"Effect": "Allow", "NotAction": "s3:*", "Resource": "*"}

    assert methods_found(policy(statement)) == []


def test_single_dict_statement_and_string_action_are_handled():
    document = {"Statement": allow("iam:CreateAccessKey")}
    resource = make_resource(POLICY_ARN, "IAM Policy", None, "p", {"document": document})

    assert methods_found(resource) == ["Creating a new user access key"]


def test_role_combines_attached_and_inline_policies():
    resource = role(attached=[[allow("iam:PassRole")]], inline=[[allow("ec2:RunInstances")]])

    hits = check_privilege_escalation([resource])

    assert len(hits) == 1
    assert hits[0].resource["resource_type"] == "IAM Role"


def test_deny_in_one_role_policy_cancels_a_grant_in_another():
    resource = role(attached=[[allow("*")]], inline=[[deny("iam:CreateAccessKey")]])

    assert "Creating a new user access key" not in methods_found(resource)


def test_role_with_unknown_attached_policies_is_not_a_finding():
    resource = role(inline=[[allow("*")]])
    del resource["attributes"]["attached_policies"]

    assert methods_found(resource) == []


def test_role_with_an_unreadable_policy_document_is_not_a_finding():
    resource = role(attached=[[allow("*")]])
    del resource["attributes"]["attached_policies"][0]["document"]

    assert methods_found(resource) == []


def test_role_with_no_policies_is_not_a_finding():
    assert methods_found(role()) == []


def test_policy_with_unknown_document_is_not_a_finding():
    resource = make_resource(POLICY_ARN, "IAM Policy", None, "p", {})

    assert methods_found(resource) == []
