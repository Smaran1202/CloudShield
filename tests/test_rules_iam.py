from cloudshield.rules.iam import check_wildcard_policies
from cloudshield.scanner.common import make_resource


def policy(document=None) -> dict:
    attributes = {} if document is None else {"document": document}
    arn = "arn:aws:iam::123456789012:policy/p"
    return make_resource(arn, "IAM Policy", None, "p", attributes)


def allow(action, resource, **extra) -> dict:
    return {"Effect": "Allow", "Action": action, "Resource": resource, **extra}


def document(*statements) -> dict:
    return {"Version": "2012-10-17", "Statement": list(statements)}


def test_action_star_is_a_high_finding():
    hits = check_wildcard_policies([policy(document(allow("*", "arn:aws:s3:::b")))])

    assert len(hits) == 1
    assert hits[0].severity == "HIGH"
    assert hits[0].details["statements"][0]["action_wildcard"] is True
    assert hits[0].details["statements"][0]["resource_wildcard"] is False


def test_resource_star_with_a_write_action_is_a_medium_finding():
    hits = check_wildcard_policies([policy(document(allow("s3:PutObject", "*")))])

    assert len(hits) == 1
    assert hits[0].severity == "MEDIUM"
    assert hits[0].details["statements"][0]["resource_wildcard"] is True
    assert hits[0].details["statements"][0]["non_read_only_actions"] == ["s3:PutObject"]


def test_resource_star_with_only_read_only_actions_is_not_a_finding():
    actions = ["s3:GetObject", "s3:List*", "ec2:Describe*", "iam:GetPolicy"]

    assert check_wildcard_policies([policy(document(allow(actions, "*")))]) == []


def test_resource_star_with_an_allowlisted_read_action_is_not_a_finding():
    actions = ["dynamodb:Query", "dynamodb:Scan", "logs:FilterLogEvents"]

    assert check_wildcard_policies([policy(document(allow(actions, "*")))]) == []


def test_resource_star_lists_only_the_non_read_only_actions():
    actions = ["s3:GetObject", "s3:DeleteObject", "ec2:Describe*"]

    hits = check_wildcard_policies([policy(document(allow(actions, "*")))])

    assert hits[0].details["statements"][0]["non_read_only_actions"] == ["s3:DeleteObject"]


def test_service_wildcard_action_on_all_resources_counts_as_not_read_only():
    hits = check_wildcard_policies([policy(document(allow("s3:*", "*")))])

    assert hits[0].severity == "MEDIUM"


def test_action_star_and_a_resource_star_statement_together_are_high():
    hits = check_wildcard_policies(
        [policy(document(allow("s3:PutObject", "*"), allow("*", "arn:aws:s3:::b")))]
    )

    assert len(hits) == 1
    assert hits[0].severity == "HIGH"
    assert len(hits[0].details["statements"]) == 2


def test_wildcards_inside_lists_are_found():
    statement = allow(["s3:GetObject", "*"], ["arn:aws:s3:::b", "*"])

    hits = check_wildcard_policies([policy(document(statement))])

    assert hits[0].details["statements"][0]["action_wildcard"] is True
    assert hits[0].details["statements"][0]["resource_wildcard"] is True


def test_statement_given_as_a_single_dict_is_handled():
    single = {"Version": "2012-10-17", "Statement": allow("*", "*")}

    assert len(check_wildcard_policies([policy(single)])) == 1


def test_specific_actions_and_resources_have_no_finding():
    statement = allow(["s3:GetObject"], "arn:aws:s3:::b/*")

    assert check_wildcard_policies([policy(document(statement))]) == []


def test_deny_with_wildcards_is_not_a_finding():
    statement = {"Effect": "Deny", "Action": "*", "Resource": "*"}

    assert check_wildcard_policies([policy(document(statement))]) == []


def test_not_action_and_not_resource_statements_are_skipped():
    not_action = {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}
    not_resource = {"Effect": "Allow", "Action": "*", "NotResource": "arn:aws:s3:::b"}

    assert check_wildcard_policies([policy(document(not_action, not_resource))]) == []


def test_policy_with_unknown_document_is_not_a_finding():
    assert check_wildcard_policies([policy()]) == []


def test_only_the_wildcard_statements_are_listed():
    safe = allow("s3:GetObject", "arn:aws:s3:::b/*")
    risky = allow("*", "*", Sid="Everything")

    hits = check_wildcard_policies([policy(document(safe, risky))])

    assert [s["statement_index"] for s in hits[0].details["statements"]] == [1]
    assert hits[0].details["statements"][0]["sid"] == "Everything"
