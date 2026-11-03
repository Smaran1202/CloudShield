from cloudshield.findings import make_finding_id
from cloudshield.rules import run_rules
from cloudshield.rules.iam import RULES, check_wildcard_policies
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
    actions = ["s3:GetBucketLocation", "s3:List*", "ec2:Describe*", "iam:GetPolicy"]

    assert check_wildcard_policies([policy(document(allow(actions, "*")))]) == []


def test_resource_star_with_an_allowlisted_read_action_is_not_a_finding():
    actions = ["dynamodb:Query", "dynamodb:Scan", "logs:FilterLogEvents"]

    assert check_wildcard_policies([policy(document(allow(actions, "*")))]) == []


def test_resource_star_lists_only_the_non_read_only_actions():
    actions = ["s3:GetBucketLocation", "s3:DeleteObject", "ec2:Describe*"]

    hits = check_wildcard_policies([policy(document(allow(actions, "*")))])

    assert hits[0].details["statements"][0]["non_read_only_actions"] == ["s3:DeleteObject"]


def test_sensitive_get_actions_on_all_resources_are_a_medium_finding():
    sensitive = [
        "secretsmanager:GetSecretValue",
        "ssm:GetParameter",
        "ssm:GetParameters",
        "ssm:GetParametersByPath",
        "ec2:GetPasswordData",
        "s3:GetObject",
    ]

    for action in sensitive:
        hits = check_wildcard_policies([policy(document(allow(action, "*")))])

        assert len(hits) == 1, action
        assert hits[0].severity == "MEDIUM", action
        assert hits[0].details["statements"][0]["non_read_only_actions"] == [action]


def test_get_wildcard_that_includes_a_sensitive_action_is_a_finding():
    for action in ["s3:Get*", "ssm:Get*", "ec2:Get*", "secretsmanager:GetSecret*"]:
        hits = check_wildcard_policies([policy(document(allow(action, "*")))])

        assert len(hits) == 1, action


def test_get_wildcard_with_no_sensitive_action_is_still_read_only():
    assert check_wildcard_policies([policy(document(allow("iam:Get*", "*")))]) == []


def test_sensitive_get_action_limited_to_one_resource_is_not_a_finding():
    statement = allow("s3:GetObject", "arn:aws:s3:::one-bucket/*")

    assert check_wildcard_policies([policy(document(statement))]) == []


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


# the title says which case fired


def finding_for(*statements):
    findings = run_rules([policy(document(*statements))], rules=RULES)
    assert len(findings) == 1
    return findings[0]


def test_action_star_says_it_allows_all_actions():
    finding = finding_for(allow("*", "arn:aws:s3:::b"))

    assert finding.title == "IAM policy allows all actions"
    assert finding.severity == "HIGH"


def test_resource_star_with_a_write_action_says_it_allows_write_actions_on_all_resources():
    finding = finding_for(allow("s3:PutObject", "*"))

    assert finding.title == "IAM policy allows write actions on all resources"
    assert finding.severity == "MEDIUM"


def test_action_star_on_resource_star_is_titled_as_all_actions():
    assert finding_for(allow("*", "*")).title == "IAM policy allows all actions"


def test_a_policy_with_both_cases_is_titled_by_the_more_serious_one():
    finding = finding_for(allow("s3:PutObject", "*"), allow("*", "arn:aws:s3:::b"))

    assert finding.title == "IAM policy allows all actions"
    assert len(finding.details["statements"]) == 2


def test_the_rule_id_and_the_finding_id_do_not_depend_on_the_title():
    arn = "arn:aws:iam::123456789012:policy/p"

    all_actions = finding_for(allow("*", "arn:aws:s3:::b"))
    writes = finding_for(allow("s3:PutObject", "*"))

    assert all_actions.rule_id == writes.rule_id == "CIS-IAM-001"
    assert all_actions.finding_id == writes.finding_id == make_finding_id("CIS-IAM-001", arn)


def test_the_rule_itself_keeps_its_general_title():
    assert RULES[0].title == "IAM policy allows all actions or all resources"