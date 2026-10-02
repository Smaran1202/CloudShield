import json

import boto3
from moto import mock_aws

from cloudshield.scanner.common import list_all
from cloudshield.scanner.iam import collect_policies, collect_roles

TRUST = '{"Version":"2012-10-17","Statement":[]}'
DOCUMENT = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}],
}


def make_session():
    return boto3.Session(region_name="us-east-1")


def make_role_with_profile(iam, role_name: str) -> str:
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=TRUST)
    iam.create_instance_profile(InstanceProfileName=role_name)
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    return iam.get_instance_profile(InstanceProfileName=role_name)["InstanceProfile"]["Arn"]


@mock_aws
def test_customer_policy_is_returned_with_its_default_version_document():
    iam = make_session().client("iam")
    iam.create_policy(PolicyName="list-buckets", PolicyDocument=json.dumps(DOCUMENT))
    errors = []

    resources = collect_policies(make_session(), errors)

    assert errors == []
    assert len(resources) == 1
    assert resources[0]["resource_type"] == "IAM Policy"
    assert resources[0]["name"] == "list-buckets"
    assert resources[0]["region"] is None
    assert resources[0]["attributes"]["document"] == DOCUMENT


@mock_aws
def test_policy_records_the_users_roles_and_groups_it_is_attached_to():
    iam = make_session().client("iam")
    policy = iam.create_policy(PolicyName="shared", PolicyDocument=json.dumps(DOCUMENT))
    policy_arn = policy["Policy"]["Arn"]
    iam.create_user(UserName="alice")
    iam.attach_user_policy(UserName="alice", PolicyArn=policy_arn)
    iam.create_role(RoleName="app-role", AssumeRolePolicyDocument=TRUST)
    iam.attach_role_policy(RoleName="app-role", PolicyArn=policy_arn)
    iam.create_group(GroupName="admins")
    iam.attach_group_policy(GroupName="admins", PolicyArn=policy_arn)
    errors = []

    resources = collect_policies(make_session(), errors)

    assert errors == []
    assert resources[0]["attributes"]["attached_to"] == {
        "users": ["alice"],
        "roles": ["app-role"],
        "groups": ["admins"],
    }


@mock_aws
def test_unattached_policy_has_empty_attachment_lists_not_missing_keys():
    iam = make_session().client("iam")
    iam.create_policy(PolicyName="lonely", PolicyDocument=json.dumps(DOCUMENT))
    errors = []

    resources = collect_policies(make_session(), errors)

    assert errors == []
    assert resources[0]["attributes"]["attached_to"] == {"users": [], "roles": [], "groups": []}


@mock_aws
def test_access_denied_on_attachments_is_an_error_not_unattached(deny):
    iam = make_session().client("iam")
    iam.create_policy(PolicyName="shared", PolicyDocument=json.dumps(DOCUMENT))
    deny("ListEntitiesForPolicy")
    errors = []

    resources = collect_policies(make_session(), errors)

    assert len(errors) == 1
    assert errors[0]["service"] == "iam"
    assert "AccessDenied" in errors[0]["message"]
    assert "attached_to" not in resources[0]["attributes"]
    assert resources[0]["attributes"]["document"] == DOCUMENT


@mock_aws
def test_list_all_follows_every_page():
    iam = make_session().client("iam")
    for number in range(5):
        iam.create_policy(PolicyName=f"policy-{number}", PolicyDocument=json.dumps(DOCUMENT))

    policies = list_all(
        iam, "list_policies", "Policies", Scope="Local", PaginationConfig={"PageSize": 2}
    )

    assert len(policies) == 5


@mock_aws
def test_role_has_attached_and_inline_policy_documents():
    iam = make_session().client("iam")
    profile_arn = make_role_with_profile(iam, "app-role")
    policy = iam.create_policy(PolicyName="managed", PolicyDocument=json.dumps(DOCUMENT))
    policy_arn = policy["Policy"]["Arn"]
    iam.attach_role_policy(RoleName="app-role", PolicyArn=policy_arn)
    iam.put_role_policy(
        RoleName="app-role", PolicyName="inline", PolicyDocument=json.dumps(DOCUMENT)
    )
    errors = []

    resources = collect_roles(make_session(), [profile_arn], errors)

    attributes = resources[0]["attributes"]
    assert errors == []
    assert resources[0]["resource_type"] == "IAM Role"
    assert resources[0]["name"] == "app-role"
    assert attributes["instance_profile_arns"] == [profile_arn]
    assert attributes["attached_policies"] == [
        {"name": "managed", "arn": policy_arn, "document": DOCUMENT}
    ]
    assert attributes["inline_policies"] == [{"name": "inline", "document": DOCUMENT}]


@mock_aws
def test_role_with_no_policies_has_empty_lists_not_missing_keys():
    iam = make_session().client("iam")
    profile_arn = make_role_with_profile(iam, "bare-role")
    errors = []

    resources = collect_roles(make_session(), [profile_arn], errors)

    assert errors == []
    assert resources[0]["attributes"]["attached_policies"] == []
    assert resources[0]["attributes"]["inline_policies"] == []


@mock_aws
def test_access_denied_listing_role_policies_is_an_error_not_no_policies(deny):
    iam = make_session().client("iam")
    profile_arn = make_role_with_profile(iam, "app-role")
    iam.put_role_policy(
        RoleName="app-role", PolicyName="inline", PolicyDocument=json.dumps(DOCUMENT)
    )
    deny("ListAttachedRolePolicies")
    errors = []

    resources = collect_roles(make_session(), [profile_arn], errors)

    attributes = resources[0]["attributes"]
    assert len(errors) == 1
    assert errors[0]["service"] == "iam"
    assert "AccessDenied" in errors[0]["message"]
    assert "attached_policies" not in attributes
    assert attributes["inline_policies"] == [{"name": "inline", "document": DOCUMENT}]


@mock_aws
def test_role_shared_by_two_profiles_is_returned_once_with_both_profiles():
    iam = make_session().client("iam")
    first_arn = make_role_with_profile(iam, "shared-role")
    iam.create_instance_profile(InstanceProfileName="second-profile")
    iam.add_role_to_instance_profile(InstanceProfileName="second-profile", RoleName="shared-role")
    second = iam.get_instance_profile(InstanceProfileName="second-profile")["InstanceProfile"]
    second_arn = second["Arn"]
    errors = []

    resources = collect_roles(make_session(), [first_arn, second_arn, first_arn], errors)

    assert len(resources) == 1
    assert sorted(resources[0]["attributes"]["instance_profile_arns"]) == sorted(
        [first_arn, second_arn]
    )
