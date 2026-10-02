import boto3
from moto import mock_aws

from cloudshield.scanner.ec2 import collect_instances
from cloudshield.scanner.security_groups import collect_security_groups

TRUST = '{"Version":"2012-10-17","Statement":[]}'


def make_session():
    return boto3.Session(region_name="us-east-1")


def run_instance(ec2, **kwargs) -> str:
    result = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1, **kwargs)
    return result["Instances"][0]["InstanceId"]


@mock_aws
def test_region_with_no_instances_gives_no_resources_and_no_errors():
    errors = []

    resources = collect_instances(make_session(), "us-west-2", errors)

    assert resources == []
    assert errors == []


@mock_aws
def test_instance_without_profile_has_profile_arn_none():
    ec2 = make_session().client("ec2")
    instance_id = run_instance(ec2)
    errors = []

    resources = collect_instances(make_session(), "us-east-1", errors)

    assert errors == []
    assert resources[0]["resource_id"] == instance_id
    assert resources[0]["resource_type"] == "EC2"
    assert resources[0]["region"] == "us-east-1"
    assert resources[0]["attributes"]["instance_profile_arn"] is None
    assert resources[0]["attributes"]["state"] == "running"
    assert isinstance(resources[0]["attributes"]["has_public_ip"], bool)


@mock_aws
def test_instance_with_profile_has_arn_and_security_groups():
    session = make_session()
    iam = session.client("iam")
    iam.create_role(RoleName="app-role", AssumeRolePolicyDocument=TRUST)
    iam.create_instance_profile(InstanceProfileName="app-profile")
    iam.add_role_to_instance_profile(InstanceProfileName="app-profile", RoleName="app-role")
    profile = iam.get_instance_profile(InstanceProfileName="app-profile")["InstanceProfile"]
    profile_arn = profile["Arn"]
    ec2 = session.client("ec2")
    group_id = ec2.create_security_group(GroupName="web", Description="web")["GroupId"]
    run_instance(ec2, IamInstanceProfile={"Arn": profile_arn}, SecurityGroupIds=[group_id])
    errors = []

    resources = collect_instances(session, "us-east-1", errors)

    assert errors == []
    assert resources[0]["attributes"]["instance_profile_arn"] == profile_arn
    assert resources[0]["attributes"]["security_group_ids"] == [group_id]


@mock_aws
def test_security_group_rules_are_returned_as_aws_gave_them():
    ec2 = make_session().client("ec2")
    group_id = ec2.create_security_group(GroupName="ssh", Description="ssh")["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )
    errors = []

    resources = collect_security_groups(make_session(), "us-east-1", errors)

    group = next(r for r in resources if r["resource_id"] == group_id)
    assert errors == []
    assert group["resource_type"] == "Security Group"
    assert group["name"] == "ssh"
    assert group["attributes"]["inbound"][0]["FromPort"] == 22
    assert group["attributes"]["inbound"][0]["IpRanges"] == [{"CidrIp": "0.0.0.0/0"}]
    assert group["attributes"]["outbound"]


@mock_aws
def test_access_denied_describing_instances_is_an_error_not_an_empty_region(deny):
    deny("DescribeInstances")
    errors = []

    resources = collect_instances(make_session(), "us-east-1", errors)

    assert resources == []
    assert len(errors) == 1
    assert errors[0]["service"] == "ec2"
    assert errors[0]["region"] == "us-east-1"