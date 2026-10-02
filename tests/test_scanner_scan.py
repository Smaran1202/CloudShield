import json

import boto3
from moto import mock_aws

from cloudshield.scanner.__main__ import main
from cloudshield.scanner.scan import scan_account

TRUST = '{"Version":"2012-10-17","Statement":[]}'


def make_session():
    return boto3.Session(region_name="us-east-1")


@mock_aws
def test_scan_account_returns_resources_of_every_type():
    session = make_session()
    session.client("s3").create_bucket(Bucket="scan-bucket")
    iam = session.client("iam")
    iam.create_role(RoleName="app-role", AssumeRolePolicyDocument=TRUST)
    iam.create_instance_profile(InstanceProfileName="app-profile")
    iam.add_role_to_instance_profile(InstanceProfileName="app-profile", RoleName="app-role")
    profile = iam.get_instance_profile(InstanceProfileName="app-profile")["InstanceProfile"]
    profile_arn = profile["Arn"]
    session.client("ec2").run_instances(
        ImageId="ami-12345678", MinCount=1, MaxCount=1, IamInstanceProfile={"Arn": profile_arn}
    )

    result = scan_account(session, ["us-east-1"])

    types = {resource["resource_type"] for resource in result["resources"]}
    assert result["errors"] == []
    assert types == {"S3", "EC2", "Security Group", "IAM Role"}


@mock_aws
def test_failure_in_one_service_does_not_stop_the_others(deny):
    session = make_session()
    session.client("s3").create_bucket(Bucket="scan-bucket")
    deny("DescribeSecurityGroups")

    result = scan_account(session, ["us-east-1"])

    types = {resource["resource_type"] for resource in result["resources"]}
    assert "S3" in types
    assert "Security Group" not in types
    assert len(result["errors"]) == 1
    assert result["errors"][0]["service"] == "ec2"


@mock_aws
def test_scan_covers_every_region_given():
    session = make_session()
    session.client("ec2", region_name="us-west-2").run_instances(
        ImageId="ami-12345678", MinCount=1, MaxCount=1
    )

    result = scan_account(session, ["us-east-1", "us-west-2"])

    instances = [r for r in result["resources"] if r["resource_type"] == "EC2"]
    assert [i["region"] for i in instances] == ["us-west-2"]


@mock_aws
def test_cli_prints_counts_and_writes_the_output_file(tmp_path, capsys):
    make_session().client("s3").create_bucket(Bucket="cli-bucket")
    out_file = tmp_path / "scan-output.json"

    exit_code = main(["--regions", "us-east-1", "--out", str(out_file)])

    printed = capsys.readouterr().out
    saved = json.loads(out_file.read_text(encoding="utf-8"))
    assert exit_code == 0
    assert "S3: 1" in printed
    assert "Errors: 0" in printed
    assert saved["resources"][0]["name"] == "cli-bucket"
