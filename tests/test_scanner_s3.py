import json

import boto3
from moto import mock_aws

from cloudshield.scanner.s3 import collect_buckets


def make_session():
    return boto3.Session(region_name="us-east-1")


@mock_aws
def test_no_buckets_gives_no_resources_and_no_errors():
    errors = []

    resources = collect_buckets(make_session(), errors)

    assert resources == []
    assert errors == []


@mock_aws
def test_bucket_without_policy_has_policy_none_and_is_not_an_error():
    make_session().client("s3").create_bucket(Bucket="plain-bucket")
    errors = []

    resources = collect_buckets(make_session(), errors)

    assert errors == []
    assert resources[0]["resource_type"] == "S3"
    assert resources[0]["region"] == "us-east-1"
    assert resources[0]["attributes"]["policy"] is None
    assert resources[0]["attributes"]["versioning"] == "Disabled"


@mock_aws
def test_bucket_settings_are_collected_in_its_own_region():
    s3 = make_session().client("s3", region_name="eu-west-1")
    s3.create_bucket(
        Bucket="eu-bucket", CreateBucketConfiguration={"LocationConstraint": "eu-west-1"}
    )
    s3.put_public_access_block(
        Bucket="eu-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    )
    s3.put_bucket_encryption(
        Bucket="eu-bucket",
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )
    s3.put_bucket_versioning(Bucket="eu-bucket", VersioningConfiguration={"Status": "Enabled"})
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::eu-bucket/*",
            }
        ],
    }
    s3.put_bucket_policy(Bucket="eu-bucket", Policy=json.dumps(policy))
    errors = []

    resources = collect_buckets(make_session(), errors)

    attributes = resources[0]["attributes"]
    assert errors == []
    assert resources[0]["region"] == "eu-west-1"
    assert attributes["public_access_block"]["BlockPublicPolicy"] is False
    assert attributes["public_access_block"]["BlockPublicAcls"] is True
    algorithm = attributes["encryption"][0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
    assert algorithm == "AES256"
    assert attributes["versioning"] == "Enabled"
    assert attributes["policy"] == policy


@mock_aws
def test_access_denied_on_one_call_is_an_error_and_other_calls_continue(deny):
    make_session().client("s3").create_bucket(Bucket="locked-bucket")
    deny("GetBucketPolicy")
    errors = []

    resources = collect_buckets(make_session(), errors)

    attributes = resources[0]["attributes"]
    assert len(errors) == 1
    assert errors[0]["service"] == "s3"
    assert errors[0]["resource"] == "locked-bucket"
    assert "AccessDenied" in errors[0]["message"]
    assert "policy" not in attributes
    assert attributes["versioning"] == "Disabled"


@mock_aws
def test_access_denied_listing_buckets_is_an_error_not_an_empty_account(deny):
    deny("ListBuckets")
    errors = []

    resources = collect_buckets(make_session(), errors)

    assert resources == []
    assert len(errors) == 1
    assert errors[0]["resource"] is None