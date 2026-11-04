import json
import shutil
from pathlib import Path
from unittest.mock import patch

import boto3
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from cloudshield.db import store
from cloudshield.db.models import ACCOUNT_ID, Base, FindingRow
from cloudshield.db.session import make_engine, make_session_factory
from cloudshield.risk.scoring import score_findings
from cloudshield.rules import ALL_RULES, run_rules
from cloudshield.scanner.scan import scan_account

REGIONS = ["us-east-1"]
ACCOUNT = "123456789012"  # the account id moto uses
BUCKET = "e1-bucket"
TRUST = json.dumps({"Version": "2012-10-17", "Statement": []})
EVERYTHING = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}
PASS_ROLE = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": ["iam:PassRole", "ec2:RunInstances"], "Resource": "*"}
    ],
}
ATTACH_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "iam:AttachRolePolicy", "Resource": "*"}],
}


def build_world() -> dict:
    """Fake resources (in moto) that break every one of CloudShield's own rules. Returns the ids
    that the experiments need."""
    session = boto3.Session(region_name="us-east-1")
    session.client("s3").create_bucket(Bucket=BUCKET)

    ec2 = session.client("ec2")
    created = ec2.create_security_group(GroupName="e1-open", Description="open on purpose")
    group_id = created["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
            },
            {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        ],
    )

    iam = session.client("iam")
    wildcard = iam.create_policy(PolicyName="e1-wildcard", PolicyDocument=json.dumps(EVERYTHING))
    pass_role = iam.create_policy(PolicyName="e1-passrole", PolicyDocument=json.dumps(PASS_ROLE))
    iam.create_role(RoleName="e1-role", AssumeRolePolicyDocument=TRUST)
    iam.attach_role_policy(RoleName="e1-role", PolicyArn=pass_role["Policy"]["Arn"])
    iam.put_role_policy(
        RoleName="e1-role", PolicyName="e1-inline", PolicyDocument=json.dumps(ATTACH_POLICY)
    )
    iam.create_instance_profile(InstanceProfileName="e1-profile")
    iam.add_role_to_instance_profile(InstanceProfileName="e1-profile", RoleName="e1-role")
    profile = iam.get_instance_profile(InstanceProfileName="e1-profile")["InstanceProfile"]
    ec2.run_instances(
        ImageId="ami-12345678", MinCount=1, MaxCount=1, IamInstanceProfile={"Arn": profile["Arn"]}
    )
    return {
        "group_id": group_id,
        "wildcard_arn": wildcard["Policy"]["Arn"],
        "pass_role_arn": pass_role["Policy"]["Arn"],
    }


def fix_bucket() -> None:
    """Really fixes the three S3 findings of the bucket, so a later scan finds them gone."""
    s3 = boto3.Session(region_name="us-east-1").client("s3")
    s3.put_public_access_block(
        Bucket=BUCKET,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_versioning(Bucket=BUCKET, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_encryption(
        Bucket=BUCKET,
        ServerSideEncryptionConfiguration={
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "aws:kms",
                        "KMSMasterKeyID": "alias/e1-key",
                    }
                }
            ]
        },
    )


def scan_world() -> dict:
    return scan_account(boto3.Session(region_name="us-east-1"), REGIONS)


def new_database(path: Path) -> sessionmaker[Session]:
    engine = make_engine(f"sqlite:///{path}")
    Base.metadata.create_all(engine)
    return make_session_factory(engine)


def copy_database(source: Path, target: Path) -> sessionmaker[Session]:
    shutil.copyfile(source, target)
    return make_session_factory(make_engine(f"sqlite:///{target}"))


def close_database(factory: sessionmaker[Session]) -> None:
    factory.kw["bind"].dispose()


def open_finding_ids(session: Session, source: str) -> set[str]:
    query = select(FindingRow.finding_id).where(
        FindingRow.account_id == ACCOUNT_ID,
        FindingRow.source == source,
        FindingRow.status == "OPEN",
        FindingRow.merged_into.is_(None),
    )
    return set(session.scalars(query).all())


def save_scan(session: Session, result: dict, resolver=None) -> None:
    """Runs the rules on a scan result and saves it, the way the scan job does. With a resolver,
    that function stands in for store.resolve_fixed."""
    findings = score_findings(run_rules(result["resources"]), result, REGIONS)
    scan = store.create_scan(session, REGIONS)
    with patch.object(store, "resolve_fixed", resolver or store.resolve_fixed):
        store.save_result(session, scan.id, result, findings)


def make_baseline(path: Path) -> set[str]:
    """Saves a clean scan of the world. Returns the ids of the open findings, and fails if any of
    our own rules has none, because the experiment needs every rule to start with a finding."""
    factory = new_database(path)
    with factory() as session:
        result = scan_world()
        if result["errors"]:
            raise RuntimeError(f"The baseline scan had errors: {result['errors']}")
        save_scan(session, result)
        open_ids = open_finding_ids(session, "cloudshield")
        query = select(FindingRow.rule_id).where(FindingRow.status == "OPEN")
        rules = set(session.scalars(query).all())
    missing = {rule.id for rule in ALL_RULES} - rules
    if missing:
        raise RuntimeError(f"No open finding for these rules at the start: {sorted(missing)}")
    return open_ids
