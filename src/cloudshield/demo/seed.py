import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

import boto3
from alembic import command
from alembic.config import Config
from moto import mock_aws
from sqlalchemy.orm import Session, sessionmaker

import cloudshield.db
from cloudshield.api.jobs import run_scan_job
from cloudshield.db import store
from cloudshield.db.models import ACCOUNT_ID, ScanRow
from cloudshield.db.session import make_engine, make_session_factory
from cloudshield.demo.synthetic import ACCOUNT, FILE_NAME, REGION, demo_file
from cloudshield.imports.importer import import_parsed
from cloudshield.imports.parser import parse_bytes
from cloudshield.scanner.scan import scan_account

REGIONS = [REGION]
DATA_LABEL = (
    "Demo data: a made-up AWS account built with moto and a hand-written imported file. "
    "Nothing here is from a real account."
)
WEAK_BUCKETS = ["demo-public-site", "demo-app-data", "demo-fixed-bucket"]
GOOD_BUCKET = "demo-backups"
TRUST = json.dumps({"Version": "2012-10-17", "Statement": []})
BLOCK_ALL = dict.fromkeys(
    ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"), True
)


def policy(actions: str | list[str]) -> str:
    statement = {"Effect": "Allow", "Action": actions, "Resource": "*"}
    return json.dumps({"Version": "2012-10-17", "Statement": [statement]})


@contextmanager
def fake_aws() -> Iterator[None]:
    """Every AWS call goes to moto. The credential files point at nothing, so a profile on this
    computer can never be picked up."""
    fake = {
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
        "AWS_DEFAULT_REGION": REGION,
        "AWS_EC2_METADATA_DISABLED": "true",
        "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
        "AWS_CONFIG_FILE": os.devnull,
    }
    with patch.dict(os.environ, fake):
        for name in ("AWS_PROFILE", "AWS_SESSION_TOKEN"):
            os.environ.pop(name, None)
        with mock_aws():
            yield


def protect_bucket(s3, name: str) -> None:
    s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration=BLOCK_ALL)
    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
    rule = {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}
    s3.put_bucket_encryption(Bucket=name, ServerSideEncryptionConfiguration={"Rules": [rule]})


def build_account(session: boto3.Session) -> None:
    account = session.client("sts").get_caller_identity()["Account"]
    if account != ACCOUNT:
        raise RuntimeError(f"moto uses account {account}, but the demo file says {ACCOUNT}.")

    s3 = session.client("s3")
    for name in [*WEAK_BUCKETS, GOOD_BUCKET]:
        s3.create_bucket(Bucket=name)
    protect_bucket(s3, GOOD_BUCKET)
    # The account-wide block is on, so the buckets with no block of their own are mitigated.
    session.client("s3control").put_public_access_block(
        AccountId=account, PublicAccessBlockConfiguration=BLOCK_ALL
    )

    ec2 = session.client("ec2")
    open_ssh = {
        "IpProtocol": "tcp",
        "FromPort": 22,
        "ToPort": 22,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
    }
    groups = {}
    for name in ("demo-open-ssh", "demo-open-unused"):
        made = ec2.create_security_group(GroupName=name, Description="open on purpose, demo")
        ec2.authorize_security_group_ingress(GroupId=made["GroupId"], IpPermissions=[open_ssh])
        groups[name] = made["GroupId"]

    iam = session.client("iam")
    admin = iam.create_policy(PolicyName="demo-admin-all", PolicyDocument=policy("*"))
    pass_role = iam.create_policy(
        PolicyName="demo-pass-role", PolicyDocument=policy(["iam:PassRole", "ec2:RunInstances"])
    )
    iam.create_policy(PolicyName="demo-unused-admin", PolicyDocument=policy("*"))
    iam.create_role(RoleName="demo-app-role", AssumeRolePolicyDocument=TRUST)
    for made in (admin, pass_role):
        iam.attach_role_policy(RoleName="demo-app-role", PolicyArn=made["Policy"]["Arn"])
    iam.put_role_policy(
        RoleName="demo-app-role",
        PolicyName="demo-inline",
        PolicyDocument=policy("iam:AttachRolePolicy"),
    )
    iam.create_instance_profile(InstanceProfileName="demo-app-profile")
    iam.add_role_to_instance_profile(
        InstanceProfileName="demo-app-profile", RoleName="demo-app-role"
    )
    profile = iam.get_instance_profile(InstanceProfileName="demo-app-profile")["InstanceProfile"]
    ec2.run_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
        SecurityGroupIds=[groups["demo-open-ssh"]],
        IamInstanceProfile={"Arn": profile["Arn"]},
    )


def scan_demo_account(regions: list[str]) -> dict:
    return scan_account(boto3.Session(region_name=REGION), regions)


def run_demo_scan(factory: sessionmaker[Session]) -> None:
    """The real scan job, rules and scoring, against the fake account."""
    with factory() as session:
        scan = store.create_scan(session, REGIONS)
        scan.data_label = DATA_LABEL
        session.commit()
        scan_id = scan.id
    run_scan_job(factory, scan_id, REGIONS, scan_demo_account)
    with factory() as session:
        scan = session.get(ScanRow, scan_id)
        if scan.status != "completed":
            raise RuntimeError(f"The demo scan did not complete: {scan.failure_message}")


def migrate(database_url: str) -> None:
    config = Config()
    migrations = Path(cloudshield.db.__file__).parent / "migrations"
    config.set_main_option("script_location", str(migrations))
    # migrations/env.py reads the database from the settings.
    with patch.dict(os.environ, {"DATABASE_URL": database_url}):
        command.upgrade(config, "head")


def seed(path: Path) -> None:
    """Builds a demo database at path. The file must not exist."""
    url = f"sqlite:///{path.resolve()}"
    migrate(url)
    engine = make_engine(url)
    factory = make_session_factory(engine)
    with fake_aws():
        session = boto3.Session(region_name=REGION)
        build_account(session)
        run_demo_scan(factory)
        # The simulated fix: the owner turned on the three settings of one bucket.
        protect_bucket(session.client("s3"), "demo-fixed-bucket")
        run_demo_scan(factory)
    with factory() as db:
        import_parsed(db, parse_bytes(demo_file()), ACCOUNT_ID, FILE_NAME)
    engine.dispose()
