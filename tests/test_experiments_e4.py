import csv
import json
import shutil

import pytest

from cloudshield.fixes.templates import build_fix
from cloudshield.rules import run_rules
from experiments import e4, validators
from experiments.e4_fixtures import FIXTURES
from experiments.validators import (
    cfn_lint_installed,
    check_cli,
    check_cloudformation,
    check_terraform,
    check_workflow,
    validate,
)

VERSIONING = "aws s3api put-bucket-versioning --bucket b"
TYPO = "aws s3api put-bucket-versionning --bucket b"
ENABLED = "--versioning-configuration Status=Enabled"
BLOCK = "aws s3api put-public-access-block --bucket b --public-access-block-configuration"
REVOKE = "aws ec2 revoke-security-group-ingress --group-id sg-1 --ip-permissions file://p.json"
GOOD_PERMISSION = [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22}]
GOOD_WORKFLOW = (
    "name: x\non:\n  pull_request:\n"
    "jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
)
GOOD_BUCKET = "Resources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: b\n"
BROKEN_BUCKET = "Resources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties:\n      NoSuch: 1\n"


def file_of(content) -> list[dict]:
    return [{"name": "p.json", "content": content}]


def patch_of(kind: str, content: str = "", instructions_only: bool = False) -> dict:
    return {
        "format": kind,
        "content": content,
        "files": [],
        "instructions_only": instructions_only,
    }


def test_the_cli_check_accepts_a_good_command_with_a_region():
    assert check_cli(f"{VERSIONING} {ENABLED} --region us-east-1\n", []) == ""


def test_the_cli_check_accepts_a_json_file_that_fits_the_shape():
    assert check_cli(REVOKE, file_of(json.dumps(GOOD_PERMISSION))) == ""


def test_the_cli_check_skips_comment_lines_and_checks_every_command():
    content = f"# Rule 1\n{VERSIONING} {ENABLED}\n# Rule 2\n{TYPO} {ENABLED}\n"

    assert "has no operation put-bucket-versionning" in check_cli(content, [])


@pytest.mark.parametrize(
    ("command", "problem"),
    [
        (TYPO, "has no operation"),
        ("aws s3apix put-bucket-versioning --bucket b", "unknown service"),
        (f"{VERSIONING} {ENABLED} --no-such-option x", "is not a parameter"),
        (VERSIONING, "missing required parameters"),
        (f"{VERSIONING} --versioning-configuration Status=Maybe", "is not one of"),
        (f"{VERSIONING} --versioning-configuration Mode=Enabled", "is not a member"),
        (f"{BLOCK} BlockPublicAcls=yes", "must be true or false"),
        (f"{VERSIONING} --versioning-configuration", "cannot read the options"),
        ("echo hello", "not an aws command"),
    ],
)
def test_the_cli_check_rejects_a_broken_command(command, problem):
    assert problem in check_cli(command, [])


@pytest.mark.parametrize(
    ("content", "problem"),
    [
        ("not json", "is not valid JSON"),
        (json.dumps([{"IpProtocol": "tcp", "Port": 22}]), "is not a member of IpPermission"),
        (json.dumps({"IpProtocol": "tcp"}), "must be a list"),
        (json.dumps([{"IpProtocol": "tcp", "FromPort": "22"}]), "must be a whole number"),
    ],
)
def test_the_cli_check_rejects_a_json_file_that_does_not_fit_the_shape(content, problem):
    assert problem in check_cli(REVOKE, file_of(content))


def test_the_cli_check_rejects_a_file_the_patch_does_not_have():
    assert "is not one of the files of the patch" in check_cli(REVOKE, [])


def test_the_workflow_check_accepts_a_workflow():
    assert check_workflow(GOOD_WORKFLOW) == ""


@pytest.mark.parametrize(
    ("workflow", "problem"),
    [
        ("name: x\non:\n  push:\n", "no jobs"),
        ("jobs:\n  a:\n    runs-on: x\n    steps:\n      - run: y\n", "no trigger"),
        ("a: [unclosed", "not valid YAML"),
        ("on: push\njobs:\n  a:\n    steps:\n      - run: y\n", "no runs-on"),
        ("on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - name: y\n", "neither"),
    ],
)
def test_the_workflow_check_rejects_a_broken_workflow(workflow, problem):
    assert problem in check_workflow(workflow)


def test_validate_skips_instructions_only_patches():
    result = validate(patch_of("terraform", "Remove it.", instructions_only=True))

    assert result == ("none", "skipped", "instructions only, there is no code to check")


def test_validate_skips_terraform_unless_a_plugin_cache_is_given():
    assert validate(patch_of("terraform"))[1] == "skipped"


def test_validate_says_when_cfn_lint_is_not_installed(monkeypatch):
    monkeypatch.setattr(validators, "cfn_lint_installed", lambda: False)

    validator, valid, error = validate(patch_of("cloudformation"))

    assert (validator, valid) == ("cfn-lint", "skipped")
    assert "not installed" in error


def test_validate_refuses_a_format_it_has_no_check_for():
    with pytest.raises(ValueError, match="No check exists"):
        validate(patch_of("pulumi"))


def test_validate_reports_a_rejected_patch_as_no():
    validator, valid, error = validate(patch_of("cli", f"{TYPO} {ENABLED}\n"))

    assert (validator, valid) == ("botocore", "no")
    assert "has no operation" in error


@pytest.mark.skipif(not cfn_lint_installed(), reason="cfn-lint is not installed")
def test_cfn_lint_accepts_a_good_template_and_rejects_a_broken_one():
    assert check_cloudformation(GOOD_BUCKET) == ""
    assert check_cloudformation(BROKEN_BUCKET) != ""


@pytest.mark.skipif(shutil.which("terraform") is None, reason="terraform is not installed")
def test_terraform_validate_rejects_a_resource_with_an_unknown_argument(tmp_path):
    good = (
        'resource "aws_s3_bucket_versioning" "b" {\n  bucket = "b"\n'
        '  versioning_configuration {\n    status = "Enabled"\n  }\n}\n'
    )
    broken = (
        'resource "aws_s3_bucket_versioning" "b" {\n  bucket = "b"\n'
        "  no_such_argument = 1\n}\n"
    )

    assert check_terraform(good, tmp_path) == ""
    assert "no_such_argument" in check_terraform(broken, tmp_path)


def test_the_fixtures_cover_ipv6_port_ranges_and_all_protocols():
    files = []
    for _, resource in FIXTURES:
        for finding in run_rules([resource]):
            if finding.rule_id == "CIS-SG-001":
                fix = build_fix({"rule_id": finding.rule_id, "details": finding.details}, resource)
                cli = next(p for p in fix["patches"] if p["format"] == "cli")
                files += [f["content"] for f in cli["files"]]
    text = "\n".join(files)

    assert '"CidrIpv6": "::/0"' in text
    assert '"IpProtocol": "-1"' in text
    assert '"FromPort": 0' in text
    assert '"ToPort": 65535' in text
    assert '"IpProtocol": "6"' in text


def test_every_patch_gets_a_check_and_no_cli_or_workflow_patch_is_rejected():
    rows = e4.fix_rows(None) + e4.guardrail_rows(None)

    rules = {row["rule"] for row in rows if row["source"] == "fix"}
    assert rules == {"CIS-S3-001", "CIS-S3-002", "CIS-S3-003", "CIS-SG-001"}
    assert {row["source"] for row in rows} == {"fix", "guardrail"}
    formats = {row["format"] for row in rows}
    assert formats == {"terraform", "cloudformation", "cli", "github_actions"}
    checked = [row for row in rows if row["validator"] in ("botocore", "yaml structure")]
    assert checked
    assert [row for row in checked if row["valid"] != "yes"] == []


def test_a_guardrail_that_belongs_to_two_rules_is_listed_once():
    rows = e4.guardrail_rows(None)

    shared = [row for row in rows if row["fixture"] == "pipeline-iam-validate-policy"]
    assert [row["rule"] for row in shared] == ["CIS-IAM-001+SX-IAM-PRIVESC-001"]


def test_run_writes_the_csv_files_with_the_documented_columns(tmp_path):
    rows = e4.run(tmp_path)

    with (tmp_path / "e4.csv").open(newline="", encoding="utf-8") as handle:
        written = list(csv.DictReader(handle))
    assert list(written[0]) == e4.COLUMNS
    assert len(written) == len(rows)
    assert (tmp_path / "e4_summary.csv").exists()


def test_run_refuses_terraform_when_it_is_not_installed(monkeypatch, tmp_path):
    monkeypatch.setattr(shutil, "which", lambda name: None)

    with pytest.raises(RuntimeError, match="terraform is not on the PATH"):
        e4.run(tmp_path, terraform=True)
