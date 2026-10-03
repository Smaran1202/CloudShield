import json

import pytest

from cloudshield.fixes.templates import build_fix, safe

ALLOWED_PREFIXES = (
    "aws s3api put-public-access-block ",
    "aws s3api put-bucket-versioning ",
    "aws s3api put-bucket-encryption ",
    "aws ec2 revoke-security-group-ingress ",
)
ALL_ON = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


def bucket(region="us-east-1") -> dict:
    return {"resource_id": "my-bucket", "resource_type": "S3", "region": region, "attributes": {}}


def group(region="ap-southeast-2") -> dict:
    return {
        "resource_id": "sg-0abc123",
        "resource_type": "Security Group",
        "region": region,
        "attributes": {},
    }


def finding(rule_id: str, details: dict) -> dict:
    return {"rule_id": rule_id, "details": details}


def rule(protocol="tcp", from_port=22, to_port=22, cidrs=("0.0.0.0/0",), exposes="SSH (port 22)"):
    return {
        "exposes": exposes,
        "protocol": protocol,
        "from_port": from_port,
        "to_port": to_port,
        "cidrs": list(cidrs),
    }


def by_format(fix: dict, name: str) -> dict:
    return next(p for p in fix["patches"] if p["format"] == name)


def cli_commands(fix: dict) -> list[str]:
    lines = by_format(fix, "cli")["content"].splitlines()
    return [line for line in lines if line and not line.startswith("#")]


def test_public_access_block_terraform_golden():
    fix = build_fix(finding("CIS-S3-001", {"public_access_block": None}), bucket())

    assert by_format(fix, "terraform")["content"] == (
        'resource "aws_s3_bucket_public_access_block" "my_bucket" {\n'
        '  bucket                  = "my-bucket"\n'
        "  block_public_acls       = true\n"
        "  block_public_policy     = true\n"
        "  ignore_public_acls      = true\n"
        "  restrict_public_buckets = true\n"
        "}\n"
    )


def test_public_access_block_cloudformation_golden():
    fix = build_fix(finding("CIS-S3-001", {"public_access_block": None}), bucket())

    assert by_format(fix, "cloudformation")["content"] == (
        "Resources:\n"
        "  MyBucket:\n"
        "    Type: AWS::S3::Bucket\n"
        "    Properties:\n"
        "      BucketName: my-bucket\n"
        "      PublicAccessBlockConfiguration:\n"
        "        BlockPublicAcls: true\n"
        "        BlockPublicPolicy: true\n"
        "        IgnorePublicAcls: true\n"
        "        RestrictPublicBuckets: true\n"
    )


def test_public_access_block_cli_golden():
    fix = build_fix(finding("CIS-S3-001", {"public_access_block": None}), bucket())

    assert by_format(fix, "cli")["content"] == (
        "aws s3api put-public-access-block --bucket my-bucket "
        '--public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,'
        'BlockPublicPolicy=true,RestrictPublicBuckets=true" --region us-east-1\n'
    )


def test_public_access_block_rollback_restores_the_previous_settings():
    before = {**ALL_ON, "BlockPublicPolicy": False}

    fix = build_fix(finding("CIS-S3-001", {"public_access_block": before}), bucket())

    assert "BlockPublicPolicy=false" in fix["rollback"]
    assert "BlockPublicAcls=true" in fix["rollback"]


def test_public_access_block_rollback_when_there_was_no_block_deletes_it():
    fix = build_fix(finding("CIS-S3-001", {"public_access_block": None}), bucket())

    assert "aws s3api delete-public-access-block --bucket my-bucket" in fix["rollback"]


def test_versioning_patches_golden():
    fix = build_fix(finding("CIS-S3-003", {"versioning": "Disabled"}), bucket())

    assert by_format(fix, "terraform")["content"] == (
        'resource "aws_s3_bucket_versioning" "my_bucket" {\n'
        '  bucket = "my-bucket"\n'
        "\n"
        "  versioning_configuration {\n"
        '    status = "Enabled"\n'
        "  }\n"
        "}\n"
    )
    assert by_format(fix, "cloudformation")["content"] == (
        "Resources:\n"
        "  MyBucket:\n"
        "    Type: AWS::S3::Bucket\n"
        "    Properties:\n"
        "      BucketName: my-bucket\n"
        "      VersioningConfiguration:\n"
        "        Status: Enabled\n"
    )
    assert by_format(fix, "cli")["content"] == (
        "aws s3api put-bucket-versioning --bucket my-bucket "
        "--versioning-configuration Status=Enabled --region us-east-1\n"
    )
    assert "Status=Suspended" in fix["rollback"]


def test_kms_encryption_patches_have_a_marked_placeholder_and_need_input():
    fix = build_fix(finding("CIS-S3-002", {"algorithms": ["AES256"]}), bucket())

    terraform = by_format(fix, "terraform")
    cli = by_format(fix, "cli")
    assert [p["format"] for p in fix["patches"]] == ["terraform", "cli"]
    assert terraform["content"] == (
        'resource "aws_s3_bucket_server_side_encryption_configuration" "my_bucket" {\n'
        '  bucket = "my-bucket"\n'
        "\n"
        "  rule {\n"
        "    apply_server_side_encryption_by_default {\n"
        '      sse_algorithm     = "aws:kms"\n'
        '      kms_master_key_id = "REPLACE_WITH_YOUR_KMS_KEY_ARN"\n'
        "    }\n"
        "  }\n"
        "}\n"
    )
    assert cli["content"] == (
        "aws s3api put-bucket-encryption --bucket my-bucket "
        "--server-side-encryption-configuration file://sse-kms-my-bucket.json "
        "--region us-east-1\n"
    )
    assert json.loads(cli["files"][0]["content"]) == {
        "Rules": [
            {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "aws:kms",
                    "KMSMasterKeyID": "REPLACE_WITH_YOUR_KMS_KEY_ARN",
                }
            }
        ]
    }
    assert terraform["needs_input"] is True
    assert cli["needs_input"] is True
    assert terraform["inputs_needed"] == ["The ARN of the KMS key to use for default encryption"]


def test_patches_without_a_placeholder_do_not_need_input():
    fix = build_fix(finding("CIS-S3-003", {"versioning": "Disabled"}), bucket())

    assert all(p["needs_input"] is False and p["inputs_needed"] == [] for p in fix["patches"])


def test_open_ssh_ipv4_cli_golden_and_json_file():
    fix = build_fix(finding("CIS-SG-001", {"rules": [rule()]}), group())

    cli = by_format(fix, "cli")
    assert cli["content"] == (
        "# Rule 1: protocol tcp, port 22 from 0.0.0.0/0\n"
        "aws ec2 revoke-security-group-ingress --group-id sg-0abc123 "
        "--ip-permissions file://sg-0abc123-rule1.json --region ap-southeast-2\n"
    )
    assert cli["files"][0]["name"] == "sg-0abc123-rule1.json"
    assert json.loads(cli["files"][0]["content"]) == [
        {
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }
    ]


def test_open_ssh_ipv6_uses_ipv6_ranges():
    fix = build_fix(finding("CIS-SG-001", {"rules": [rule(cidrs=["::/0"])]}), group())

    permission = json.loads(by_format(fix, "cli")["files"][0]["content"])[0]
    assert permission["Ipv6Ranges"] == [{"CidrIpv6": "::/0"}]
    assert "IpRanges" not in permission


def test_rule_open_to_both_ipv4_and_ipv6_lists_both():
    fix = build_fix(finding("CIS-SG-001", {"rules": [rule(cidrs=["0.0.0.0/0", "::/0"])]}), group())

    permission = json.loads(by_format(fix, "cli")["files"][0]["content"])[0]
    assert permission["IpRanges"] == [{"CidrIp": "0.0.0.0/0"}]
    assert permission["Ipv6Ranges"] == [{"CidrIpv6": "::/0"}]


def test_port_range_is_kept_as_a_range():
    ranged = rule(from_port=0, to_port=1024, exposes="SSH (port 22)")

    fix = build_fix(finding("CIS-SG-001", {"rules": [ranged]}), group())

    cli = by_format(fix, "cli")
    permission = json.loads(cli["files"][0]["content"])[0]
    assert (permission["FromPort"], permission["ToPort"]) == (0, 1024)
    assert "# Rule 1: protocol tcp, port 0-1024 from 0.0.0.0/0" in cli["content"]


def test_all_protocols_rule_has_no_ports_in_the_json():
    everything = rule(protocol="-1", from_port=None, to_port=None, exposes="all ports")

    fix = build_fix(finding("CIS-SG-001", {"rules": [everything]}), group())

    cli = by_format(fix, "cli")
    permission = json.loads(cli["files"][0]["content"])[0]
    assert permission == {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
    assert "# Rule 1: all ports and protocols from 0.0.0.0/0" in cli["content"]


def test_two_open_rules_give_two_commands_and_two_files():
    fix = build_fix(finding("CIS-SG-001", {"rules": [rule(), rule(protocol="-1")]}), group())

    cli = by_format(fix, "cli")
    assert len(cli_commands(fix)) == 2
    assert [f["name"] for f in cli["files"]] == ["sg-0abc123-rule1.json", "sg-0abc123-rule2.json"]
    assert fix["rollback"].count("aws ec2 authorize-security-group-ingress") == 2


def test_security_group_terraform_and_cloudformation_are_instructions_not_code():
    fix = build_fix(finding("CIS-SG-001", {"rules": [rule()]}), group())

    for name in ("terraform", "cloudformation"):
        patch = by_format(fix, name)
        assert patch["instructions_only"] is True
        assert "protocol tcp, port 22 from 0.0.0.0/0" in patch["content"]
        assert "sg-0abc123" in patch["content"]
        assert 'resource "' not in patch["content"]
        assert "Type:" not in patch["content"]
        assert "{" not in patch["content"]


def test_iam_rules_give_guidance_and_no_patch():
    for rule_id in ("CIS-IAM-001", "SX-IAM-PRIVESC-001"):
        resource = {"resource_id": "arn:aws:iam::1:policy/p", "resource_type": "IAM Policy"}
        resource.update({"region": None, "attributes": {}})

        fix = build_fix(finding(rule_id, {}), resource)

        assert fix["patches"] == []
        assert len(fix["guidance"]) >= 3
        assert "No patch is generated" in fix["guidance"][-1]


def test_every_fix_says_how_to_verify():
    fix = build_fix(finding("CIS-S3-003", {"versioning": "Disabled"}), bucket())

    assert fix["verify"] == "Rescan (POST /api/scans). This finding should resolve."


def test_every_cli_command_starts_with_an_allowed_prefix():
    fixes = [
        build_fix(finding("CIS-S3-001", {"public_access_block": None}), bucket()),
        build_fix(finding("CIS-S3-002", {"algorithms": []}), bucket()),
        build_fix(finding("CIS-S3-003", {"versioning": "Disabled"}), bucket()),
        build_fix(finding("CIS-SG-001", {"rules": [rule(), rule(protocol="-1")]}), group()),
    ]

    commands = [command for fix in fixes for command in cli_commands(fix)]

    assert len(commands) == 5
    assert all(command.startswith(ALLOWED_PREFIXES) for command in commands)


def test_cli_commands_are_one_line_with_no_continuation_characters():
    fix = build_fix(finding("CIS-SG-001", {"rules": [rule(), rule(cidrs=["::/0"])]}), group())

    for line in by_format(fix, "cli")["content"].splitlines():
        assert not line.endswith(("\\", "`"))
    for command in cli_commands(fix):
        assert "{" not in command and "\n" not in command


def test_region_is_left_out_when_the_resource_has_none():
    fix = build_fix(finding("CIS-S3-003", {"versioning": "Disabled"}), bucket(region=None))

    assert "--region" not in by_format(fix, "cli")["content"]


def test_unsafe_values_are_refused_instead_of_put_in_a_command():
    evil = {"resource_id": "b; rm -rf /", "resource_type": "S3", "region": "us-east-1"}
    evil["attributes"] = {}

    with pytest.raises(ValueError):
        build_fix(finding("CIS-S3-003", {"versioning": "Disabled"}), evil)
    with pytest.raises(ValueError):
        safe("$(whoami)")


def test_bucket_names_that_start_with_a_digit_get_a_valid_terraform_label():
    numbered = {"resource_id": "123.bucket", "resource_type": "S3", "region": None}
    numbered["attributes"] = {}

    fix = build_fix(finding("CIS-S3-003", {"versioning": "Disabled"}), numbered)

    assert 'resource "aws_s3_bucket_versioning" "bucket_123_bucket"' in (
        by_format(fix, "terraform")["content"]
    )
