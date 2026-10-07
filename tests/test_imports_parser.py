import codecs
import logging

import pytest
from prowler_data import ACCOUNT, BUCKET_ARN, GROUP_ARN, POLICY_ARN, entry, to_bytes

from cloudshield.imports import parser
from cloudshield.imports.parser import ImportRejected, parse_bytes, parse_file
from cloudshield.imports.resources import map_resource

ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/managed/Admin"
USER_ARN = f"arn:aws:iam::{ACCOUNT}:user/someone"
AWS_POLICY_ARN = "arn:aws:iam::aws:policy/SecurityAudit"


def test_parses_a_pass_and_a_fail_with_the_fields_we_need():
    raw = to_bytes([entry(), entry(check="s3_other", status="PASS")])

    parsed = parse_bytes(raw)

    fail, passed = parsed.records
    assert fail.status == "FAIL"
    assert fail.check_id == "s3_bucket_public_access"
    assert fail.title == "Bucket does not block public access"
    assert fail.description == "Description of s3_bucket_public_access."
    assert fail.risk == "Risk of s3_bucket_public_access."
    assert fail.remediation == "Fix s3_bucket_public_access like this."
    assert fail.references == ["https://example.com/s3_bucket_public_access"]
    assert fail.categories == ["internet-exposed"]
    assert fail.resource_id == "my-bucket"
    assert fail.resource_type == "S3"
    assert fail.region == "ap-southeast-2"
    assert fail.service == "s3"
    assert passed.status == "PASS"
    assert parsed.external_account_id == ACCOUNT
    assert len(parsed.sha256) == 64


def test_ignores_the_top_level_status_which_is_always_new():
    parsed = parse_bytes(to_bytes([entry(status="PASS")]))

    assert parsed.records[0].status == "PASS"


def test_reads_a_file_that_starts_with_a_byte_order_mark():
    raw = codecs.BOM_UTF8 + to_bytes([entry()])

    assert len(parse_bytes(raw).records) == 1


def test_refuses_a_file_that_is_not_json():
    with pytest.raises(ImportRejected, match="not valid JSON"):
        parse_bytes(b"{not json")


def test_refuses_a_file_that_is_not_utf8():
    with pytest.raises(ImportRejected, match="UTF-8"):
        parse_bytes(b"\xff\xfe\x00")


def test_refuses_json_that_is_not_an_array_or_is_empty():
    with pytest.raises(ImportRejected, match="array"):
        parse_bytes(b'{"a": 1}')
    with pytest.raises(ImportRejected, match="no findings"):
        parse_bytes(b"[]")


def test_refuses_a_file_over_the_size_limit_before_reading_it(tmp_path, monkeypatch):
    monkeypatch.setattr(parser, "MAX_BYTES", 10)
    path = tmp_path / "big.json"
    path.write_bytes(to_bytes([entry()]))

    with pytest.raises(ImportRejected, match="50 MB"):
        parse_file(path)
    with pytest.raises(ImportRejected, match="50 MB"):
        parse_bytes(to_bytes([entry()]))


def test_refuses_a_file_with_another_ocsf_major_version():
    with pytest.raises(ImportRejected, match="major version 2"):
        parse_bytes(to_bytes([entry(), entry(version="2.0.0")]))


def test_accepts_a_newer_minor_version_of_ocsf_1():
    assert len(parse_bytes(to_bytes([entry(version="1.7.0")])).records) == 1


def test_refuses_a_file_that_mixes_two_accounts():
    with pytest.raises(ImportRejected, match="more than one"):
        parse_bytes(to_bytes([entry(), entry(account="999999999999")]))


def test_counts_other_statuses_as_ignored_and_never_fails_on_them():
    raw = to_bytes([entry(status="MANUAL"), entry(status="MUTED"), entry()])

    parsed = parse_bytes(raw)

    assert parsed.ignored == 2
    assert len(parsed.records) == 1


def test_counts_entries_that_lack_a_check_id_or_title_as_rejected():
    broken = entry()
    del broken["metadata"]["event_code"]
    untitled = entry()
    untitled["finding_info"]["title"] = ""

    parsed = parse_bytes(to_bytes([broken, untitled, "text", entry()]))

    assert parsed.rejected == 3
    assert len(parsed.records) == 1


def test_does_not_fail_on_fields_it_does_not_know():
    extra = entry()
    extra["something_new"] = {"deep": [1, 2, 3]}
    extra["metadata"]["another"] = "value"

    assert len(parse_bytes(to_bytes([extra])).records) == 1


@pytest.mark.parametrize(
    ("text", "severity_id", "expected"),
    [
        ("Critical", 5, "CRITICAL"),
        ("High", 4, "HIGH"),
        ("Medium", 3, "MEDIUM"),
        ("Low", 2, "LOW"),
        ("Informational", 1, "INFO"),
        ("info", 1, "INFO"),
        # The text wins over the id.
        ("Low", 5, "LOW"),
    ],
)
def test_maps_the_severity_text(text, severity_id, expected):
    parsed = parse_bytes(to_bytes([entry(severity=text, severity_id=severity_id)]))

    assert parsed.records[0].severity == expected
    assert parsed.unknown_severity == 0


@pytest.mark.parametrize(
    ("severity_id", "expected"),
    [(1, "INFO"), (2, "LOW"), (3, "MEDIUM"), (4, "HIGH"), (5, "CRITICAL")],
)
def test_falls_back_to_the_severity_id_when_the_text_is_missing(severity_id, expected):
    parsed = parse_bytes(to_bytes([entry(severity=None, severity_id=severity_id)]))

    assert parsed.records[0].severity == expected
    assert parsed.unknown_severity == 0


@pytest.mark.parametrize("severity_id", [0, 6, 99])
def test_treats_an_unknown_severity_as_info_and_counts_it(severity_id):
    parsed = parse_bytes(to_bytes([entry(severity="Weird", severity_id=severity_id)]))

    assert parsed.records[0].severity == "INFO"
    assert parsed.unknown_severity == 1


def test_logs_counts_only_and_never_the_finding_text(caplog):
    caplog.set_level(logging.INFO)

    parse_bytes(to_bytes([entry(title="Secret title text")]))

    assert "1 records" in caplog.text
    assert "Secret title text" not in caplog.text
    assert "my-bucket" not in caplog.text


def test_a_finding_with_no_resource_becomes_an_account_finding():
    parsed = parse_bytes(to_bytes([entry(uid=None)]))

    record = parsed.records[0]
    assert record.resource_type == "Account"
    assert record.resource_id == ACCOUNT


@pytest.mark.parametrize(
    ("uid", "resource_id", "resource_type"),
    [
        (BUCKET_ARN, "my-bucket", "S3"),
        (GROUP_ARN, "sg-0abc123", "Security Group"),
        (f"arn:aws:ec2:ap-southeast-2:{ACCOUNT}:instance/i-0abc", "i-0abc", "EC2"),
        (POLICY_ARN, POLICY_ARN, "IAM Policy"),
        (ROLE_ARN, ROLE_ARN, "IAM Role"),
        (USER_ARN, USER_ARN, "IAM User"),
        (AWS_POLICY_ARN, AWS_POLICY_ARN, "IAM Policy"),
        (
            f"arn:aws:ec2:ap-southeast-2:{ACCOUNT}:network-acl/acl-1",
            f"arn:aws:ec2:ap-southeast-2:{ACCOUNT}:network-acl/acl-1",
            "Network ACL",
        ),
    ],
)
def test_maps_an_arn_to_our_resource_id_and_type(uid, resource_id, resource_type):
    assert map_resource(uid, ACCOUNT, "") == (resource_id, resource_type)


@pytest.mark.parametrize(
    "uid",
    [
        ACCOUNT,
        None,
        "",
        f"arn:aws:iam::{ACCOUNT}:root",
        f"arn:aws:iam:ap-southeast-2:{ACCOUNT}:password-policy",
        f"arn:aws:s3:ap-southeast-2:{ACCOUNT}:account",
        f"arn:aws:ec2:ap-southeast-2:{ACCOUNT}:account",
    ],
)
def test_marks_account_level_resources_as_account(uid):
    assert map_resource(uid, ACCOUNT, "Other")[1] == "Account"


def test_keeps_an_unknown_arn_and_the_type_prowler_gave():
    uid = f"arn:aws:lambda:ap-southeast-2:{ACCOUNT}:function:f"

    assert map_resource(uid, ACCOUNT, "AwsLambdaFunction") == (uid, "AwsLambdaFunction")
