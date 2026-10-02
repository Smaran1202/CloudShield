from cloudshield.rules.s3 import check_kms_encryption, check_public_access_block, check_versioning
from cloudshield.scanner.common import make_resource

ALL_ON = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


def bucket(**attributes) -> dict:
    return make_resource("my-bucket", "S3", "us-east-1", "my-bucket", attributes)


def test_public_access_block_fully_on_has_no_finding():
    assert check_public_access_block([bucket(public_access_block=ALL_ON)]) == []


def test_public_access_block_with_one_setting_off_is_a_finding():
    block = {**ALL_ON, "BlockPublicPolicy": False}

    hits = check_public_access_block([bucket(public_access_block=block)])

    assert len(hits) == 1
    assert hits[0].details["settings_off"] == ["BlockPublicPolicy"]


def test_missing_public_access_block_is_a_finding_with_all_four_off():
    hits = check_public_access_block([bucket(public_access_block=None)])

    assert len(hits) == 1
    assert len(hits[0].details["settings_off"]) == 4


def test_unknown_public_access_block_is_not_a_finding():
    assert check_public_access_block([bucket()]) == []


def test_default_s3_encryption_is_a_finding_because_it_is_not_kms():
    rules = [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]

    hits = check_kms_encryption([bucket(encryption=rules)])

    assert len(hits) == 1
    assert hits[0].details["algorithms"] == ["AES256"]


def test_kms_encryption_has_no_finding():
    rules = [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]

    assert check_kms_encryption([bucket(encryption=rules)]) == []


def test_no_encryption_configuration_is_a_finding():
    hits = check_kms_encryption([bucket(encryption=None)])

    assert len(hits) == 1
    assert hits[0].details["algorithms"] == []


def test_unknown_encryption_is_not_a_finding():
    assert check_kms_encryption([bucket()]) == []


def test_versioning_disabled_or_suspended_is_a_finding():
    disabled = check_versioning([bucket(versioning="Disabled")])
    suspended = check_versioning([bucket(versioning="Suspended")])

    assert len(disabled) == 1
    assert len(suspended) == 1


def test_versioning_enabled_has_no_finding():
    assert check_versioning([bucket(versioning="Enabled")]) == []


def test_unknown_versioning_is_not_a_finding():
    assert check_versioning([bucket()]) == []
