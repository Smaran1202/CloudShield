import re

from cloudshield.findings import make_finding_id


def test_finding_id_has_rule_id_and_eight_hex_characters():
    finding_id = make_finding_id("CIS-S3-001", "my-bucket")

    assert re.fullmatch(r"F-CIS-S3-001-[0-9a-f]{8}", finding_id)


def test_finding_id_is_the_same_every_time():
    first = make_finding_id("CIS-S3-001", "my-bucket")
    second = make_finding_id("CIS-S3-001", "my-bucket")

    assert first == second


def test_finding_id_differs_by_resource_and_by_variant():
    base = make_finding_id("SX-IAM-PRIVESC-001", "arn:aws:iam::1:policy/p")
    other_resource = make_finding_id("SX-IAM-PRIVESC-001", "arn:aws:iam::1:policy/q")
    other_variant = make_finding_id("SX-IAM-PRIVESC-001", "arn:aws:iam::1:policy/p", "method")

    assert len({base, other_resource, other_variant}) == 3
