# Imported check id -> our own rule id, for checks that test exactly the same thing. Add a pair
# only after it has been confirmed against real output. A check that covers only part of what
# our rule covers (for example the IAM wildcard check) must not be listed here.
SOURCE = "imported scan output"


def rule_id_of(check_id: str) -> str:
    return f"PRW-{check_id}"


# The attribute of our stored resource that each of our rules needs. When it is missing, the
# call that reads it failed, so our side has no data.
NEEDS = {"CIS-S3-001": "public_access_block", "CIS-S3-003": "versioning"}

SAME_CHECK = {
    "s3_bucket_level_public_access_block": "CIS-S3-001",
    "s3_bucket_object_versioning": "CIS-S3-003",
}
