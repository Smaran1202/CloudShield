from typing import NamedTuple

# Imported check id -> our own rule id, for checks that test exactly the same thing. Add a pair
# only after it has been confirmed against real output. A check that covers only part of what
# our rule covers (for example the IAM wildcard check) must not be listed here.
#
# Confirmed against a real results file:
#   s3_bucket_kms_encryption             on 2026-10-27 (the check id was found in the file)
#   s3_bucket_level_public_access_block  earlier, date not recorded
#   s3_bucket_object_versioning          earlier, date not recorded
# Not confirmed: none.
SOURCE = "imported scan output"


def rule_id_of(check_id: str) -> str:
    return f"PRW-{check_id}"


class Pair(NamedTuple):
    rule: str
    # The attribute of our stored resource that the rule needs. When it is missing, the call
    # that reads it failed, so our side has no data.
    needs: str


SAME_CHECK = {
    "s3_bucket_level_public_access_block": Pair("CIS-S3-001", "public_access_block"),
    "s3_bucket_object_versioning": Pair("CIS-S3-003", "versioning"),
    "s3_bucket_kms_encryption": Pair("CIS-S3-002", "encryption"),
}
