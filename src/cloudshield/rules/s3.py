from cloudshield.rules.rule import Hit, Rule, of_type

BLOCK_SETTINGS = (
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
)
KMS_ALGORITHMS = ("aws:kms", "aws:kms:dsse")


def check_public_access_block(resources: list[dict]) -> list[Hit]:
    hits = []
    for bucket in of_type(resources, "S3"):
        attributes = bucket["attributes"]
        if "public_access_block" not in attributes:
            continue
        block = attributes["public_access_block"]
        if block is None:
            details = {"public_access_block": None, "settings_off": list(BLOCK_SETTINGS)}
            hits.append(Hit(bucket, details))
            continue
        off = [name for name in BLOCK_SETTINGS if not block.get(name)]
        if off:
            hits.append(Hit(bucket, {"public_access_block": block, "settings_off": off}))
    return hits


def check_kms_encryption(resources: list[dict]) -> list[Hit]:
    hits = []
    for bucket in of_type(resources, "S3"):
        attributes = bucket["attributes"]
        if "encryption" not in attributes:
            continue
        rules = attributes["encryption"] or []
        algorithms = [r["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"] for r in rules]
        if not any(algorithm in KMS_ALGORITHMS for algorithm in algorithms):
            hits.append(Hit(bucket, {"algorithms": algorithms}))
    return hits


def check_versioning(resources: list[dict]) -> list[Hit]:
    hits = []
    for bucket in of_type(resources, "S3"):
        attributes = bucket["attributes"]
        if "versioning" not in attributes:
            continue
        if attributes["versioning"] != "Enabled":
            hits.append(Hit(bucket, {"versioning": attributes["versioning"]}))
    return hits


RULES = [
    Rule(
        id="CIS-S3-001",
        title="S3 bucket does not block all public access",
        severity="HIGH",
        category="Storage",
        description=(
            "The bucket's public access block is missing, or at least one of its four settings "
            "(BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets) is off. "
            "Without all four, an ACL or bucket policy can make objects public."
        ),
        fix="Turn on all four public access block settings for the bucket, or for the account.",
        check=check_public_access_block,
    ),
    Rule(
        id="CIS-S3-002",
        title="S3 bucket default encryption does not use a KMS key",
        severity="INFO",
        category="Storage",
        description=(
            "The bucket's default encryption is not SSE-KMS. S3 encrypts every new bucket with "
            "SSE-S3 by default, so a bucket with no encryption at all is almost never real. This "
            "finding means the keys are managed by S3 rather than by your own KMS key, which "
            "matters when you need key-level access control or audit."
        ),
        fix="Set the bucket default encryption to SSE-KMS with a KMS key you control.",
        check=check_kms_encryption,
        counts_toward_risk=False,
    ),
    Rule(
        id="CIS-S3-003",
        title="S3 bucket versioning is not enabled",
        severity="MEDIUM",
        category="Storage",
        description=(
            "Versioning is off or suspended, so overwritten or deleted objects cannot be recovered."
        ),
        fix="Enable versioning on the bucket.",
        check=check_versioning,
    ),
]
