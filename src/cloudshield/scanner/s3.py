import json

from cloudshield.scanner.common import attempt, list_all, make_resource

# Older bucket locations come back as None (us-east-1) or "EU" (eu-west-1).
LOCATION_NAMES = {None: "us-east-1", "EU": "eu-west-1"}


def collect_buckets(session, errors: list) -> list[dict]:
    s3 = session.client("s3")
    where = {"service": "s3", "region": None, "resource": None}
    buckets, ok = attempt(errors, where, list_all, s3, "list_buckets", "Buckets")
    if not ok:
        return []
    return [describe_bucket(session, bucket["Name"], errors) for bucket in buckets]


def describe_bucket(session, name: str, errors: list) -> dict:
    where = {"service": "s3", "region": None, "resource": name}
    s3 = session.client("s3")
    response, ok = attempt(errors, where, s3.get_bucket_location, Bucket=name)
    if not ok:
        return make_resource(name, "S3", None, name, {})

    location = response["LocationConstraint"]
    region = LOCATION_NAMES.get(location, location)
    where["region"] = region
    s3 = session.client("s3", region_name=region)

    # A key is left out of attributes when its call failed, so "unknown" is never
    # mistaken for "not configured". None means the call worked and nothing is set.
    attributes = {}

    response, ok = attempt(
        errors,
        where,
        s3.get_public_access_block,
        missing_codes=("NoSuchPublicAccessBlockConfiguration",),
        Bucket=name,
    )
    if ok:
        attributes["public_access_block"] = (
            response["PublicAccessBlockConfiguration"] if response else None
        )

    response, ok = attempt(
        errors,
        where,
        s3.get_bucket_encryption,
        missing_codes=("ServerSideEncryptionConfigurationNotFoundError",),
        Bucket=name,
    )
    if ok:
        attributes["encryption"] = (
            response["ServerSideEncryptionConfiguration"]["Rules"] if response else None
        )

    response, ok = attempt(errors, where, s3.get_bucket_versioning, Bucket=name)
    if ok:
        attributes["versioning"] = response.get("Status", "Disabled")

    response, ok = attempt(
        errors,
        where,
        s3.get_bucket_policy,
        missing_codes=("NoSuchBucketPolicy",),
        Bucket=name,
    )
    if ok:
        attributes["policy"] = json.loads(response["Policy"]) if response else None

    return make_resource(name, "S3", region, name, attributes)
