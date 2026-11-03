from cloudshield.scanner.common import attempt


def collect_account_settings(session, region: str, errors: list) -> dict:
    """Settings that belong to the whole account, not to one resource.

    A key is left out when its call failed, so "could not read it" is never mistaken for "not
    set". None means the call worked and nothing is set.
    """
    identity, ok = attempt(
        errors,
        {"service": "sts", "region": None, "resource": None},
        session.client("sts").get_caller_identity,
    )
    if not ok:
        return {}

    # The setting is account-wide; the call is made through the first scanned region.
    s3control = session.client("s3control", region_name=region)
    where = {"service": "s3control", "region": region, "resource": None}
    response, ok = attempt(
        errors,
        where,
        s3control.get_public_access_block,
        missing_codes=("NoSuchPublicAccessBlockConfiguration",),
        AccountId=identity["Account"],
    )
    if not ok:
        return {}
    return {
        "s3_public_access_block": response["PublicAccessBlockConfiguration"] if response else None
    }
