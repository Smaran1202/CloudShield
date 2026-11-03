from cloudshield.db.models import ScanRow

BLOCK_NAMES = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")

CANNOT_SEE = {
    "pipeline_check": (
        "CloudShield cannot see your pipeline, so it cannot tell whether this check is in place."
    ),
    "detective_rule": (
        "CloudShield does not read AWS Config rules, so it cannot tell whether this rule exists."
    ),
    "account_setting": "CloudShield does not read this setting, so it cannot tell if it is set.",
}
ORGANIZATION = (
    "Only your organization's management account can apply or read this, so CloudShield cannot "
    "verify it."
)


def guardrail_status(guardrail: dict, scan: ScanRow | None) -> tuple[str, str]:
    """(status, reason). "active" is only returned when a scan read the setting and found it on.
    Every error, missing permission or missing scan gives "unknown"."""
    if guardrail["kind"] == "organization_policy":
        return "needs_org_admin", ORGANIZATION
    reads = guardrail["reads"]
    if reads is None:
        return "unknown", CANNOT_SEE[guardrail["kind"]]
    if scan is None:
        return "unknown", "No scan has finished yet, so nothing was read."
    settings = scan.account_settings or {}
    if reads not in settings:
        return "unknown", "The last scan could not read it (access denied or an error)."
    value = settings[reads]
    if value is None:
        return "not_active", "The last scan read the account and no setting is configured."
    off = [name for name in BLOCK_NAMES if value.get(name) is not True]
    if off:
        return "not_active", f"The last scan read the account. These settings are off: {off}."
    return (
        "active",
        "The last scan read all four settings as on. This is the setting in effect for the "
        "account, so it may come from an organization policy.",
    )
