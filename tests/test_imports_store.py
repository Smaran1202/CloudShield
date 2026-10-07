import pytest
from prowler_data import ACCOUNT, BUCKET_ARN, GROUP_ARN, POLICY_ARN, entry, to_bytes
from sqlalchemy import select

from cloudshield.db import store
from cloudshield.db.models import (
    ACCOUNT_ID,
    Base,
    FindingRow,
    ImportRow,
    PassedCheckRow,
)
from cloudshield.db.session import make_engine, make_session_factory
from cloudshield.findings import make_finding_id
from cloudshield.imports.importer import import_parsed
from cloudshield.imports.parser import ImportRejected, parse_bytes
from cloudshield.risk.scoring import score_findings
from cloudshield.rules import run_rules
from cloudshield.scanner.common import make_resource

REGIONS = ["ap-southeast-2"]
ALL_OFF = {
    "BlockPublicAcls": False,
    "IgnorePublicAcls": False,
    "BlockPublicPolicy": False,
    "RestrictPublicBuckets": False,
}
GROUP_FINDING = make_finding_id("PRW-ec2_securitygroup_open", "sg-0abc123")
BUCKET_FINDING = make_finding_id("PRW-s3_bucket_public_access", "my-bucket")


@pytest.fixture
def session(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'test.db'}")
    Base.metadata.create_all(engine)
    with make_session_factory(engine)() as session:
        yield session


def run_import(session, entries, account_id=ACCOUNT_ID) -> dict:
    return import_parsed(session, parse_bytes(to_bytes(entries)), account_id)


def finding(session, finding_id: str) -> FindingRow:
    return session.get(FindingRow, (ACCOUNT_ID, finding_id))


def bucket_resource(block=ALL_OFF) -> dict:
    attributes = {"public_access_block": block, "encryption": None, "versioning": "Enabled"}
    attributes["policy"] = None
    return make_resource("my-bucket", "S3", "ap-southeast-2", "my-bucket", attributes)


def run_scan(session, resources, errors=None, regions=REGIONS) -> int:
    result = {"resources": resources, "errors": errors or []}
    findings = score_findings(run_rules(resources), result, regions)
    scan = store.create_scan(session, regions)
    store.save_result(session, scan.id, result, findings)
    return scan.id


def test_imports_a_failure_as_an_open_finding_with_a_prowler_rule_id(session):
    result = run_import(session, [entry()])

    row = finding(session, BUCKET_FINDING)
    assert result["counts"]["imported"] == 1
    assert row.rule_id == "PRW-s3_bucket_public_access"
    assert row.source == "prowler"
    assert row.status == "OPEN"
    assert row.resource_id == "my-bucket"
    assert row.resource_type == "S3"
    assert row.title == "Detail for s3_bucket_public_access."
    assert row.details["check_title"] == "Bucket does not block public access"
    assert row.severity == "HIGH"
    assert row.last_scan_id is None
    assert row.import_id == result["import_id"]
    assert row.last_imported_at is not None
    assert row.details["remediation"] == "Fix s3_bucket_public_access like this."


def test_finding_ids_are_stable_and_follow_the_existing_scheme(session):
    run_import(session, [entry()])
    first = finding(session, BUCKET_FINDING)
    assert BUCKET_FINDING.startswith("F-PRW-s3_bucket_public_access-")

    again = run_import(session, [entry(), entry(check="other")])

    assert again["counts"]["already_seen"] == 1
    assert again["counts"]["imported"] == 1
    assert finding(session, BUCKET_FINDING) is first
    assert first.first_seen_at <= first.last_seen_at


def test_evidence_from_prowler_text_is_reported_not_verified(session):
    run_import(session, [entry()])

    items = finding(session, BUCKET_FINDING).evidence["items"]

    assert {item["certainty"] for item in items} == {"reported"}
    assert {item["source"] for item in items} == {"imported scan output"}
    assert [item["fact"] for item in items] == [
        "Failing statement",
        "Resource",
        "Check and severity",
        "Risk described by the scanner",
        "Check description",
    ]


def test_the_same_file_imported_twice_is_rejected_and_changes_nothing(session):
    raw = to_bytes([entry()])
    import_parsed(session, parse_bytes(raw), ACCOUNT_ID)

    with pytest.raises(ImportRejected, match="already imported"):
        import_parsed(session, parse_bytes(raw), ACCOUNT_ID)

    assert len(session.scalars(select(ImportRow)).all()) == 1


def test_the_same_file_for_another_account_id_is_not_a_duplicate(session):
    raw = to_bytes([entry()])
    import_parsed(session, parse_bytes(raw), ACCOUNT_ID)

    import_parsed(session, parse_bytes(raw), "other")

    assert len(session.scalars(select(ImportRow)).all()) == 2


def test_the_import_row_stores_counts_regions_and_checks(session):
    entries = [entry(), entry(check="c2", status="PASS", region="us-east-1"), entry(status="MUTED")]

    result = run_import(session, entries)

    row = session.get(ImportRow, result["import_id"])
    assert row.source == "prowler"
    assert row.external_account_id == ACCOUNT
    assert len(row.file_sha256) == 64
    assert row.regions_covered == ["ap-southeast-2", "us-east-1"]
    assert row.checks_covered == ["c2", "s3_bucket_public_access"]
    assert row.counts == {
        "imported": 1,
        "passed": 1,
        "ignored": 1,
        "already_seen": 0,
        "resolved": 0,
        "rejected": 0,
        "unknown_severity": 0,
    }


def test_a_passing_check_is_stored_as_one_compact_row(session):
    run_import(session, [entry(check="c2", status="PASS")])

    row = session.get(PassedCheckRow, (ACCOUNT_ID, "c2", "my-bucket"))

    assert row.region == "ap-southeast-2"
    assert row.last_import_id == 1
    assert {c.name for c in PassedCheckRow.__table__.columns} == {
        "account_id",
        "check_id",
        "resource_id",
        "region",
        "last_import_id",
    }


def test_a_later_pass_resolves_an_open_imported_finding(session):
    run_import(session, [entry()])

    result = run_import(session, [entry(status="PASS")])

    row = finding(session, BUCKET_FINDING)
    assert result["counts"]["resolved"] == 1
    assert row.status == "RESOLVED"
    assert row.resolution_reason == "passed in a newer import"
    assert row.resolved_at is not None


def test_a_failure_after_a_pass_opens_the_finding_again(session):
    run_import(session, [entry()])
    run_import(session, [entry(status="PASS")])

    run_import(session, [entry(title="Bucket does not block public access ")])

    row = finding(session, BUCKET_FINDING)
    assert row.status == "OPEN"
    assert row.resolved_at is None
    assert row.resolution_reason is None


def test_a_check_missing_from_a_newer_import_stays_open_and_is_not_rechecked(session):
    first = run_import(session, [entry()])
    second = run_import(session, [entry(check="other")])

    row = finding(session, BUCKET_FINDING)
    assert row.status == "OPEN"
    assert row.import_id == first["import_id"]
    assert row.import_id != second["import_id"]
    assert row.last_imported_at is not None


def test_a_pass_for_a_different_resource_does_not_resolve_the_finding(session):
    run_import(session, [entry()])

    run_import(session, [entry(status="PASS", uid="arn:aws:s3:::other-bucket")])

    assert finding(session, BUCKET_FINDING).status == "OPEN"


def test_a_scan_does_not_resolve_imported_findings(session):
    run_import(session, [entry()])

    run_scan(session, [])

    assert finding(session, BUCKET_FINDING).status == "OPEN"


def test_a_resource_our_scan_no_longer_sees_resolves_a_finding_that_was_not_rechecked(session):
    run_scan(session, [bucket_resource()])
    run_import(session, [entry()])
    run_import(session, [entry(check="other")])

    run_scan(session, [])

    row = finding(session, BUCKET_FINDING)
    assert row.status == "RESOLVED"
    assert row.resolution_reason == "resource no longer exists"


def test_the_gone_exception_is_applied_when_the_import_arrives_after_the_scan(session):
    run_scan(session, [bucket_resource()])
    run_import(session, [entry()])
    run_scan(session, [])
    # The newest import mentions the finding, so the scan may not override it.
    assert finding(session, BUCKET_FINDING).status == "OPEN"

    result = run_import(session, [entry(check="other")])

    assert result["counts"]["resolved"] == 1
    assert finding(session, BUCKET_FINDING).resolution_reason == "resource no longer exists"


def test_a_finding_the_newest_import_reported_is_not_resolved_by_the_exception(session):
    run_scan(session, [bucket_resource()])
    run_scan(session, [])

    run_import(session, [entry()])

    assert finding(session, BUCKET_FINDING).status == "OPEN"


def test_the_gone_exception_needs_a_scan_without_errors_for_that_service(session):
    run_scan(session, [bucket_resource()])
    run_import(session, [entry()])
    run_import(session, [entry(check="other")])
    errors = [{"service": "s3", "region": None, "resource": None, "message": "denied"}]

    run_scan(session, [], errors=errors)

    assert finding(session, BUCKET_FINDING).status == "OPEN"


def test_the_gone_exception_never_applies_to_a_resource_we_never_saw(session):
    run_scan(session, [])
    run_import(session, [entry()])

    run_import(session, [entry(check="other")])

    assert finding(session, BUCKET_FINDING).status == "OPEN"


def test_the_gone_exception_needs_the_region_of_a_security_group_to_be_scanned(session):
    group = make_resource(
        "sg-0abc123", "Security Group", "us-east-1", "web", {"vpc_id": "v", "inbound": []}
    )
    run_scan(session, [group], regions=["us-east-1"])
    run_import(session, [entry(check="ec2_securitygroup_open", uid=GROUP_ARN, group="ec2")])
    run_import(session, [entry(check="other")])

    run_scan(session, [], regions=["ap-southeast-2"])
    assert finding(session, GROUP_FINDING).status == "OPEN"

    run_scan(session, [], regions=["us-east-1"])
    assert finding(session, GROUP_FINDING).status == "RESOLVED"


def test_the_gone_exception_never_applies_to_a_policy_owned_by_aws(session):
    uid = "arn:aws:iam::aws:policy/AdministratorAccess"
    policy_finding = make_finding_id("PRW-iam_admin", uid)
    run_import(session, [entry(check="iam_admin", uid=uid, group="iam")])
    run_import(session, [entry(check="other")])

    run_scan(session, [])

    assert finding(session, policy_finding).status == "OPEN"


def test_an_imported_finding_without_our_resource_gets_the_base_score_and_a_context_note(session):
    run_import(session, [entry(severity="High")])

    row = finding(session, BUCKET_FINDING)

    assert row.risk_score == 70
    assert row.risk_factors == [
        {
            "factor": "context",
            "adjustment": 0,
            "reason": "context not available for imported findings",
            "certainty": "unknown",
        }
    ]


@pytest.mark.parametrize(
    ("severity", "score"),
    [("Critical", 90), ("High", 70), ("Medium", 40), ("Low", 20)],
)
def test_the_base_score_comes_from_the_severity_alone(session, severity, score):
    run_import(session, [entry(severity=severity)])

    assert finding(session, BUCKET_FINDING).risk_score == score


def test_an_informational_imported_finding_has_no_risk_score(session):
    run_import(session, [entry(severity="Informational", severity_id=1)])

    row = finding(session, BUCKET_FINDING)

    assert row.severity == "INFO"
    assert row.risk_score is None
    assert row.risk_factors == []


def test_our_own_context_is_added_when_the_same_resource_was_scanned(session):
    run_scan(session, [bucket_resource()])

    run_import(session, [entry(severity="High")])

    row = finding(session, BUCKET_FINDING)
    assert row.risk_score == 85
    assert [f["factor"] for f in row.risk_factors] == ["exposure"]
    assert row.risk_factors[0]["certainty"] == "verified"


def test_an_account_level_finding_is_never_matched_to_our_resources(session):
    uid = f"arn:aws:iam::{ACCOUNT}:root"
    run_import(session, [entry(check="iam_root", uid=uid, group="iam")])

    row = finding(session, make_finding_id("PRW-iam_root", uid))

    assert row.resource_type == "Account"
    assert row.risk_score == 70
    assert row.risk_factors[0]["factor"] == "context"


def test_a_finding_with_no_resource_uses_the_account_id(session):
    run_import(session, [entry(check="iam_none", uid=None)])

    row = finding(session, make_finding_id("PRW-iam_none", ACCOUNT))

    assert row.resource_type == "Account"
    assert row.resource_id == ACCOUNT


def test_a_security_group_and_a_policy_are_stored_under_our_resource_ids(session):
    run_import(
        session,
        [
            entry(check="ec2_securitygroup_open", uid=GROUP_ARN, group="ec2"),
            entry(check="iam_wild", uid=POLICY_ARN, group="iam"),
        ],
    )

    group_row = finding(session, GROUP_FINDING)
    policy_row = finding(session, make_finding_id("PRW-iam_wild", POLICY_ARN))

    assert (group_row.resource_id, group_row.resource_type) == ("sg-0abc123", "Security Group")
    assert (policy_row.resource_id, policy_row.resource_type) == (POLICY_ARN, "IAM Policy")


def test_an_import_for_a_different_aws_account_gives_a_warning(session):
    run_import(session, [entry()])

    result = run_import(session, [entry(check="other", account="999999999999")])

    assert "differs" in result["warning"]


def test_an_import_for_the_same_aws_account_gives_no_warning(session):
    run_import(session, [entry()])

    assert run_import(session, [entry(check="other")])["warning"] is None


def test_our_own_findings_are_not_touched_by_an_import(session):
    run_scan(session, [bucket_resource()])
    before = session.scalars(select(FindingRow).where(FindingRow.source == "cloudshield")).all()

    run_import(session, [entry(status="PASS")])

    after = session.scalars(select(FindingRow).where(FindingRow.source == "cloudshield")).all()
    assert [f.status for f in after] == [f.status for f in before]
    assert BUCKET_ARN.endswith("my-bucket")
