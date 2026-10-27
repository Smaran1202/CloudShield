import importlib.util
import json

import pytest
from fastapi.testclient import TestClient
from prowler_data import ACCOUNT, BUCKET_ARN, entry, to_bytes
from sqlalchemy import select

from cloudshield.api.app import create_app
from cloudshield.db import store
from cloudshield.db.models import Base, FixRow
from cloudshield.db.session import make_engine
from cloudshield.fixes import explain
from cloudshield.fixes.templates import NOT_CHECKED
from cloudshield.imports.guidance import guidance_for
from cloudshield.imports.importer import import_parsed
from cloudshield.imports.parser import parse_bytes
from cloudshield.risk.scoring import score_breakdown, score_findings
from cloudshield.rules import ALL_RULES, run_rules
from cloudshield.scanner.common import make_resource

REGIONS = ["ap-southeast-2"]
ALL_OFF = {
    "BlockPublicAcls": False,
    "IgnorePublicAcls": False,
    "BlockPublicPolicy": False,
    "RestrictPublicBuckets": False,
}
KMS = [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]
PASSWORD_ARN = f"arn:aws:iam:ap-southeast-2:{ACCOUNT}:password-policy"
LENGTH_CHECK = "iam_password_policy_minimum_length_14"


def make_client(tmp_path) -> TestClient:
    url = f"sqlite:///{tmp_path / 'test.db'}"
    Base.metadata.create_all(make_engine(url))
    return TestClient(create_app(database_url=url, load_env=False))


def bucket() -> dict:
    attributes = {
        "public_access_block": ALL_OFF,
        "encryption": KMS,
        "versioning": "Enabled",
        "policy": None,
    }
    return make_resource("my-bucket", "S3", "ap-southeast-2", "my-bucket", attributes)


def scan(client, resources) -> None:
    result = {"resources": resources, "errors": []}
    findings = score_findings(run_rules(resources), result, REGIONS)
    with client.app.state.session_factory() as session:
        created = store.create_scan(session, REGIONS)
        store.save_result(session, created.id, result, findings)


def load(client, entries) -> None:
    with client.app.state.session_factory() as session:
        import_parsed(session, parse_bytes(to_bytes(entries)), "local")


def by_rule(client, rule_id: str) -> dict:
    return next(f for f in client.get("/api/findings").json() if f["rule_id"] == rule_id)


def fix_of(client, rule_id: str) -> dict:
    finding_id = by_rule(client, rule_id)["finding_id"]
    return client.post(f"/api/findings/{finding_id}/fix").json()


# Blast radius is gone


def test_the_blast_radius_module_no_longer_exists():
    assert importlib.util.find_spec("cloudshield.fixes.blast") is None


def test_no_fix_response_or_schema_mentions_blast_radius(tmp_path):
    client = make_client(tmp_path)
    scan(client, [bucket()])
    load(client, [entry(check=LENGTH_CHECK, uid=PASSWORD_ARN, group="iam")])
    own = fix_of(client, "CIS-S3-001")
    imported = fix_of(client, f"PRW-{LENGTH_CHECK}")

    shown = json.dumps([own, imported, client.get("/openapi.json").json()]).lower()

    assert "blast" not in shown
    assert "impact_note" not in shown
    assert "blast_radius" not in own
    assert "blast_radius" not in imported


def test_the_prompt_and_the_instruction_never_mention_blast_radius():
    context = {
        "finding": {
            "rule_id": "CIS-S3-001",
            "title": "t",
            "severity": "HIGH",
            "resource_type": "S3",
            "resource_id": "my-bucket",
            "evidence": {"items": []},
        },
        "knowledge": "What the rule checks.",
        "patches": [],
        "guidance": [],
        "pre_checks": ["Check the policy."],
        "not_checked": NOT_CHECKED["CIS-S3-001"],
    }

    body, data = explain.build_request(context)

    shown = json.dumps(body).lower() + data.lower()
    assert "blast" not in shown
    assert "not_checked" in shown
    assert "did not check" in explain.SYSTEM_INSTRUCTION
    assert "never say that a change is safe" in explain.SYSTEM_INSTRUCTION.lower()


def test_a_new_fix_stores_an_empty_blast_radius_and_the_column_is_kept(tmp_path):
    client = make_client(tmp_path)
    scan(client, [bucket()])
    fix_of(client, "CIS-S3-001")

    with client.app.state.session_factory() as session:
        row = session.scalars(select(FixRow)).one()

    assert row.blast_radius == {}
    assert "blast_radius" in FixRow.__table__.columns


def test_a_stored_fix_made_before_this_change_is_rebuilt_on_the_next_request(tmp_path):
    client = make_client(tmp_path)
    scan(client, [bucket()])
    first = fix_of(client, "CIS-S3-001")
    with client.app.state.session_factory() as session:
        row = session.scalars(select(FixRow)).one()
        row.evidence_hash = "made-before-the-change"
        row.blast_radius = {"level": "unknown", "factors": [], "notes": ["old"]}
        row.explanation = {**row.explanation, "what_could_break": "Blast radius: unknown."}
        session.commit()

    again = fix_of(client, "CIS-S3-001")

    assert "blast" not in again["explanation"]["what_could_break"].lower()
    assert again["explanation"] == first["explanation"]
    with client.app.state.session_factory() as session:
        row = session.scalars(select(FixRow)).one()
        assert row.evidence_hash != "made-before-the-change"
        assert row.blast_radius == {}


# Honesty stays: pre-checks and what was not checked


def test_an_own_fix_lists_what_was_not_checked_and_the_explanation_says_so(tmp_path):
    client = make_client(tmp_path)
    scan(client, [bucket()])

    fix = fix_of(client, "CIS-S3-001")

    assert fix["not_checked"] == NOT_CHECKED["CIS-S3-001"]
    assert fix["pre_checks"]
    could_break = fix["explanation"]["what_could_break"]
    assert "CloudShield did not check:" in could_break
    assert "Static website hosting" in could_break
    assert fix["pre_checks"][0] in could_break
    assert "safe" not in could_break.lower()


def test_every_own_rule_says_what_was_not_checked():
    for rule in ALL_RULES:
        assert NOT_CHECKED[rule.id], rule.id
        for item in NOT_CHECKED[rule.id]:
            assert item.strip()


def test_not_checked_is_read_from_the_rule_each_time_and_not_stored(tmp_path):
    client = make_client(tmp_path)
    scan(client, [bucket()])
    finding_id = by_rule(client, "CIS-S3-001")["finding_id"]
    fix_of(client, "CIS-S3-001")

    stored = client.get(f"/api/findings/{finding_id}/fix").json()

    assert stored["not_checked"] == NOT_CHECKED["CIS-S3-001"]
    assert "not_checked" not in FixRow.__table__.columns
    assert "cloudshield_steps" not in FixRow.__table__.columns


# Imported findings: What to do


def test_an_imported_check_with_an_entry_gets_cloudshield_steps(tmp_path):
    client = make_client(tmp_path)
    load(client, [entry(check=LENGTH_CHECK, uid=PASSWORD_ARN, group="iam")])

    fix = fix_of(client, f"PRW-{LENGTH_CHECK}")

    steps = fix["cloudshield_steps"]
    expected = guidance_for(LENGTH_CHECK)
    assert steps["check_id"] == LENGTH_CHECK
    assert steps["docs_url"] == expected["docs_url"]
    assert steps["verified_on"] == expected["verified_on"]
    assert [s["text"] for s in steps["steps"]] == [s["text"] for s in expected["steps"]]
    assert steps["steps"][0]["command"] == "aws iam get-account-password-policy"
    assert steps["before_you_apply"] == expected["before_you_apply"]
    assert fix["pre_checks"] == expected["before_you_apply"]
    assert fix["not_checked"] == []


def test_an_imported_check_with_no_entry_keeps_the_generic_guidance(tmp_path):
    client = make_client(tmp_path)
    load(client, [entry(check="s3_bucket_cross_region_replication")])

    fix = fix_of(client, "PRW-s3_bucket_cross_region_replication")

    assert fix["cloudshield_steps"] is None
    assert fix["pre_checks"] == ["Find out what depends on this resource before you change it."]
    assert fix["guidance"][0] == "Fix s3_bucket_cross_region_replication like this."


def test_the_steps_come_back_when_the_stored_fix_is_read_again(tmp_path):
    client = make_client(tmp_path)
    load(client, [entry(check=LENGTH_CHECK, uid=PASSWORD_ARN, group="iam")])
    posted = fix_of(client, f"PRW-{LENGTH_CHECK}")
    finding_id = by_rule(client, f"PRW-{LENGTH_CHECK}")["finding_id"]

    read = client.get(f"/api/findings/{finding_id}/fix").json()

    assert read["cloudshield_steps"] == posted["cloudshield_steps"]


def test_our_own_findings_never_get_imported_steps(tmp_path):
    client = make_client(tmp_path)
    scan(client, [bucket()])

    assert fix_of(client, "CIS-S3-001")["cloudshield_steps"] is None


def test_an_imported_fix_has_no_ai_text_only_the_one_plain_line(tmp_path):
    client = make_client(tmp_path)
    load(client, [entry(check=LENGTH_CHECK, uid=PASSWORD_ARN, group="iam")])

    explanation = fix_of(client, f"PRW-{LENGTH_CHECK}")["explanation"]

    assert explanation["skipped_reason"] == "CloudShield did not collect this evidence."
    assert explanation["what_changes"] == ""
    assert explanation["what_could_break"] == ""
    assert explanation["why_it_matters"] == f"Risk of {LENGTH_CHECK}."


def test_the_imported_verify_text_says_how_to_check_it(tmp_path):
    client = make_client(tmp_path)
    load(client, [entry(check=LENGTH_CHECK, uid=PASSWORD_ARN, group="iam")])

    verify = fix_of(client, f"PRW-{LENGTH_CHECK}")["verify"]

    assert "full scan" in verify
    assert "python -m cloudshield.imports prowler <file>" in verify


# Score breakdown


def test_the_breakdown_of_our_own_score_is_the_base_plus_the_context(tmp_path):
    client = make_client(tmp_path)
    scan(client, [bucket()])

    breakdown = by_rule(client, "CIS-S3-001")["score_breakdown"]

    assert breakdown == {
        "base": 70,
        "base_source": "cloudshield",
        "adjustments": 15,
        "capped": False,
        "basis": "context adjusted",
    }
    assert by_rule(client, "CIS-S3-001")["risk_score"] == 85


def test_the_breakdown_of_an_imported_score_with_no_scan_data(tmp_path):
    client = make_client(tmp_path)
    load(client, [entry(check="elsewhere", uid="arn:aws:s3:::other-bucket")])

    finding = by_rule(client, "PRW-elsewhere")

    assert finding["risk_score"] == 70
    assert finding["score_breakdown"] == {
        "base": 70,
        "base_source": "scanner",
        "adjustments": 0,
        "capped": False,
        "basis": "severity only",
    }


def test_the_breakdown_of_an_imported_score_when_our_scan_has_the_resource(tmp_path):
    client = make_client(tmp_path)
    scan(client, [bucket()])
    load(client, [entry(check="other_check", uid=BUCKET_ARN)])

    finding = by_rule(client, "PRW-other_check")

    assert finding["risk_score"] == 85
    assert finding["score_breakdown"]["base_source"] == "scanner"
    assert finding["score_breakdown"]["adjustments"] == 15
    assert finding["score_breakdown"]["basis"] == "context adjusted"


def test_a_score_that_was_capped_says_so(tmp_path):
    client = make_client(tmp_path)
    scan(client, [bucket()])
    load(client, [entry(check="critical_check", uid=BUCKET_ARN, severity="Critical")])

    finding = by_rule(client, "PRW-critical_check")

    assert finding["risk_score"] == 100
    assert finding["score_breakdown"]["base"] == 90
    assert finding["score_breakdown"]["adjustments"] == 15
    assert finding["score_breakdown"]["capped"] is True


def test_a_finding_with_no_score_has_no_breakdown(tmp_path):
    client = make_client(tmp_path)
    load(
        client,
        [entry(check="info_check", uid=None, severity="Informational", severity_id=1)],
    )

    finding = by_rule(client, "PRW-info_check")

    assert finding["risk_score"] is None
    assert finding["score_breakdown"] is None


@pytest.mark.parametrize(
    ("severity", "base"), [("CRITICAL", 90), ("HIGH", 70), ("MEDIUM", 40), ("LOW", 20)]
)
def test_the_base_comes_from_the_same_table_the_scoring_code_uses(severity, base):
    result = score_breakdown(severity, base, [], "prowler", "severity only")

    assert result["base"] == base
    assert result["adjustments"] == 0


def test_the_breakdown_adds_up_every_factor():
    factors = [{"adjustment": 15}, {"adjustment": 10}, {"adjustment": 0}]

    result = score_breakdown("MEDIUM", 65, factors, "cloudshield", "context adjusted")

    assert (result["base"], result["adjustments"], result["capped"]) == (40, 25, False)
