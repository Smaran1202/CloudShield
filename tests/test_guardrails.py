import json
import re
from types import SimpleNamespace
from urllib.parse import urlparse

import boto3
import pytest
import yaml
from fastapi.testclient import TestClient
from moto import mock_aws
from prowler_data import entry, to_bytes

from cloudshield.api.app import create_app
from cloudshield.db import store
from cloudshield.db.models import Base
from cloudshield.db.session import make_engine
from cloudshield.fixes.export import write_guardrail_files
from cloudshield.fixes.templates import BUILDERS
from cloudshield.guardrails.catalog import BY_RULE, GUARDRAILS, guardrails_for
from cloudshield.guardrails.status import BLOCK_NAMES, guardrail_status
from cloudshield.risk.scoring import score_findings
from cloudshield.rules import run_rules
from cloudshield.scanner.account import collect_account_settings
from cloudshield.scanner.common import make_resource

KINDS = {"account_setting", "pipeline_check", "detective_rule", "organization_policy"}
SCOPES = {"resource", "account", "organization"}
PATCH_FORMATS = {"terraform", "cloudformation", "cli", "github_actions"}
CLI_PREFIXES = (
    "aws s3control put-public-access-block ",
    "aws organizations enable-policy-type ",
    "aws organizations create-policy ",
    "aws organizations attach-policy ",
    "aws configservice put-config-rule ",
    "aws iam put-role-permissions-boundary ",
)
ALL_ON = dict.fromkeys(BLOCK_NAMES, True)
JSON = {"Content-Type": "application/json"}
REGIONS = ["us-east-1"]


def scan_with(settings: dict) -> SimpleNamespace:
    return SimpleNamespace(account_settings=settings)


def by_kind(kind: str) -> list[dict]:
    return [g for g in GUARDRAILS.values() if g["kind"] == kind]


def cli_lines(patch: dict) -> list[str]:
    return [x for x in patch["content"].splitlines() if x and not x.startswith("#")]


@pytest.mark.parametrize("guardrail", GUARDRAILS.values(), ids=list(GUARDRAILS))
def test_every_guardrail_has_valid_fields_and_an_aws_docs_link(guardrail):
    assert guardrail["kind"] in KINDS
    assert guardrail["scope"] in SCOPES
    assert urlparse(guardrail["docs_url"]).hostname == "docs.aws.amazon.com"
    assert guardrail["docs_url"].startswith("https://")
    for name in ("title", "prevents", "affects", "cost"):
        assert guardrail[name].strip()
    assert guardrail["patches"]


@pytest.mark.parametrize("guardrail", GUARDRAILS.values(), ids=list(GUARDRAILS))
def test_every_guardrail_patch_is_valid_text(guardrail):
    for patch in guardrail["patches"]:
        content = patch["content"]
        assert patch["format"] in PATCH_FORMATS
        assert patch["title"].strip()
        assert patch["needs_input"] == bool(patch["inputs_needed"])
        assert ("REPLACE_WITH" in content) == patch["needs_input"]
        if patch["format"] == "cli":
            assert all(line.startswith(CLI_PREFIXES) for line in cli_lines(patch))
            assert not re.search(r"[;|&`]|\$\(", "\n".join(cli_lines(patch)))
        if patch["format"] == "cloudformation" and not patch["instructions_only"]:
            assert "Resources" in yaml.safe_load(content)
        if patch["format"] == "terraform" and not patch["instructions_only"]:
            assert content.startswith("resource ")
            assert content.count("{") == content.count("}")
        if patch["format"] == "github_actions":
            assert "jobs" in yaml.safe_load(content)
        for file in patch["files"]:
            assert file["name"].endswith(".json")
            assert isinstance(json.loads(file["content"]), dict)


def test_guardrail_ids_are_unique_and_every_rule_in_the_map_is_one_of_ours():
    assert len({g["id"] for g in GUARDRAILS.values()}) == len(GUARDRAILS)
    assert set(BY_RULE) <= set(BUILDERS)
    for ids in BY_RULE.values():
        assert set(ids) <= set(GUARDRAILS)


def test_the_account_setting_has_no_cloudformation_patch_because_aws_has_no_resource_for_it():
    formats = [p["format"] for p in GUARDRAILS["s3-account-block-public-access"]["patches"]]

    assert formats == ["terraform", "cli"]


def test_the_pipeline_checks_use_the_checkov_ids_read_in_its_documentation():
    versioning = GUARDRAILS["pipeline-s3-versioning"]["patches"][0]["content"]
    ssh = GUARDRAILS["pipeline-sg-no-open-ssh"]["patches"][0]["content"]

    assert "--check CKV_AWS_21 --hard-fail-on CKV_AWS_21" in versioning
    assert "--check CKV_AWS_24 --hard-fail-on CKV_AWS_24" in ssh


def test_the_policy_check_validates_identity_policies_and_fails_on_errors_and_warnings():
    content = GUARDRAILS["pipeline-iam-validate-policy"]["patches"][0]["content"]

    assert "aws accessanalyzer validate-policy" in content
    assert "--policy-type IDENTITY_POLICY" in content
    assert "findingType=='ERROR' || findingType=='SECURITY_WARNING'" in content


def test_both_iam_rules_get_the_policy_check_and_the_boundary():
    for rule_id in ("CIS-IAM-001", "SX-IAM-PRIVESC-001"):
        ids = [g["id"] for g in guardrails_for(rule_id)]
        assert "pipeline-iam-validate-policy" in ids
        assert "iam-permissions-boundary" in ids


def test_the_informational_kms_rule_has_no_guardrails():
    assert guardrails_for("CIS-S3-002") == []


def test_account_setting_is_active_only_when_all_four_settings_are_on():
    guardrail = GUARDRAILS["s3-account-block-public-access"]

    status, reason = guardrail_status(guardrail, scan_with({"s3_public_access_block": ALL_ON}))

    assert status == "active"
    assert "may come from an organization policy" in reason


@pytest.mark.parametrize("name", BLOCK_NAMES)
def test_account_setting_is_not_active_when_one_setting_is_off(name):
    guardrail = GUARDRAILS["s3-account-block-public-access"]
    settings = {"s3_public_access_block": {**ALL_ON, name: False}}

    status, reason = guardrail_status(guardrail, scan_with(settings))

    assert status == "not_active"
    assert name in reason


def test_account_setting_is_not_active_when_the_account_has_none():
    guardrail = GUARDRAILS["s3-account-block-public-access"]

    status, _ = guardrail_status(guardrail, scan_with({"s3_public_access_block": None}))

    assert status == "not_active"


@pytest.mark.parametrize("scan", [None, scan_with({}), scan_with({"other": ALL_ON})])
def test_account_setting_is_unknown_when_nothing_was_read(scan):
    guardrail = GUARDRAILS["s3-account-block-public-access"]

    status, _ = guardrail_status(guardrail, scan)

    assert status == "unknown"


def test_a_value_of_the_wrong_kind_is_never_read_as_active():
    guardrail = GUARDRAILS["s3-account-block-public-access"]
    settings = {"s3_public_access_block": dict.fromkeys(BLOCK_NAMES, "true")}

    status, _ = guardrail_status(guardrail, scan_with(settings))

    assert status == "not_active"


def test_what_cloudshield_cannot_read_is_unknown_even_when_a_scan_read_everything_on():
    scan = scan_with({"s3_public_access_block": ALL_ON})
    cannot_read = [
        g for g in GUARDRAILS.values() if g["reads"] is None and g["kind"] != "organization_policy"
    ]

    statuses = {g["id"]: guardrail_status(g, scan)[0] for g in cannot_read}

    assert statuses
    assert set(statuses.values()) == {"unknown"}


def test_organization_policies_always_need_an_organization_admin():
    scans = [None, scan_with({}), scan_with({"s3_public_access_block": ALL_ON})]
    policies = by_kind("organization_policy")

    for scan in scans:
        assert {guardrail_status(g, scan)[0] for g in policies} == {"needs_org_admin"}
    assert policies


@mock_aws
def test_the_scanner_reads_the_account_block_when_one_is_set():
    session = boto3.Session(region_name="us-east-1")
    account = session.client("sts").get_caller_identity()["Account"]
    session.client("s3control").put_public_access_block(
        AccountId=account, PublicAccessBlockConfiguration=ALL_ON
    )
    errors = []

    settings = collect_account_settings(session, "us-east-1", errors)

    assert settings == {"s3_public_access_block": ALL_ON}
    assert errors == []


@mock_aws
def test_the_scanner_reads_none_when_the_account_has_no_block():
    session = boto3.Session(region_name="us-east-1")
    errors = []

    settings = collect_account_settings(session, "us-east-1", errors)

    assert settings == {"s3_public_access_block": None}
    assert errors == []


@mock_aws
def test_an_access_error_leaves_the_setting_out_and_records_the_error(deny):
    deny("GetPublicAccessBlock")
    session = boto3.Session(region_name="us-east-1")
    errors = []

    settings = collect_account_settings(session, "us-east-1", errors)

    assert settings == {}
    assert [e["service"] for e in errors] == ["s3control"]


def make_client(tmp_path) -> TestClient:
    url = f"sqlite:///{tmp_path / 'test.db'}"
    Base.metadata.create_all(make_engine(url))
    return TestClient(create_app(database_url=url, load_env=False))


def bucket() -> dict:
    attributes = {"public_access_block": None, "encryption": None, "versioning": "Disabled"}
    return make_resource("my-bucket", "S3", "us-east-1", "my-bucket", attributes)


def seed(client, account_settings: dict | None) -> None:
    result = {"resources": [bucket()], "errors": []}
    if account_settings is not None:
        result["account_settings"] = account_settings
    findings = score_findings(run_rules(result["resources"]), result, REGIONS)
    with client.app.state.session_factory() as session:
        scan = store.create_scan(session, REGIONS)
        store.save_result(session, scan.id, result, findings)


def fix_guardrails(client, rule_id: str) -> dict:
    findings = client.get("/api/findings", params={"rule_id": rule_id}).json()
    fix = client.post(f"/api/findings/{findings[0]['finding_id']}/fix").json()
    return {g["id"]: g for g in fix["guardrails"]}


def test_the_fix_for_our_own_finding_lists_its_guardrails_with_statuses(tmp_path):
    client = make_client(tmp_path)
    seed(client, {"s3_public_access_block": ALL_ON})

    shown = fix_guardrails(client, "CIS-S3-001")

    assert list(shown) == ["s3-account-block-public-access", "s3-organization-block-public-access"]
    assert shown["s3-account-block-public-access"]["status"] == "active"
    assert shown["s3-organization-block-public-access"]["status"] == "needs_org_admin"


def test_a_scan_that_could_not_read_the_account_setting_gives_unknown_in_the_api(tmp_path):
    client = make_client(tmp_path)
    seed(client, None)

    shown = fix_guardrails(client, "CIS-S3-001")

    assert shown["s3-account-block-public-access"]["status"] == "unknown"


def test_pipeline_checks_show_unknown_in_the_api(tmp_path):
    client = make_client(tmp_path)
    seed(client, {"s3_public_access_block": ALL_ON})

    shown = fix_guardrails(client, "CIS-S3-003")

    assert {g["status"] for g in shown.values()} == {"unknown"}
    assert [g["kind"] for g in shown.values()] == ["pipeline_check", "detective_rule"]


def test_the_guardrail_list_has_every_guardrail_and_never_shows_active_without_a_read(tmp_path):
    client = make_client(tmp_path)
    seed(client, None)

    listed = client.get("/api/guardrails").json()

    assert [g["id"] for g in listed] == list(GUARDRAILS)
    assert "active" not in {g["status"] for g in listed}


def test_an_imported_finding_shows_no_guardrails(tmp_path):
    client = make_client(tmp_path)
    seed(client, {"s3_public_access_block": ALL_ON})
    client.post("/api/imports/prowler", content=to_bytes([entry()]), headers=JSON)
    imported = client.get("/api/findings", params={"source": "prowler"}).json()[0]

    fix = client.post(f"/api/findings/{imported['finding_id']}/fix").json()

    assert fix["guardrails"] == []


def test_export_writes_each_guardrail_to_its_own_folder_with_a_review_header(tmp_path):
    out = tmp_path / "out"

    written = write_guardrail_files(guardrails_for("CIS-S3-001"), out)

    names = sorted(str(p.relative_to(out)).replace("\\", "/") for p in written)
    assert names == [
        "guardrails/s3-account-block-public-access/guardrail.ps1",
        "guardrails/s3-account-block-public-access/guardrail.tf",
        "guardrails/s3-organization-block-public-access/guardrail.ps1",
        "guardrails/s3-organization-block-public-access/s3-block-public-access-policy.json",
    ]
    script = (out / "guardrails/s3-account-block-public-access/guardrail.ps1").read_text()
    assert "Review this file before you use it" in script
    assert "What it prevents:" in script


def test_export_writes_the_pipeline_file_as_a_workflow_that_still_parses(tmp_path):
    out = tmp_path / "out"

    write_guardrail_files(guardrails_for("CIS-S3-003"), out)

    path = out / "guardrails/pipeline-s3-versioning/workflow.yml"
    text = path.read_text(encoding="utf-8")
    assert text.startswith("# CloudShield guardrail:")
    assert "CKV_AWS_21" in yaml.safe_load(text)["jobs"]["checkov"]["steps"][-1]["run"]
