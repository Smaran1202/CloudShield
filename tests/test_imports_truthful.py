from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from prowler_data import ACCOUNT, BUCKET_ARN, GROUP_ARN, POLICY_ARN, entry, to_bytes
from sqlalchemy import create_engine, select, text

from cloudshield.api.app import create_app
from cloudshield.db import store
from cloudshield.db.models import Base, FindingRow, ImportRow
from cloudshield.db.session import make_engine
from cloudshield.findings import make_finding_id
from cloudshield.imports import mapping
from cloudshield.imports.__main__ import main as import_main
from cloudshield.imports.importer import import_parsed, refresh_parsed
from cloudshield.imports.parser import parse_bytes
from cloudshield.risk.scoring import score_findings
from cloudshield.rules import run_rules
from cloudshield.scanner.common import make_resource

ROOT = Path(__file__).resolve().parents[1]
REGIONS = ["ap-southeast-2"]
ALL_OFF = {
    "BlockPublicAcls": False,
    "IgnorePublicAcls": False,
    "BlockPublicPolicy": False,
    "RestrictPublicBuckets": False,
}
ALL_ON = {name: True for name in ALL_OFF}
KMS = [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]
BLOCK_CHECK = "s3_bucket_level_public_access_block"
VERSIONING_CHECK = "s3_bucket_object_versioning"
INFO_ENTRY = entry(
    check="info", uid=GROUP_ARN, group="ec2", severity="Informational", severity_id=1
)
IMPORTED_BLOCK = make_finding_id(f"PRW-{BLOCK_CHECK}", "my-bucket")


def make_client(tmp_path) -> TestClient:
    url = f"sqlite:///{tmp_path / 'test.db'}"
    Base.metadata.create_all(make_engine(url))
    return TestClient(create_app(database_url=url, load_env=False))


def bucket(block=ALL_OFF, versioning="Enabled") -> dict:
    attributes = {
        "public_access_block": block,
        "encryption": KMS,
        "versioning": versioning,
        "policy": None,
    }
    return make_resource("my-bucket", "S3", "ap-southeast-2", "my-bucket", attributes)


def scan(client, resources, errors=None) -> None:
    result = {"resources": resources, "errors": errors or []}
    findings = score_findings(run_rules(resources), result, REGIONS)
    with client.app.state.session_factory() as session:
        created = store.create_scan(session, REGIONS)
        store.save_result(session, created.id, result, findings)


def load(client, entries, file_name=None) -> None:
    with client.app.state.session_factory() as session:
        import_parsed(session, parse_bytes(to_bytes(entries)), "local", file_name)


def listed(client) -> list[dict]:
    return client.get("/api/findings").json()


def by_rule(client, rule_id: str) -> dict:
    return next(f for f in listed(client) if f["rule_id"] == rule_id)


@pytest.fixture
def session(tmp_path):
    from cloudshield.db.session import make_session_factory

    engine = make_engine(f"sqlite:///{tmp_path / 'store.db'}")
    Base.metadata.create_all(engine)
    with make_session_factory(engine)() as session:
        yield session


def imported_row(session, entry_data, check="s3_bucket_public_access") -> FindingRow:
    import_parsed(session, parse_bytes(to_bytes([entry_data])), "local")
    return session.get(FindingRow, ("local", make_finding_id(f"PRW-{check}", "my-bucket")))


# 1. Titles


def test_the_title_of_an_imported_failure_is_the_failing_statement(session):
    row = imported_row(session, entry(status_detail="Bucket my-bucket has no public access block."))

    assert row.title == "Bucket my-bucket has no public access block."
    assert row.details["check_title"] == "Bucket does not block public access"


@pytest.mark.parametrize("empty", ["", "   "])
def test_a_missing_failing_statement_gives_a_title_that_starts_with_failed(session, empty):
    row = imported_row(session, entry(status_detail=empty))

    assert row.title == "Failed: Bucket does not block public access"


def test_no_imported_title_reads_like_the_passing_state(session):
    titles = [
        "Bucket does not block public access",
        "Network ACL does not allow ingress from 0.0.0.0/0 to any port",
        "IAM password policy requires at least one number",
    ]
    for number, title in enumerate(titles):
        import_parsed(
            session,
            parse_bytes(to_bytes([entry(check=f"c{number}", title=title, status_detail="")])),
            "local",
        )

    rows = session.scalars(select(FindingRow).where(FindingRow.source == "prowler")).all()

    assert len(rows) == 3
    for row in rows:
        assert row.title.startswith("Failed: ")
        assert row.title != row.details["check_title"]


# 2. Evidence


def test_every_imported_finding_has_the_required_evidence_items(session):
    row = imported_row(session, entry(severity="High"))

    facts = {item["fact"]: item for item in row.evidence["items"]}

    assert {item["certainty"] for item in row.evidence["items"]} == {"reported"}
    assert {item["source"] for item in row.evidence["items"]} == {"imported scan output"}
    assert facts["Failing statement"]["value"] == "Detail for s3_bucket_public_access."
    assert facts["Resource"]["value"] == {
        "uid": BUCKET_ARN,
        "type": "S3",
        "region": "ap-southeast-2",
    }
    assert facts["Check and severity"]["value"] == {
        "check_id": "s3_bucket_public_access",
        "severity": "High",
    }
    assert facts["Risk described by the scanner"]["value"] == "Risk of s3_bucket_public_access."


def test_an_imported_finding_has_evidence_even_when_the_tool_gave_no_text(session):
    bare = entry(status_detail="")
    bare["risk_details"] = ""
    bare["finding_info"]["desc"] = ""

    row = imported_row(session, bare)

    assert [item["fact"] for item in row.evidence["items"]] == ["Resource", "Check and severity"]


def test_the_api_returns_the_evidence_of_an_imported_finding(tmp_path):
    client = make_client(tmp_path)
    load(client, [entry()])

    finding = client.get("/api/findings").json()[0]

    assert len(finding["evidence"]["items"]) == 5
    assert finding["evidence"]["items"][0]["certainty"] == "reported"


def test_refresh_rewrites_title_evidence_and_details_but_not_status_or_dates(session):
    raw = to_bytes([entry()])
    import_parsed(session, parse_bytes(raw), "local")
    finding_id = make_finding_id("PRW-s3_bucket_public_access", "my-bucket")
    row = session.get(FindingRow, ("local", finding_id))
    first_seen = row.first_seen_at
    row.title = "Bucket does not block public access"
    row.evidence = {"items": []}
    row.details = {"remediation": "old"}
    row.status = "RESOLVED"
    row.resolution_reason = "passed in a newer import"
    row.risk_score = 12
    session.commit()

    result = refresh_parsed(session, parse_bytes(raw), "local", "file.json")

    assert result == {"refreshed": 1, "not_found": 0}
    assert row.title == "Detail for s3_bucket_public_access."
    assert len(row.evidence["items"]) == 5
    assert row.details["check_title"] == "Bucket does not block public access"
    assert row.status == "RESOLVED"
    assert row.resolution_reason == "passed in a newer import"
    assert row.first_seen_at == first_seen
    assert row.risk_score == 12


def test_refresh_reports_findings_it_does_not_have_and_creates_nothing(session):
    result = refresh_parsed(session, parse_bytes(to_bytes([entry()])), "local", None)

    assert result == {"refreshed": 0, "not_found": 1}
    assert session.scalars(select(FindingRow)).all() == []


def test_the_refresh_command_works_on_a_file_that_was_already_imported(
    tmp_path, monkeypatch, capsys
):
    url = f"sqlite:///{tmp_path / 'cli.db'}"
    Base.metadata.create_all(make_engine(url))
    monkeypatch.setenv("DATABASE_URL", url)
    path = tmp_path / "prowler-test.ocsf.json"
    path.write_bytes(to_bytes([entry()]))
    import_main(["prowler", str(path)], load_env=False)
    capsys.readouterr()

    code = import_main(["prowler", str(path), "--refresh"], load_env=False)

    out = capsys.readouterr().out
    assert code == 0
    assert "Refreshed: 1" in out
    with create_engine(url).connect() as connection:
        assert connection.execute(text("select count(*) from imports")).scalar() == 1


# 3. Merging duplicates


def test_the_mapping_has_only_the_two_confirmed_pairs():
    assert mapping.SAME_CHECK == {
        "s3_bucket_level_public_access_block": "CIS-S3-001",
        "s3_bucket_object_versioning": "CIS-S3-003",
    }


def test_when_both_report_the_same_thing_ours_stays_and_the_imported_one_is_merged(tmp_path):
    client = make_client(tmp_path)
    scan(client, [bucket()])

    load(client, [entry(check=BLOCK_CHECK)])

    ours = by_rule(client, "CIS-S3-001")
    assert [f["rule_id"] for f in listed(client)] == ["CIS-S3-001"]
    assert ours["corroborated_by"] == [
        {
            "source": "prowler",
            "check_id": BLOCK_CHECK,
            "status": "FAIL",
            "last_imported_at": ours["corroborated_by"][0]["last_imported_at"],
        }
    ]
    assert ours["corroborated_by"][0]["last_imported_at"] is not None
    assert ours["tools_disagree"] is False
    last = ours["evidence"]["items"][-1]
    assert last["fact"] == "Also reported by an imported scan"
    assert last["certainty"] == "reported"
    merged = client.get(f"/api/findings/{IMPORTED_BLOCK}").json()
    assert merged["merged_into"] == ours["finding_id"]


def test_a_merged_finding_is_left_out_of_counts_scores_and_lists(tmp_path):
    client = make_client(tmp_path)
    scan(client, [bucket()])
    before = client.get("/api/risk/summary").json()

    load(client, [entry(check=BLOCK_CHECK, severity="Critical")])

    after = client.get("/api/risk/summary").json()
    assert after["environment_score"] == before["environment_score"]
    assert after["counts_by_severity"] == before["counts_by_severity"]
    assert len(after["top_findings"]) == 1
    assert len(client.get("/api/findings", params={"source": "prowler"}).json()) == 0
    assert len(client.get("/api/findings", params={"status": "OPEN"}).json()) == 1


def test_the_corroboration_is_not_added_twice_by_a_second_import_or_a_rescan(tmp_path):
    client = make_client(tmp_path)
    scan(client, [bucket()])
    load(client, [entry(check=BLOCK_CHECK)])
    load(client, [entry(check=BLOCK_CHECK, uid=BUCKET_ARN, title="Other title")])

    scan(client, [bucket()])
    ours = by_rule(client, "CIS-S3-001")

    facts = [i["fact"] for i in ours["evidence"]["items"]]
    assert facts.count("Also reported by an imported scan") == 1
    assert len(ours["corroborated_by"]) == 1


def test_the_second_confirmed_pair_merges_too(tmp_path):
    client = make_client(tmp_path)
    scan(client, [bucket(block=ALL_ON, versioning="Disabled")])

    load(client, [entry(check=VERSIONING_CHECK)])

    ours = by_rule(client, "CIS-S3-003")
    assert ours["corroborated_by"][0]["check_id"] == VERSIONING_CHECK
    assert [f["rule_id"] for f in listed(client)] == ["CIS-S3-003"]


def test_when_ours_is_open_and_the_import_passes_both_stay_visible_and_are_flagged(tmp_path):
    client = make_client(tmp_path)
    scan(client, [bucket()])

    load(client, [entry(check=BLOCK_CHECK, status="PASS")])

    ours = by_rule(client, "CIS-S3-001")
    assert ours["tools_disagree"] is True
    assert ours["corroborated_by"][0]["status"] == "PASS"
    assert "Also reported by an imported scan" not in [i["fact"] for i in ours["evidence"]["items"]]
    assert ours["status"] == "OPEN"


def test_when_ours_passes_and_the_import_fails_both_views_stay_and_are_flagged(tmp_path):
    client = make_client(tmp_path)
    scan(client, [bucket(block=ALL_ON)])

    load(client, [entry(check=BLOCK_CHECK)])

    theirs = by_rule(client, f"PRW-{BLOCK_CHECK}")
    assert theirs["tools_disagree"] is True
    assert theirs["merged_into"] is None
    assert theirs["status"] == "OPEN"


def test_a_rescan_that_fixes_ours_turns_a_merge_into_a_disagreement(tmp_path):
    client = make_client(tmp_path)
    scan(client, [bucket()])
    load(client, [entry(check=BLOCK_CHECK)])
    assert len(listed(client)) == 1

    scan(client, [bucket(block=ALL_ON)])

    theirs = by_rule(client, f"PRW-{BLOCK_CHECK}")
    assert theirs["tools_disagree"] is True
    assert theirs["merged_into"] is None


def test_a_later_pass_unmerges_and_flags_a_disagreement_with_ours(tmp_path):
    client = make_client(tmp_path)
    scan(client, [bucket()])
    load(client, [entry(check=BLOCK_CHECK)])

    load(client, [entry(check=BLOCK_CHECK, status="PASS")])

    ours = by_rule(client, "CIS-S3-001")
    assert ours["tools_disagree"] is True
    assert client.get(f"/api/findings/{IMPORTED_BLOCK}").json()["merged_into"] is None


def test_without_any_scan_of_ours_an_imported_failure_is_not_flagged_or_merged(tmp_path):
    client = make_client(tmp_path)

    load(client, [entry(check=BLOCK_CHECK)])

    finding = listed(client)[0]
    assert finding["merged_into"] is None
    assert finding["tools_disagree"] is False


def test_a_partial_match_never_merges(tmp_path):
    client = make_client(tmp_path)
    document = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    policy = make_resource(
        POLICY_ARN,
        "IAM Policy",
        None,
        "deploy",
        {"document": document, "attached_to": {"users": [], "roles": [], "groups": []}},
    )
    scan(client, [policy])

    load(
        client,
        [
            entry(
                check="iam_customer_unattached_policy_no_administrative_privileges",
                uid=POLICY_ARN,
                group="iam",
            )
        ],
    )

    rules = {f["rule_id"] for f in listed(client)}
    assert {
        "CIS-IAM-001",
        "PRW-iam_customer_unattached_policy_no_administrative_privileges",
    } <= rules
    for finding in listed(client):
        assert finding["merged_into"] is None
        assert finding["tools_disagree"] is False
        assert finding["corroborated_by"] == []


NOT_COMPARED = "CloudShield could not read this setting, so the two results are not compared."
S3_ERROR = [{"service": "s3", "region": None, "resource": "my-bucket", "message": "denied"}]


def unreadable_bucket() -> dict:
    # The call that reads the public access block failed, so the key is missing.
    attributes = {"encryption": KMS, "versioning": "Enabled", "policy": None}
    return make_resource("my-bucket", "S3", "ap-southeast-2", "my-bucket", attributes)


def facts(finding: dict) -> list[str]:
    return [item["fact"] for item in finding["evidence"]["items"]]


def test_an_unknown_attribute_means_no_data_so_nothing_is_flagged_or_merged(tmp_path):
    client = make_client(tmp_path)
    scan(client, [unreadable_bucket()])

    load(client, [entry(check=BLOCK_CHECK)])

    theirs = by_rule(client, f"PRW-{BLOCK_CHECK}")
    assert theirs["tools_disagree"] is False
    assert theirs["merged_into"] is None
    assert theirs["status"] == "OPEN"
    assert NOT_COMPARED in facts(theirs)
    assert (
        next(i for i in theirs["evidence"]["items"] if i["fact"] == NOT_COMPARED)["certainty"]
        == "unknown"
    )


def test_an_unknown_attribute_with_an_imported_pass_adds_nothing_and_flags_nothing(tmp_path):
    client = make_client(tmp_path)
    scan(client, [unreadable_bucket()])

    load(client, [entry(check=BLOCK_CHECK, status="PASS")])

    assert listed(client) == []


def test_a_scan_error_for_the_service_keeps_both_findings_and_compares_nothing(tmp_path):
    client = make_client(tmp_path)
    scan(client, [bucket()])
    scan(client, [bucket()], errors=S3_ERROR)

    load(client, [entry(check=BLOCK_CHECK)])

    ours = by_rule(client, "CIS-S3-001")
    theirs = by_rule(client, f"PRW-{BLOCK_CHECK}")
    assert theirs["merged_into"] is None
    assert ours["corroborated_by"] == []
    assert ours["tools_disagree"] is False
    assert theirs["tools_disagree"] is False
    assert NOT_COMPARED in facts(ours)
    assert NOT_COMPARED in facts(theirs)
    assert "Also reported by an imported scan" not in facts(ours)


def test_a_scan_error_stops_a_disagreement_from_being_flagged(tmp_path):
    client = make_client(tmp_path)
    scan(client, [bucket(block=ALL_ON)], errors=S3_ERROR)

    load(client, [entry(check=BLOCK_CHECK)])

    assert by_rule(client, f"PRW-{BLOCK_CHECK}")["tools_disagree"] is False

    load(client, [entry(check=BLOCK_CHECK, status="PASS")])
    scan(client, [bucket()], errors=S3_ERROR)

    assert by_rule(client, "CIS-S3-001")["tools_disagree"] is False
    assert by_rule(client, "CIS-S3-001")["corroborated_by"] == []


def test_an_error_for_another_service_does_not_stop_the_comparison(tmp_path):
    client = make_client(tmp_path)
    errors = [{"service": "iam", "region": None, "resource": None, "message": "denied"}]
    scan(client, [bucket()], errors=errors)

    load(client, [entry(check=BLOCK_CHECK)])

    assert [f["rule_id"] for f in listed(client)] == ["CIS-S3-001"]
    assert NOT_COMPARED not in facts(by_rule(client, "CIS-S3-001"))


def test_the_comparison_happens_once_a_clean_scan_reads_the_setting(tmp_path):
    client = make_client(tmp_path)
    scan(client, [bucket()], errors=S3_ERROR)
    load(client, [entry(check=BLOCK_CHECK)])
    assert len(listed(client)) == 2

    scan(client, [bucket()])

    ours = by_rule(client, "CIS-S3-001")
    assert [f["rule_id"] for f in listed(client)] == ["CIS-S3-001"]
    assert NOT_COMPARED not in facts(ours)
    assert "Also reported by an imported scan" in facts(ours)


# 5. Import history


def test_the_import_keeps_the_file_name_the_tool_and_the_counts(session):
    entries = [entry(), entry(check="c2", status="PASS"), entry(check="c3", status="PASS")]

    result = import_parsed(session, parse_bytes(to_bytes(entries)), "local", "my-file.json")

    row = session.get(ImportRow, result["import_id"])
    assert row.file_name == "my-file.json"
    assert row.tool_name == "Prowler"
    assert row.tool_version == "5.44.0"
    assert row.pass_count == 2
    assert row.fail_count == 1


def test_the_command_stores_the_base_name_of_the_file_and_never_a_path(tmp_path, monkeypatch):
    url = f"sqlite:///{tmp_path / 'cli.db'}"
    Base.metadata.create_all(make_engine(url))
    monkeypatch.setenv("DATABASE_URL", url)
    folder = tmp_path / "private" / "folder"
    folder.mkdir(parents=True)
    path = folder / "prowler-test.ocsf.json"
    path.write_bytes(to_bytes([entry()]))

    import_main(["prowler", str(path)], load_env=False)

    with create_engine(url).connect() as connection:
        name = connection.execute(text("select file_name from imports")).scalar()
    assert name == "prowler-test.ocsf.json"
    assert "private" not in name


def test_the_imports_endpoint_lists_the_newest_first_with_its_counts(tmp_path):
    client = make_client(tmp_path)
    load(client, [entry(), entry(check="c2", status="PASS")], "first.json")
    load(
        client,
        [entry(status="PASS"), entry(check="c4"), entry(status="MUTED"), "text"],
        "second.json",
    )

    imports = client.get("/api/imports").json()

    assert [i["file_name"] for i in imports] == ["second.json", "first.json"]
    second, first = imports
    assert (first["findings_added"], first["resolved"], first["rejected"]) == (1, 0, 0)
    assert (second["findings_added"], second["resolved"], second["rejected"]) == (1, 1, 1)
    assert second["ignored"] == 1
    assert second["tool_name"] == "Prowler"
    assert second["tool_version"] == "5.44.0"
    assert (second["pass_count"], second["fail_count"]) == (1, 1)
    assert second["regions_covered"] == ["ap-southeast-2"]
    assert "file_sha256" not in second
    assert "external_account_id" not in second


def test_an_import_with_no_history_fields_is_listed_with_nulls(tmp_path):
    client = make_client(tmp_path)
    load(client, [entry()])
    with client.app.state.session_factory() as session:
        row = session.scalars(select(ImportRow)).one()
        row.file_name = row.tool_name = row.tool_version = None
        row.pass_count = row.fail_count = None
        session.commit()

    imported = client.get("/api/imports").json()[0]

    assert imported["file_name"] is None
    assert imported["pass_count"] is None


# 6. Imported-only resources


def test_imported_only_resources_lists_what_only_the_import_knows(tmp_path):
    client = make_client(tmp_path)
    scan(client, [bucket()])
    load(
        client,
        [
            entry(check="a", uid=BUCKET_ARN),
            entry(check="b", uid=GROUP_ARN, group="ec2", severity="Critical"),
            entry(check="c", uid=GROUP_ARN, group="ec2", severity="Low"),
            entry(check="d", uid=f"arn:aws:iam::{ACCOUNT}:root", group="iam", severity="Medium"),
        ],
    )

    resources = client.get("/api/resources/imported").json()

    assert [r["resource_id"] for r in resources] == [
        "sg-0abc123",
        f"arn:aws:iam::{ACCOUNT}:root",
    ]
    group = resources[0]
    assert group["resource_type"] == "Security Group"
    assert group["region"] == "ap-southeast-2"
    assert group["open_count"] == 2
    assert group["highest_risk"] == 90
    assert resources[1]["resource_type"] == "Account"
    assert resources[1]["highest_risk"] == 40


def test_imported_only_resources_count_only_open_findings(tmp_path):
    client = make_client(tmp_path)
    load(client, [entry(check="a", uid=GROUP_ARN, group="ec2")])
    load(client, [entry(check="a", uid=GROUP_ARN, group="ec2", status="PASS")])

    resource = client.get("/api/resources/imported").json()[0]

    assert resource["open_count"] == 0
    assert resource["highest_risk"] is None


def test_the_resources_endpoint_is_unchanged_by_imports(tmp_path):
    client = make_client(tmp_path)
    scan(client, [bucket()])
    before = client.get("/api/resources").json()

    load(client, [entry(check="a", uid=GROUP_ARN, group="ec2")])

    assert client.get("/api/resources").json() == before
    assert [r["resource_id"] for r in before] == ["my-bucket"]


# 7. Score basis


def test_the_score_basis_says_whether_context_was_used(tmp_path):
    client = make_client(tmp_path)
    scan(client, [bucket()])
    load(
        client,
        [
            entry(check="on_ours", uid=BUCKET_ARN),
            entry(check="elsewhere", uid=GROUP_ARN, group="ec2"),
            INFO_ENTRY,
        ],
    )

    rows = {f["rule_id"]: f for f in listed(client)}

    assert rows["CIS-S3-001"]["score_basis"] == "context adjusted"
    assert rows["PRW-on_ours"]["score_basis"] == "context adjusted"
    assert rows["PRW-on_ours"]["risk_score"] == 85
    assert rows["PRW-elsewhere"]["score_basis"] == "severity only"
    assert rows["PRW-elsewhere"]["risk_score"] == 70
    assert rows["PRW-info"]["score_basis"] == "severity only"
    assert rows["PRW-info"]["risk_score"] is None


# Migration


def test_the_migration_keeps_earlier_data_and_fills_the_new_fields(tmp_path, monkeypatch):
    url = f"sqlite:///{tmp_path / 'old.db'}"
    monkeypatch.setenv("DATABASE_URL", url)
    config = Config(str(ROOT / "alembic.ini"))
    migrations = ROOT / "src" / "cloudshield" / "db" / "migrations"
    config.set_main_option("script_location", str(migrations))
    command.upgrade(config, "0004")
    context = '[{"factor": "exposure", "adjustment": 15, "reason": "r", "certainty": "verified"}]'
    no_context = (
        '[{"factor": "context", "adjustment": 0, "reason": "context not available for '
        'imported findings", "certainty": "unknown"}]'
    )
    insert = (
        "insert into findings (finding_id, rule_id, resource_id, resource_type, title, "
        "severity, category, status, details, evidence, risk_score, risk_factors, "
        "first_seen_at, last_seen_at, last_scan_id, source) values "
        "(:id, :rule, :res, 'S3', 'T', 'HIGH', 'c', 'OPEN', '{}', '{\"items\": []}', 85, "
        ":factors, '2026-10-01 00:00:00', '2026-10-01 00:00:00', :scan, :source)"
    )
    with create_engine(url).begin() as connection:
        connection.execute(
            text(
                "insert into scans (id, status, regions, resource_count, finding_count, "
                "error_count, errors) values (1, 'completed', '[]', 0, 1, 0, '[]')"
            )
        )
        connection.execute(
            text(
                "insert into imports (id, source, file_sha256, imported_at, counts, "
                "regions_covered, checks_covered) values (1, 'prowler', 'abc', "
                '\'2026-10-02 00:00:00\', \'{"imported": 2, "passed": 0, "ignored": 0, '
                '"already_seen": 0, "resolved": 0, "rejected": 0}\', \'[]\', \'[]\')'
            )
        )
        rows = [
            ("F-own", "CIS-S3-001", "a", context, 1, "cloudshield"),
            ("F-PRW-ctx", "PRW-x", "b", context, None, "prowler"),
            ("F-PRW-none", "PRW-y", "c", no_context, None, "prowler"),
        ]
        for row_id, rule, resource, factors, scan_id, source in rows:
            connection.execute(
                text(insert),
                {
                    "id": row_id,
                    "rule": rule,
                    "res": resource,
                    "factors": factors,
                    "scan": scan_id,
                    "source": source,
                },
            )

    command.upgrade(config, "head")

    client = TestClient(create_app(database_url=url, load_env=False))
    found = {f["finding_id"]: f for f in listed(client)}
    assert found["F-own"]["score_basis"] == "context adjusted"
    assert found["F-PRW-ctx"]["score_basis"] == "context adjusted"
    assert found["F-PRW-none"]["score_basis"] == "severity only"
    for finding in found.values():
        assert finding["merged_into"] is None
        assert finding["tools_disagree"] is False
        assert finding["corroborated_by"] == []
        assert finding["disposition"] == "none"
        assert finding["dismissed"] is False
    history = client.get("/api/imports").json()[0]
    assert history["file_name"] is None
    assert history["pass_count"] is None
    assert history["findings_added"] == 2
    load(client, [entry(check="new")])
    assert len(listed(client)) == 4
