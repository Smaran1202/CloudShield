import re
from datetime import datetime
from importlib.metadata import version
from pathlib import Path

import pytest

from cloudshield.config import Settings
from cloudshield.db.models import Base, FindingRow, ImportRow, ScanRow
from cloudshield.db.session import make_engine, make_session_factory
from cloudshield.report import numbers
from cloudshield.report.__main__ import main

ACCOUNT = "123456789012"
POLICY = f"arn:aws:iam::{ACCOUNT}:policy/deploy"
ACL = f"arn:aws:ec2:us-east-1:{ACCOUNT}:network-acl/acl-1"
SG_1 = "sg-0123456789abcdef0"
SG_2 = "sg-0fedcba9876543210"
NOW = datetime(2026, 11, 1, 12, 0, 0)
ALL_ON = dict.fromkeys(
    ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"), True
)
REAL_NAMES = [
    ACCOUNT,
    "aaa-customer-data",
    "bbb-logs",
    "ccc-reports",
    "ddd-old",
    SG_1,
    SG_2,
    "policy/deploy",
    "acl-1",
]
IMPORTED = {"source": "prowler"}
MERGED = {**IMPORTED, "merged_into": "own-a"}
DISAGREE = {**IMPORTED, "tools_disagree": True}
RESOLVED_OWN = {
    "status": "RESOLVED",
    "resolved_at": datetime(2026, 10, 5),
    "resolution_reason": "no longer detected",
}
RESOLVED_IMPORTED = {
    **IMPORTED,
    "status": "RESOLVED",
    "resolved_at": datetime(2026, 10, 6),
    "resolution_reason": "passed in a newer import",
}


def finding(finding_id, rule, resource, severity, score, kind="S3", **fields) -> FindingRow:
    values = {
        "title": "t",
        "category": "c",
        "status": "OPEN",
        "details": {},
        "first_seen_at": NOW,
        "last_seen_at": NOW,
    }
    return FindingRow(
        finding_id=finding_id,
        rule_id=rule,
        resource_id=resource,
        resource_type=kind,
        severity=severity,
        risk_score=score,
        **{**values, **fields},
    )


def import_row(sha: str, **fields) -> ImportRow:
    values = {
        "source": "prowler",
        "imported_at": NOW,
        "counts": {},
        "regions_covered": [],
        "checks_covered": [],
    }
    return ImportRow(file_sha256=sha, **{**values, **fields})


def make_database(path: Path) -> None:
    engine = make_engine(f"sqlite:///{path}")
    Base.metadata.create_all(engine)
    with make_session_factory(engine)() as session:
        session.add_all(
            [
                ScanRow(
                    status="completed",
                    regions=["us-east-1"],
                    started_at=datetime(2026, 10, 1, 10, 0, 0),
                    finished_at=datetime(2026, 10, 1, 10, 0, 30),
                    resource_count=3,
                    finding_count=4,
                    account_settings={"s3_public_access_block": ALL_ON},
                ),
                ScanRow(status="failed", regions=["us-east-1"]),
                import_row(
                    "a" * 64,
                    external_account_id=ACCOUNT,
                    origin="dashboard",
                    run_mode="docker",
                    tool_version="5.44.0",
                    pass_count=7,
                    fail_count=3,
                ),
                import_row("b" * 64, origin="upload"),
            ]
        )
        session.add_all(
            [
                finding("own-a", "CIS-S3-001", "aaa-customer-data", "HIGH", 95),
                finding("own-b", "CIS-S3-001", "bbb-logs", "HIGH", 85),
                finding("own-c", "CIS-SG-001", SG_1, "HIGH", 60, "Security Group"),
                finding("own-d", "CIS-S3-003", "ccc-reports", "MEDIUM", 40),
                finding("own-e", "CIS-S3-002", "ccc-reports", "INFO", None),
                finding("own-f", "CIS-S3-003", "ccc-reports", "MEDIUM", 40, disposition="accepted"),
                finding("own-g", "CIS-S3-003", "ccc-reports", "MEDIUM", 30, tools_disagree=True),
                finding("own-h", "CIS-S3-001", "ddd-old", "HIGH", 70, **RESOLVED_OWN),
                finding("imp-1", "PRW-x", POLICY, "HIGH", 70, "IAM Policy", **IMPORTED),
                finding("imp-2", "PRW-x", ACCOUNT, "CRITICAL", 90, "Account", **IMPORTED),
                finding("imp-3", "PRW-y", "aaa-customer-data", "MEDIUM", 40, **MERGED),
                finding("imp-4", "PRW-x", SG_2, "LOW", 20, "Security Group", **RESOLVED_IMPORTED),
                finding("imp-5", "PRW-z", ACL, "INFO", None, "Network ACL", **IMPORTED),
                finding("imp-6", "PRW-y", "bbb-logs", "HIGH", 70, **DISAGREE),
            ]
        )
        session.commit()
    engine.dispose()


def build(tmp_path, settings=None, experiments=None):
    path = tmp_path / "fixture.db"
    if not path.exists():
        make_database(path)
    engine = make_engine(f"sqlite:///{path}")
    with make_session_factory(engine)() as session:
        tables, aliases = numbers.build_tables(
            session, settings or Settings(), NOW, experiments or tmp_path / "none"
        )
    engine.dispose()
    return tables, aliases


def rows_of(tables: list, title: str) -> list:
    return next(rows for name, _, rows in tables if name == title)


def titles(tables: list) -> list[str]:
    return [title for title, _, _ in tables]


def test_lane_thresholds_are_the_ones_in_the_dashboard():
    lanes_file = Path(__file__).resolve().parents[1] / "web" / "src" / "lanes.ts"

    found = re.search(r"fixNow: (\d+), next: (\d+)", lanes_file.read_text(encoding="utf-8"))

    assert (numbers.FIX_NOW, numbers.NEXT) == (int(found[1]), int(found[2]))


def test_lanes_count_like_the_dashboard(tmp_path):
    tables, _ = build(tmp_path)

    assert rows_of(tables, "Findings per lane") == [
        ["Fix now", 2, 1, 3],
        ["Next", 1, 2, 3],
        ["Later", 2, 0, 2],
        ["Informational", 1, 1, 2],
        ["Dismissed", 1, 0, 1],
        ["Done (resolved)", 1, 1, 2],
    ]


def test_own_findings_by_rule_and_severity(tmp_path):
    tables, _ = build(tmp_path)

    assert rows_of(tables, "Own findings by rule and severity") == [
        ["CIS-S3-001", "HIGH", 2, 1],
        ["CIS-S3-002", "INFO", 1, 0],
        ["CIS-S3-003", "MEDIUM", 3, 0],
        ["CIS-SG-001", "HIGH", 1, 0],
    ]


def test_imported_findings_by_severity_keep_merged_ones_apart(tmp_path):
    tables, _ = build(tmp_path)

    assert rows_of(tables, "Imported findings by severity") == [
        ["CRITICAL", 1, 0, 0],
        ["HIGH", 2, 0, 0],
        ["MEDIUM", 0, 0, 1],
        ["LOW", 0, 1, 0],
        ["INFO", 1, 0, 0],
    ]


def test_merged_pairs_and_disagreements(tmp_path):
    tables, _ = build(tmp_path)

    assert rows_of(tables, "Merged pairs and disagreements") == [
        ["merged pairs", 1],
        ["tools disagree, own findings", 1],
        ["tools disagree, imported findings", 1],
    ]


def test_resolved_findings_have_a_date_a_reason_and_an_alias_for_the_resource(tmp_path):
    tables, _ = build(tmp_path)

    assert rows_of(tables, "Resolved findings") == [
        ["imported", "PRW-x", "sg-2", "2026-10-06", "passed in a newer import"],
        ["own", "CIS-S3-001", "bucket-4", "2026-10-05", "no longer detected"],
    ]


def test_scans_and_imports_are_listed_with_their_own_numbers(tmp_path):
    tables, _ = build(tmp_path)

    assert rows_of(tables, "Scans") == [
        [1, "completed", 30.0, 3, 4, 0],
        [2, "failed", "n/a", 0, 0, 0],
    ]
    assert rows_of(tables, "Imports") == [
        [1, "dashboard", "docker", "5.44.0", 7, 3],
        [2, "upload", "n/a", "n/a", "n/a", "n/a"],
    ]
    assert rows_of(tables, "Totals") == [
        ["scans", 2],
        ["imports", 2],
        ["own findings stored", 8],
        ["imported findings stored", 6],
    ]


def test_guardrails_are_counted_by_status_from_the_last_completed_scan(tmp_path):
    tables, _ = build(tmp_path)

    assert ["active", 1] in rows_of(tables, "Guardrails by status")


def test_versions_come_from_the_package_and_the_imports(tmp_path):
    tables, _ = build(tmp_path)

    assert rows_of(tables, "Versions") == [
        ["CloudShield", version("cloudshield")],
        ["imported scanner (from the import files)", "5.44.0"],
    ]


def test_model_names_are_listed_and_the_key_is_never_read(tmp_path):
    settings = Settings(gemini_model="model-a", gemini_api_key="secret-key-value")
    tables, aliases = build(tmp_path, settings)

    text = numbers.markdown(tables, aliases)

    assert ["GEMINI_MODEL", "model-a"] in rows_of(tables, "AI model settings")
    assert ["EMBEDDING_MODEL", "not set"] in rows_of(tables, "AI model settings")
    assert "secret-key-value" not in text


def test_test_counts_are_placeholders(tmp_path):
    tables, _ = build(tmp_path)

    counts = {row[1] for row in rows_of(tables, "Test counts")}
    assert counts == {"(fill in by hand)"}


def test_experiment_summaries_are_added_only_when_the_files_exist(tmp_path):
    results = tmp_path / "results"
    results.mkdir()
    (results / "e1_summary.csv").write_text("scenario,cases\nscan_fault,18\n", encoding="utf-8")

    with_file, _ = build(tmp_path, experiments=results)
    without, _ = build(tmp_path, experiments=tmp_path / "missing")

    assert rows_of(with_file, "Experiment E1 summary") == [["scan_fault", "18"]]
    assert "Experiment E4 summary" not in titles(with_file)
    assert "Experiment E1 summary" not in titles(without)


def test_no_real_account_id_arn_or_resource_name_is_in_the_output(tmp_path):
    tables, aliases = build(tmp_path)

    text = numbers.markdown(tables, aliases) + numbers.long_csv(tables, aliases)

    for real in REAL_NAMES:
        assert real not in text


def test_a_twelve_digit_number_that_was_not_expected_is_still_replaced():
    aliases = numbers.Aliases(set())

    assert aliases.scrub("see 999988887777 and 999988887777") == "see acct-1 and acct-1"


def test_aliases_are_the_same_on_every_run(tmp_path):
    first, _ = build(tmp_path)
    second, _ = build(tmp_path)

    assert rows_of(first, "Resolved findings") == rows_of(second, "Resolved findings")


def test_the_command_prints_and_saves_markdown_and_csv_and_nothing_else(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.chdir(tmp_path)
    make_database(tmp_path / "fixture.db")

    code = main(
        ["numbers", "--db", "fixture.db", "--out", "n.md", "--csv", "n.csv"], load_env=False
    )

    printed = capsys.readouterr().out
    assert code == 0
    assert printed == (tmp_path / "n.md").read_text(encoding="utf-8") + "\n"
    assert (tmp_path / "n.csv").read_text(encoding="utf-8").startswith("section,row,column,value")
    assert sorted(p.name for p in tmp_path.iterdir()) == ["fixture.db", "n.csv", "n.md"]


def test_the_command_stops_and_creates_nothing_when_the_database_is_missing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    with pytest.raises(SystemExit, match="No such database"):
        main(["numbers", "--db", "missing.db"], load_env=False)

    assert list(tmp_path.iterdir()) == []
