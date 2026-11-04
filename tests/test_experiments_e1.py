import csv

import pytest
from sqlalchemy import select

from cloudshield.db.models import FindingRow
from cloudshield.rules import ALL_RULES
from experiments import e1
from experiments.common import fake_aws, summarise
from experiments.faults import CALLS, Fault, inject, recording
from experiments.world import (
    build_world,
    copy_database,
    make_baseline,
    open_finding_ids,
    scan_world,
)


@pytest.fixture
def world(tmp_path):
    with fake_aws():
        ids = build_world()
        base = tmp_path / "base.db"
        before = make_baseline(base)
        yield e1.Setup(base, tmp_path, before), ids


def by_resolver(rows: list[dict]) -> dict[str, dict]:
    return {row["resolver"]: row for row in rows}


def test_the_fake_account_starts_with_an_open_finding_for_every_rule(world):
    setup, _ = world

    factory = copy_database(setup.base, setup.workdir / "copy.db")
    with factory() as session:
        rules = set(session.scalars(select(FindingRow.rule_id)).all())
        open_ids = open_finding_ids(session, "cloudshield")

    assert rules == {rule.id for rule in ALL_RULES}
    assert open_ids == setup.before
    assert len(open_ids) == 9


def test_the_call_list_is_every_call_the_scanner_makes():
    with fake_aws():
        build_world()
        with recording() as calls:
            scan_world()

    assert calls == {(service, operation) for service, operation, _ in CALLS}


@pytest.mark.parametrize(
    ("kind", "code"),
    [("access_denied", "AccessDenied"), ("throttling", "RequestLimitExceeded")],
)
def test_an_injected_error_reaches_the_scan_and_is_recorded(world, kind, code):
    fault = Fault("ec2", "DescribeSecurityGroups", kind)

    result, outcome = e1.scan_with(fault)

    assert fault.hits == 1
    assert outcome == "completed"
    assert [error["service"] for error in result["errors"]] == ["ec2"]
    assert code in result["errors"][0]["message"]
    assert not [r for r in result["resources"] if r["resource_type"] == "Security Group"]


def test_a_response_without_its_key_stops_the_scan_and_is_recorded(world):
    fault = Fault("iam", "ListPolicies", "missing_key", "Policies")

    result, outcome = e1.scan_with(fault)

    assert fault.hits == 1
    assert result is None
    assert outcome == "crashed: KeyError 'Policies'"


def test_the_fault_is_removed_after_the_block(world):
    with inject(Fault("s3", "ListBuckets", "access_denied")):
        pass

    assert scan_world()["errors"] == []


def test_the_naive_resolver_resolves_findings_that_a_denied_call_hid(world):
    setup, _ = world
    fault = Fault("s3", "ListBuckets", "access_denied")
    result, outcome = e1.scan_with(fault)

    rows = e1.scan_rows(setup, e1.Case("t", "s3", "access_denied", "x"), result, set(), outcome)

    by = by_resolver(rows)
    assert by["naive"]["wrongly_resolved"] == 3
    assert by["naive"]["correctly_kept_open"] == len(setup.before) - 3
    assert by["cloudshield"]["wrongly_resolved"] == 0
    assert by["cloudshield"]["correctly_kept_open"] == len(setup.before)


def test_cloudshield_keeps_a_role_finding_when_the_instances_could_not_be_listed(world):
    setup, _ = world
    result, outcome = e1.scan_with(Fault("ec2", "DescribeInstances", "access_denied"))

    rows = e1.scan_rows(setup, e1.Case("t", "ec2", "access_denied", "x"), result, set(), outcome)

    by = by_resolver(rows)
    assert by["naive"]["wrongly_resolved"] == 1
    assert by["cloudshield"]["wrongly_resolved"] == 0


def test_a_crashed_scan_resolves_nothing_for_either_resolver(world):
    setup, _ = world
    fault = Fault("s3", "ListBuckets", "missing_key", "Buckets")
    result, outcome = e1.scan_with(fault)

    rows = e1.scan_rows(setup, e1.Case("t", "s3", "missing_key", "x"), result, set(), outcome)

    for row in rows:
        assert row["scan_outcome"].startswith("crashed")
        assert row["wrongly_resolved"] == 0
        assert row["correctly_kept_open"] == len(setup.before)


def test_a_dropped_attribute_is_really_removed_from_a_copy(world):
    clean = scan_world()

    dropped = e1.without_attribute(clean, "S3", "versioning")

    buckets = [r for r in dropped["resources"] if r["resource_type"] == "S3"]
    assert buckets
    assert all("versioning" not in r["attributes"] for r in buckets)
    assert any("versioning" in r["attributes"] for r in clean["resources"])


def test_dropping_an_attribute_nothing_has_is_an_error(world):
    with pytest.raises(RuntimeError, match="had the attribute"):
        e1.without_attribute(scan_world(), "S3", "no_such_attribute")


def test_a_real_fix_is_resolved_by_both_resolvers_and_cloudshield_still_keeps_the_rest(world):
    setup, _ = world

    rows = e1.control_rows(setup)

    clean = by_resolver([r for r in rows if r["service"] == "s3"])
    denied = by_resolver([r for r in rows if r["service"] == "ec2"])
    for resolver in ("cloudshield", "naive"):
        assert clean[resolver]["correctly_resolved"] == 3
        assert clean[resolver]["wrongly_resolved"] == 0
    assert denied["cloudshield"]["correctly_resolved"] == 3
    assert denied["cloudshield"]["wrongly_resolved"] == 0
    assert denied["naive"]["wrongly_resolved"] == 1


def test_a_newer_import_that_leaves_a_check_out_does_not_resolve_it(world):
    setup, ids = world

    rows = e1.import_rows(setup, ids)

    absent = by_resolver([r for r in rows if r["fault"] == "check_absent"])
    assert absent["naive"]["wrongly_resolved"] == 2
    assert absent["cloudshield"]["wrongly_resolved"] == 0
    assert absent["cloudshield"]["correctly_kept_open"] == 3
    passing = by_resolver([r for r in rows if r["fault"] == "check_passes"])
    assert passing["cloudshield"]["correctly_resolved"] == 3
    assert passing["naive"]["correctly_resolved"] == 3
    ignored = by_resolver([r for r in rows if r["fault"] == "ignored_status"])
    assert ignored["naive"]["wrongly_resolved"] == 2
    assert ignored["cloudshield"]["wrongly_resolved"] == 0


def test_summarise_counts_cases_sums_and_flags():
    rows = [
        {"k": "a", "n": 1, "x": "ok"},
        {"k": "a", "n": 2, "x": "bad"},
        {"k": "b", "n": 5, "x": "bad"},
    ]

    result = summarise(rows, ["k"], ["n"], {"bad": lambda row: row["x"] == "bad"})

    assert result == [
        {"k": "a", "cases": 2, "n": 3, "bad": 1},
        {"k": "b", "cases": 1, "n": 5, "bad": 1},
    ]


def test_run_writes_the_csv_files_with_the_documented_columns(tmp_path):
    calls = [("ec2", "DescribeSecurityGroups", "SecurityGroups")]

    rows = e1.run(tmp_path, calls)

    with (tmp_path / "e1.csv").open(newline="", encoding="utf-8") as handle:
        written = list(csv.DictReader(handle))
    assert list(written[0]) == e1.COLUMNS
    assert len(written) == len(rows)
    assert (tmp_path / "e1_summary.csv").exists()
    scan_faults = [row for row in written if row["scenario"] == "scan_fault"]
    assert len(scan_faults) == 3 * 2


def test_an_attribute_dropped_without_an_error_is_never_resolved_by_cloudshield(world):
    setup, _ = world

    rows = e1.silent_drop_rows(setup)

    kept = [row for row in rows if row["resolver"] == "cloudshield"]
    naive = [row for row in rows if row["resolver"] == "naive"]
    assert len(kept) == len(naive) == len(e1.SILENT_DROPS)
    assert all(row["errors_recorded"] == 0 for row in rows)
    assert sum(row["wrongly_resolved"] for row in kept) == 0
    assert sum(row["correctly_kept_open"] for row in kept) == len(kept) * len(setup.before)
    assert sum(row["wrongly_resolved"] for row in naive) == 10
