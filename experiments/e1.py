"""E1: unknown handling.

Starts from a fake account that breaks every one of CloudShield's own rules, with all findings
open. Then it scans again with one fault at a time and checks what each resolver does with the
findings that the faulty scan could not confirm. Nothing in the account was fixed, so a finding
that is resolved after a faulty scan is resolved wrongly. The control cases fix things for real.
"""

import argparse
import copy
import itertools
import json
import tempfile
from pathlib import Path
from typing import NamedTuple

from sqlalchemy import select

from cloudshield.db import store
from cloudshield.db.models import ACCOUNT_ID, FindingRow
from cloudshield.findings import make_finding_id
from cloudshield.imports.importer import import_parsed
from cloudshield.imports.mapping import rule_id_of
from cloudshield.imports.parser import parse_bytes
from experiments.common import RESULTS, fake_aws, format_table, summarise, write_csv
from experiments.faults import CALLS, Fault, inject
from experiments.naive import naive_resolve_fixed, naive_resolve_imports
from experiments.world import (
    ACCOUNT,
    BUCKET,
    build_world,
    close_database,
    copy_database,
    fix_bucket,
    make_baseline,
    open_finding_ids,
    save_scan,
    scan_world,
)

COLUMNS = [
    "scenario",
    "service",
    "fault",
    "detail",
    "resolver",
    "findings_open_before",
    "truly_fixed",
    "wrongly_resolved",
    "correctly_resolved",
    "correctly_kept_open",
    "wrongly_kept_open",
    "scan_outcome",
    "errors_recorded",
]
SUMMARY_SUMS = [
    "findings_open_before",
    "wrongly_resolved",
    "correctly_resolved",
    "correctly_kept_open",
    "wrongly_kept_open",
]
SUMMARY_FLAGS = {
    "cases_with_wrong_resolve": lambda row: row["wrongly_resolved"] > 0,
    "scans_crashed": lambda row: row["scan_outcome"].startswith("crashed"),
}
FAULT_KINDS = ("access_denied", "throttling", "missing_key")
# Attributes that a rule reads. They are removed from the scan result with no error recorded,
# which the scanner itself never does. This probes whether the resolver relies on that.
SILENT_DROPS = [
    ("s3", "S3", "public_access_block"),
    ("s3", "S3", "encryption"),
    ("s3", "S3", "versioning"),
    ("ec2", "Security Group", "inbound"),
    ("iam", "IAM Policy", "document"),
    ("iam", "IAM Role", "attached_policies"),
    ("iam", "IAM Role", "inline_policies"),
]
RESOLVERS = {"cloudshield": None, "naive": naive_resolve_fixed}
file_numbers = itertools.count()


class Setup(NamedTuple):
    base: Path  # the database after the clean scan
    workdir: Path
    before: set[str]  # the open findings in that database


class Case(NamedTuple):
    scenario: str
    service: str
    fault: str
    detail: str


def count_outcome(factory, source: str, before: set[str], truly_fixed: set[str]) -> dict:
    with factory() as session:
        still_open = open_finding_ids(session, source)
    resolved = before - still_open
    kept = before & still_open
    return {
        "findings_open_before": len(before),
        "truly_fixed": len(truly_fixed),
        "wrongly_resolved": len(resolved - truly_fixed),
        "correctly_resolved": len(resolved & truly_fixed),
        "correctly_kept_open": len(kept - truly_fixed),
        "wrongly_kept_open": len(kept & truly_fixed),
    }


def make_row(case: Case, resolver: str, counts: dict, outcome: str, errors: int) -> dict:
    return {
        **case._asdict(),
        "resolver": resolver,
        **counts,
        "scan_outcome": outcome,
        "errors_recorded": errors,
    }


def scan_rows(
    setup: Setup, case: Case, result: dict | None, truly_fixed: set[str], outcome: str
) -> list[dict]:
    """The rows of one case, one for each resolver. result is None when the scan crashed, so
    nothing was saved and nothing could be resolved."""
    rows = []
    for name, resolver in RESOLVERS.items():
        factory = copy_database(setup.base, setup.workdir / f"case{next(file_numbers)}.db")
        if result is not None:
            with factory() as session:
                save_scan(session, result, resolver)
        counts = count_outcome(factory, "cloudshield", setup.before, truly_fixed)
        close_database(factory)
        errors = len(result["errors"]) if result else 0
        rows.append(make_row(case, name, counts, outcome, errors))
    return rows


def scan_with(fault: Fault) -> tuple[dict | None, str]:
    with inject(fault):
        try:
            return scan_world(), "completed"
        except KeyError as exc:
            # A response without the key the scanner reads stops the scan. That is a result of
            # the experiment (the scan job would mark the scan failed), so it is recorded.
            return None, f"crashed: KeyError {exc}"


def fault_rows(setup: Setup, calls) -> list[dict]:
    rows = []
    for service, operation, key in calls:
        for kind in FAULT_KINDS:
            fault = Fault(service, operation, kind, key)
            result, outcome = scan_with(fault)
            if fault.hits == 0:
                raise RuntimeError(f"The fault {kind} on {service} {operation} was never reached.")
            if kind != "missing_key" and not result["errors"]:
                raise RuntimeError(f"The scan recorded no error for {kind} on {operation}.")
            case = Case("scan_fault", service, kind, operation)
            rows += scan_rows(setup, case, result, set(), outcome)
    return rows


def without_attribute(result: dict, resource_type: str, attribute: str) -> dict:
    changed = copy.deepcopy(result)
    removed = 0
    for resource in changed["resources"]:
        if resource["resource_type"] == resource_type and attribute in resource["attributes"]:
            del resource["attributes"][attribute]
            removed += 1
    if removed == 0:
        raise RuntimeError(f"No {resource_type} had the attribute {attribute}.")
    return changed


def silent_drop_rows(setup: Setup) -> list[dict]:
    clean = scan_world()
    rows = []
    for service, resource_type, attribute in SILENT_DROPS:
        result = without_attribute(clean, resource_type, attribute)
        case = Case("silent_drop", service, "attribute_dropped", f"{resource_type}.{attribute}")
        rows += scan_rows(setup, case, result, set(), "completed")
    return rows


def finding_ids_of(factory, resource_type: str) -> set[str]:
    query = select(FindingRow.finding_id).where(
        FindingRow.account_id == ACCOUNT_ID,
        FindingRow.source == "cloudshield",
        FindingRow.resource_type == resource_type,
    )
    with factory() as session:
        return set(session.scalars(query).all())


def control_rows(setup: Setup) -> list[dict]:
    """The bucket is really fixed. A resolver that never resolved anything would be safe but
    useless, so these cases show that real fixes are still resolved."""
    factory = copy_database(setup.base, setup.workdir / "truth.db")
    truly_fixed = finding_ids_of(factory, "S3") & setup.before
    close_database(factory)
    fix_bucket()
    clean = Case("control_fixed", "s3", "none", "bucket fixed")
    rows = scan_rows(setup, clean, scan_world(), truly_fixed, "completed")
    fault = Fault("ec2", "DescribeSecurityGroups", "access_denied")
    result, outcome = scan_with(fault)
    denied = Case("control_fixed", "ec2", "access_denied", "bucket fixed, security groups denied")
    return rows + scan_rows(setup, denied, result, truly_fixed, outcome)


def ocsf(check: str, status: str, uid: str) -> dict:
    """One entry of an import file. Written by hand for the experiment, so it is synthetic."""
    return {
        "metadata": {"event_code": check, "version": "1.5.0", "product": {"name": "synthetic"}},
        "severity": "High",
        "status_code": status,
        "status_detail": f"Synthetic result of {check}.",
        "finding_info": {"uid": f"synthetic-{check}", "title": f"Synthetic {check}"},
        "cloud": {"account": {"uid": ACCOUNT}, "region": "us-east-1"},
        "resources": [
            {"uid": uid, "region": "us-east-1", "group": {"name": "synthetic"}, "type": "Other"}
        ],
    }


def to_file(entries: list[dict]) -> bytes:
    return json.dumps(entries).encode("utf-8")


def newer(fault: str, detail: str) -> Case:
    return Case("import_newer", "import", fault, detail)


def import_rows(setup: Setup, ids: dict) -> list[dict]:
    """A first import opens three findings. Newer imports then leave a check out, report it with a
    status that is not PASS or FAIL, or report it for another resource; one reports a PASS."""
    uid_of = {
        "synthetic_check_a": f"arn:aws:s3:::{BUCKET}",
        "synthetic_check_b": f"arn:aws:ec2:us-east-1:{ACCOUNT}:security-group/{ids['group_id']}",
        "synthetic_check_c": ids["wildcard_arn"],
    }
    resource_of = {
        "synthetic_check_a": BUCKET,
        "synthetic_check_b": ids["group_id"],
        "synthetic_check_c": ids["wildcard_arn"],
    }
    expected = {make_finding_id(rule_id_of(c), resource) for c, resource in resource_of.items()}
    a, b, c = (ocsf(check, "FAIL", uid) for check, uid in uid_of.items())
    manual = [ocsf(check, "MANUAL", uid) for check, uid in list(uid_of.items())[1:]]
    elsewhere = ocsf("synthetic_check_a", "FAIL", "arn:aws:s3:::another-bucket")
    passing = [ocsf(check, "PASS", uid) for check, uid in uid_of.items()]
    cases = [
        (newer("check_absent", "B and C left out"), [a], False),
        (newer("ignored_status", "B and C are MANUAL"), [a, *manual], False),
        (newer("resource_absent", "A for another bucket"), [elsewhere, b, c], False),
        (newer("check_passes", "A, B and C pass"), passing, True),
    ]

    seeded = setup.workdir / "imports.db"
    factory = copy_database(setup.base, seeded)
    with factory() as session:
        import_parsed(session, parse_bytes(to_file([a, b, c])), ACCOUNT_ID)
        before = open_finding_ids(session, "prowler")
    close_database(factory)
    if before != expected:
        raise RuntimeError("The first import did not open the three expected findings.")

    rows = []
    for case, entries, really_fixed in cases:
        for name in RESOLVERS:
            factory = copy_database(seeded, setup.workdir / f"case{next(file_numbers)}.db")
            with factory() as session:
                parsed = parse_bytes(to_file(entries))
                import_parsed(session, parsed, ACCOUNT_ID)
                if name == "naive":
                    naive_resolve_imports(session, parsed, store.utcnow())
                    session.commit()
            counts = count_outcome(factory, "prowler", before, before if really_fixed else set())
            close_database(factory)
            rows.append(make_row(case, name, counts, "imported", 0))
    return rows


def run(out_dir: Path = RESULTS, calls=CALLS) -> list[dict]:
    with fake_aws(), tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        workdir = Path(tmp)
        ids = build_world()
        base = workdir / "base.db"
        setup = Setup(base, workdir, make_baseline(base))
        rows = fault_rows(setup, calls)
        rows += silent_drop_rows(setup)
        rows += import_rows(setup, ids)
        # Last, because it changes the fake account.
        rows += control_rows(setup)
    write_csv(out_dir / "e1.csv", COLUMNS, rows)
    write_csv(out_dir / "e1_summary.csv", summary_columns(), summary(rows))
    return rows


def summary(rows: list[dict]) -> list[dict]:
    return summarise(rows, ["scenario", "fault", "resolver"], SUMMARY_SUMS, SUMMARY_FLAGS)


def summary_columns() -> list[str]:
    return ["scenario", "fault", "resolver", "cases", *SUMMARY_SUMS, *SUMMARY_FLAGS]


def print_summary(rows: list[dict]) -> None:
    print("E1 unknown handling: wrongly_resolved is the number that matters")
    print(format_table(summary_columns(), summary(rows)))


def main() -> None:
    parser = argparse.ArgumentParser(description="Run E1 and write experiments/results/e1.csv")
    parser.add_argument("--out", type=Path, default=RESULTS)
    args = parser.parse_args()
    print_summary(run(args.out))


if __name__ == "__main__":
    main()
