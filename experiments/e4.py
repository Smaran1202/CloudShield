"""E4: patch validity.

Generates every patch that CloudShield can write: the fixes for the rules that have a patch
template, from hand-written fixtures, and the guardrail patches. Each patch is then checked by a
validator for its format. CLI commands are checked offline against botocore's service model.
"""

import argparse
import shutil
import tempfile
from pathlib import Path

from cloudshield.fixes.templates import build_fix
from cloudshield.guardrails.catalog import BY_RULE, GUARDRAILS
from cloudshield.rules import run_rules
from experiments.common import RESULTS, format_table, summarise, write_csv
from experiments.e4_fixtures import FIXTURES
from experiments.validators import validate

COLUMNS = ["rule", "fixture", "source", "format", "patch", "validator", "valid", "error"]
SUMMARY_COLUMNS = ["source", "format", "validator", "cases", "yes", "no", "skipped"]
SUMMARY_FLAGS = {
    "yes": lambda row: row["valid"] == "yes",
    "no": lambda row: row["valid"] == "no",
    "skipped": lambda row: row["valid"] == "skipped",
}


def make_row(rule: str, fixture: str, source: str, patch: dict, plugin_cache) -> dict:
    validator, valid, error = validate(patch, plugin_cache)
    return {
        "rule": rule,
        "fixture": fixture,
        "source": source,
        "format": patch["format"],
        "patch": patch["title"],
        "validator": validator,
        "valid": valid,
        "error": error,
    }


def fix_rows(plugin_cache) -> list[dict]:
    rows = []
    for name, resource in FIXTURES:
        for finding in run_rules([resource]):
            fix = build_fix({"rule_id": finding.rule_id, "details": finding.details}, resource)
            for patch in fix["patches"]:
                rows.append(make_row(finding.rule_id, name, "fix", patch, plugin_cache))
    return rows


def guardrail_rows(plugin_cache) -> list[dict]:
    rules_of: dict[str, list[str]] = {}
    for rule_id, guardrail_ids in BY_RULE.items():
        for guardrail_id in guardrail_ids:
            rules_of.setdefault(guardrail_id, []).append(rule_id)
    rows = []
    for guardrail_id, guardrail in GUARDRAILS.items():
        rule = "+".join(rules_of[guardrail_id])
        for patch in guardrail["patches"]:
            rows.append(make_row(rule, guardrail_id, "guardrail", patch, plugin_cache))
    return rows


def run(out_dir: Path = RESULTS, terraform: bool = False) -> list[dict]:
    if terraform and shutil.which("terraform") is None:
        raise RuntimeError("--terraform was given, but terraform is not on the PATH.")
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as cache:
        plugin_cache = Path(cache) if terraform else None
        rows = fix_rows(plugin_cache) + guardrail_rows(plugin_cache)
    write_csv(out_dir / "e4.csv", COLUMNS, rows)
    write_csv(out_dir / "e4_summary.csv", SUMMARY_COLUMNS, summary(rows))
    return rows


def summary(rows: list[dict]) -> list[dict]:
    return summarise(rows, ["source", "format", "validator"], [], SUMMARY_FLAGS)


def print_summary(rows: list[dict]) -> None:
    print("E4 patch validity: no is a patch that its validator rejected")
    print(format_table(SUMMARY_COLUMNS, summary(rows)))
    for row in rows:
        if row["valid"] == "no":
            print(f"  rejected: {row['rule']} {row['fixture']} {row['format']}: {row['error']}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run E4 and write experiments/results/e4.csv")
    parser.add_argument("--out", type=Path, default=RESULTS)
    parser.add_argument("--terraform", action="store_true", help="also run terraform validate")
    args = parser.parse_args()
    print_summary(run(args.out, args.terraform))


if __name__ == "__main__":
    main()
