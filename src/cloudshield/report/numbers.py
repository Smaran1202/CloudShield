import csv
import io
import re
from collections import Counter
from datetime import datetime
from importlib.metadata import version
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from cloudshield.config import Settings
from cloudshield.db.models import ACCOUNT_ID, FindingRow, ImportRow, ResourceRow, ScanRow
from cloudshield.dispositions import is_dismissed
from cloudshield.findings import SEVERITIES
from cloudshield.guardrails.catalog import GUARDRAILS
from cloudshield.guardrails.status import guardrail_status
from cloudshield.imports.merge import latest_completed_scan

# The same numbers as LANE_THRESHOLDS in web/src/lanes.ts. A test compares the two files.
FIX_NOW = 80
NEXT = 60
EXPERIMENT_SUMMARIES = ("e1_summary", "e4_summary")
PREFIXES = {
    "S3": "bucket",
    "Security Group": "sg",
    "EC2": "instance",
    "IAM Policy": "policy",
    "IAM Role": "role",
    "IAM User": "user",
    "Network ACL": "acl",
}
TO_FILL_IN = "(fill in by hand)"
ACCOUNT_NUMBER = re.compile(r"\b\d{12}\b")

# A table is (title, column names, rows).
Table = tuple[str, list[str], list[list]]


class Aliases:
    """Stable stand-ins for account ids and resource ids. The map is kept in memory only: it is
    never written to disk or printed."""

    def __init__(self, pairs: set[tuple[str, str]]) -> None:
        self.names: dict[str, str] = {}
        self.counts: Counter = Counter()
        for kind, resource_id in sorted(pairs):
            self.of(kind, resource_id)

    def of(self, kind: str, resource_id: str) -> str:
        if resource_id not in self.names:
            if resource_id.isdigit() and len(resource_id) == 12:
                prefix = "acct"
            elif kind == "Account":
                prefix = "account-item"
            else:
                prefix = PREFIXES.get(kind, "resource")
            self.counts[prefix] += 1
            self.names[resource_id] = f"{prefix}-{self.counts[prefix]}"
        return self.names[resource_id]

    def scrub(self, text: str) -> str:
        """Safety net for the finished text: any 12-digit number is an account id."""
        return ACCOUNT_NUMBER.sub(lambda match: self.of("Account", match.group()), text)


def lane_of(score: int) -> str:
    if score >= FIX_NOW:
        return "Fix now"
    if score >= NEXT:
        return "Next"
    return "Later"


def by_source(rows: list[FindingRow]) -> list[int]:
    own = sum(r.source == "cloudshield" for r in rows)
    imported = sum(r.source == "prowler" for r in rows)
    return [own, imported, len(rows)]


def own_by_rule(own: list[FindingRow]) -> Table:
    groups: dict[tuple[str, str], list[FindingRow]] = {}
    for row in own:
        groups.setdefault((row.rule_id, row.severity), []).append(row)
    rows = []
    for rule, severity in sorted(groups, key=lambda key: (key[0], SEVERITIES.index(key[1]))):
        members = groups[(rule, severity)]
        open_count = sum(r.status == "OPEN" for r in members)
        rows.append([rule, severity, open_count, len(members) - open_count])
    return "Own findings by rule and severity", ["rule", "severity", "open", "resolved"], rows


def imported_by_severity(imported: list[FindingRow]) -> Table:
    rows = []
    for severity in SEVERITIES:
        members = [r for r in imported if r.severity == severity]
        merged = sum(r.merged_into is not None for r in members)
        shown = [r for r in members if r.merged_into is None]
        open_count = sum(r.status == "OPEN" for r in shown)
        rows.append([severity, open_count, len(shown) - open_count, merged])
    columns = ["severity", "open", "resolved", "merged into an own finding"]
    return "Imported findings by severity", columns, rows


def lanes(findings: list[FindingRow], now: datetime) -> Table:
    """The same rule as the dashboard (web/src/lanes.ts): merged findings are left out, a lane
    holds open, not dismissed findings with a score, and Done holds the resolved ones."""
    shown = [r for r in findings if r.merged_into is None]
    active = [r for r in shown if r.status == "OPEN" and not is_dismissed(r, now)]
    scored = [r for r in active if r.risk_score is not None]
    rows = []
    for name in ("Fix now", "Next", "Later"):
        in_lane = [r for r in scored if lane_of(r.risk_score) == name]
        rows.append([name, *by_source(in_lane)])
    rows.append(["Informational", *by_source([r for r in active if r.severity == "INFO"])])
    dismissed = [r for r in shown if r.status == "OPEN" and is_dismissed(r, now)]
    rows.append(["Dismissed", *by_source(dismissed)])
    rows.append(["Done (resolved)", *by_source([r for r in shown if r.status == "RESOLVED"])])
    return "Findings per lane", ["lane", "own", "imported", "total"], rows


def merged_and_disagreeing(findings: list[FindingRow]) -> Table:
    open_rows = [r for r in findings if r.merged_into is None and r.status == "OPEN"]
    disagree = [r for r in open_rows if r.tools_disagree]
    merged = sum(r.merged_into is not None for r in findings)
    rows = [
        ["merged pairs", merged],
        ["tools disagree, own findings", by_source(disagree)[0]],
        ["tools disagree, imported findings", by_source(disagree)[1]],
    ]
    return "Merged pairs and disagreements", ["what", "count"], rows


def resolved_findings(findings: list[FindingRow], aliases: Aliases) -> Table:
    rows = []
    for row in findings:
        if row.status != "RESOLVED" or row.merged_into is not None:
            continue
        when = row.resolved_at.date().isoformat() if row.resolved_at else "unknown"
        source = "own" if row.source == "cloudshield" else "imported"
        resource = aliases.of(row.resource_type, row.resource_id)
        rows.append([source, row.rule_id, resource, when, row.resolution_reason or "unknown"])
    rows.sort(key=lambda r: (r[0], r[3], r[1], r[2]))
    return "Resolved findings", ["source", "rule", "resource", "resolved on", "reason"], rows


def scans_table(scans: list[ScanRow]) -> Table:
    rows = []
    for scan in scans:
        seconds = "n/a"
        if scan.started_at and scan.finished_at:
            seconds = round((scan.finished_at - scan.started_at).total_seconds(), 1)
        counts = [scan.resource_count, scan.finding_count, scan.error_count]
        rows.append([scan.id, scan.status, seconds, *counts])
    columns = ["scan", "status", "seconds", "resources", "findings", "errors"]
    return "Scans", columns, rows


def imports_table(imports: list[ImportRow]) -> Table:
    def shown(value) -> str | int:
        return "n/a" if value is None else value

    rows = [
        [
            row.id,
            row.origin,
            shown(row.run_mode),
            shown(row.tool_version),
            shown(row.pass_count),
            shown(row.fail_count),
        ]
        for row in imports
    ]
    columns = ["import", "origin", "run mode", "tool version", "passed", "failed"]
    return "Imports", columns, rows


def guardrails_table(session: Session) -> Table:
    scan = latest_completed_scan(session, ACCOUNT_ID)
    statuses = Counter(guardrail_status(g, scan)[0] for g in GUARDRAILS.values())
    rows = [[status, count] for status, count in sorted(statuses.items())]
    return "Guardrails by status", ["status", "count"], rows


def versions_table(imports: list[ImportRow]) -> Table:
    tools = sorted({row.tool_version for row in imports if row.tool_version})
    rows = [
        ["CloudShield", version("cloudshield")],
        ["imported scanner (from the import files)", ", ".join(tools) or "no import"],
    ]
    return "Versions", ["what", "version"], rows


def ai_table(settings: Settings) -> Table:
    # Model names only. The key is never read here.
    rows = [
        ["GEMINI_MODEL", settings.gemini_model or "not set"],
        ["GEMINI_FALLBACK_MODEL", settings.gemini_fallback_model or "not set"],
        ["EMBEDDING_MODEL", settings.embedding_model or "not set"],
    ]
    return "AI model settings", ["setting", "value"], rows


def experiment_tables(folder: Path) -> list[Table]:
    tables = []
    for name in EXPERIMENT_SUMMARIES:
        path = folder / f"{name}.csv"
        if path.is_file():
            with path.open(newline="", encoding="utf-8") as handle:
                reader = csv.DictReader(handle)
                columns = list(reader.fieldnames or [])
                rows = [[row[column] for column in columns] for row in reader]
            tables.append((f"Experiment {name[:2].upper()} summary", columns, rows))
    return tables


def tests_table() -> Table:
    suites = ["pytest", "vitest", "Playwright read-only", "Playwright actions"]
    return "Test counts", ["suite", "count"], [[suite, TO_FILL_IN] for suite in suites]


def build_tables(
    session: Session, settings: Settings, now: datetime, experiments: Path
) -> tuple[list[Table], Aliases]:
    query = select(FindingRow).where(FindingRow.account_id == ACCOUNT_ID)
    findings = list(session.scalars(query))
    scans = list(session.scalars(select(ScanRow).order_by(ScanRow.id)))
    imports = list(session.scalars(select(ImportRow).order_by(ImportRow.id)))
    pairs = {(r.resource_type, r.resource_id) for r in findings}
    pairs |= {(r.resource_type, r.resource_id) for r in session.scalars(select(ResourceRow))}
    pairs |= {("Account", i.external_account_id) for i in imports if i.external_account_id}
    aliases = Aliases(pairs)
    own = [r for r in findings if r.source == "cloudshield"]
    imported = [r for r in findings if r.source == "prowler"]
    totals = [["scans", len(scans)], ["imports", len(imports)]]
    totals += [["own findings stored", len(own)], ["imported findings stored", len(imported)]]
    tables = [
        ("Totals", ["what", "count"], totals),
        own_by_rule(own),
        imported_by_severity(imported),
        lanes(findings, now),
        merged_and_disagreeing(findings),
        resolved_findings(findings, aliases),
        scans_table(scans),
        imports_table(imports),
        guardrails_table(session),
        versions_table(imports),
        ai_table(settings),
        *experiment_tables(experiments),
        tests_table(),
    ]
    return tables, aliases


def markdown(tables: list[Table], aliases: Aliases) -> str:
    lines = [
        "# CloudShield numbers",
        "",
        "Made from the database only. Account ids and resource names are replaced by aliases.",
        "",
    ]
    for title, columns, rows in tables:
        lines += [f"## {title}", ""]
        if not rows:
            lines += ["None.", ""]
            continue
        lines.append("| " + " | ".join(columns) + " |")
        lines.append("| " + " | ".join("---" for _ in columns) + " |")
        lines += ["| " + " | ".join(str(cell) for cell in row) + " |" for row in rows]
        lines.append("")
    return aliases.scrub("\n".join(lines))


def long_csv(tables: list[Table], aliases: Aliases) -> str:
    """One line for each cell: section, row number, column, value."""
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(["section", "row", "column", "value"])
    for title, columns, rows in tables:
        for number, row in enumerate(rows, start=1):
            for column, cell in zip(columns, row, strict=True):
                writer.writerow([title, number, column, cell])
    return aliases.scrub(out.getvalue())
