import hashlib
import json
import logging
from dataclasses import dataclass
from pathlib import Path

from cloudshield.imports.resources import map_resource

logger = logging.getLogger(__name__)

MAX_BYTES = 50 * 1024 * 1024
OCSF_MAJOR_VERSION = 1
# The id is used only when the severity text is missing or not one we know.
SEVERITY_OF_ID = {1: "INFO", 2: "LOW", 3: "MEDIUM", 4: "HIGH", 5: "CRITICAL"}
SEVERITY_OF_TEXT = {
    "INFORMATIONAL": "INFO",
    "INFO": "INFO",
    "LOW": "LOW",
    "MEDIUM": "MEDIUM",
    "HIGH": "HIGH",
    "CRITICAL": "CRITICAL",
}


class ImportRejected(Exception):
    """The file cannot be imported. The message says why, in plain words."""


@dataclass(frozen=True)
class Record:
    check_id: str
    status: str  # PASS or FAIL
    severity: str
    title: str
    description: str
    risk: str
    remediation: str
    references: list[str]
    categories: list[str]
    status_detail: str
    prowler_uid: str
    check_title: str  # the check's own title, which describes the passing state
    tool_severity: str  # the severity text exactly as the tool wrote it
    resource_uid: str  # the uid exactly as the tool wrote it
    resource_id: str
    resource_type: str
    region: str | None
    service: str | None


@dataclass
class ParsedFile:
    sha256: str
    external_account_id: str | None
    records: list[Record]
    tool_name: str | None = None
    tool_version: str | None = None
    ignored: int = 0  # entries whose status is not PASS or FAIL
    rejected: int = 0  # entries that are missing something needed
    unknown_severity: int = 0


def dig(data, *path):
    for key in path:
        if not isinstance(data, dict) or key not in data:
            return None
        data = data[key]
    return data


def text_of(value) -> str:
    return value if isinstance(value, str) else ""


def list_of_text(value) -> list[str]:
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


def severity_of(entry: dict) -> tuple[str, bool]:
    """Returns the severity, and whether it fell back to INFO because it was not known."""
    text = dig(entry, "severity")
    if isinstance(text, str) and text.upper() in SEVERITY_OF_TEXT:
        return SEVERITY_OF_TEXT[text.upper()], False
    number = dig(entry, "severity_id")
    if isinstance(number, int) and number in SEVERITY_OF_ID:
        return SEVERITY_OF_ID[number], False
    return "INFO", True


def major_version(entry) -> int | None:
    version = dig(entry, "metadata", "version")
    if not isinstance(version, str) or not version.split(".")[0].isdigit():
        return None
    return int(version.split(".")[0])


def read_array(raw: bytes) -> list:
    try:
        data = json.loads(raw.decode("utf-8-sig"))
    except UnicodeDecodeError as exc:
        raise ImportRejected("The file is not UTF-8 text.") from exc
    except json.JSONDecodeError as exc:
        raise ImportRejected(
            f"The file is not valid JSON ({exc.msg} at line {exc.lineno})."
        ) from exc
    if not isinstance(data, list):
        raise ImportRejected("Expected a JSON array of OCSF findings.")
    if not data:
        raise ImportRejected("The file holds no findings.")
    return data


def first_text(entries: list, *path) -> str | None:
    for entry in entries:
        value = dig(entry, *path)
        if isinstance(value, str) and value:
            return value
    return None


def parse_bytes(raw: bytes) -> ParsedFile:
    if len(raw) > MAX_BYTES:
        raise ImportRejected("The file is over 50 MB, which is too large to import.")
    entries = read_array(raw)

    for entry in entries:
        major = major_version(entry)
        if major is not None and major != OCSF_MAJOR_VERSION:
            raise ImportRejected(
                f"This file uses OCSF major version {major}. Only version "
                f"{OCSF_MAJOR_VERSION} is supported."
            )

    accounts = {a for e in entries if isinstance(a := dig(e, "cloud", "account", "uid"), str)}
    if len(accounts) > 1:
        raise ImportRejected("The file mixes findings from more than one AWS account.")
    parsed = ParsedFile(
        sha256=hashlib.sha256(raw).hexdigest(),
        external_account_id=next(iter(accounts), None),
        records=[],
        tool_name=first_text(entries, "metadata", "product", "name"),
        tool_version=first_text(entries, "metadata", "product", "version"),
    )
    for entry in entries:
        read_entry(entry, parsed)
    logger.info(
        "Parsed import file: %d records, %d ignored, %d rejected, %d unknown severities",
        len(parsed.records),
        parsed.ignored,
        parsed.rejected,
        parsed.unknown_severity,
    )
    return parsed


def read_entry(entry, parsed: ParsedFile) -> None:
    check_id = dig(entry, "metadata", "event_code")
    title = dig(entry, "finding_info", "title")
    valid = all(isinstance(v, str) and v for v in (check_id, title))
    if not valid or major_version(entry) is None:
        parsed.rejected += 1
        return
    status = dig(entry, "status_code")
    if status not in ("PASS", "FAIL"):
        parsed.ignored += 1
        return

    severity, unknown = severity_of(entry)
    parsed.unknown_severity += unknown
    resources = dig(entry, "resources")
    resources = [r for r in resources if isinstance(r, dict)] if isinstance(resources, list) else []
    for resource in resources or [{}]:
        resource_id, resource_type = map_resource(
            text_of(resource.get("uid")), parsed.external_account_id, text_of(resource.get("type"))
        )
        region = resource.get("region") or dig(entry, "cloud", "region")
        parsed.records.append(
            Record(
                check_id=check_id,
                status=status,
                severity=severity,
                title=title,
                description=text_of(dig(entry, "finding_info", "desc")),
                risk=text_of(dig(entry, "risk_details")),
                remediation=text_of(dig(entry, "remediation", "desc")),
                references=list_of_text(dig(entry, "remediation", "references")),
                categories=list_of_text(dig(entry, "unmapped", "categories")),
                status_detail=text_of(dig(entry, "status_detail")),
                prowler_uid=text_of(dig(entry, "finding_info", "uid")),
                check_title=title,
                tool_severity=text_of(dig(entry, "severity")),
                resource_uid=text_of(resource.get("uid")),
                resource_id=resource_id,
                resource_type=resource_type,
                region=region if isinstance(region, str) else None,
                service=text_of(dig(resource, "group", "name")) or None,
            )
        )


def parse_file(path: Path) -> ParsedFile:
    # The size is checked before reading, so a huge file is never loaded.
    if path.stat().st_size > MAX_BYTES:
        raise ImportRejected("The file is over 50 MB, which is too large to import.")
    return parse_bytes(path.read_bytes())
