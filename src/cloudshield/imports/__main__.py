import argparse
from pathlib import Path

from cloudshield.config import Settings, load_env_file
from cloudshield.db.models import ACCOUNT_ID
from cloudshield.db.session import make_engine, make_session_factory
from cloudshield.imports.importer import import_parsed, refresh_parsed
from cloudshield.imports.parser import ImportRejected, parse_file

LABELS = [
    ("imported", "Imported"),
    ("passed", "Passed"),
    ("ignored", "Ignored"),
    ("already_seen", "Already seen"),
    ("resolved", "Resolved"),
    ("rejected", "Rejected"),
]


def mask(account_id: str | None) -> str:
    if not account_id:
        return "not in the file"
    return "*" * max(0, len(account_id) - 4) + account_id[-4:]


def import_prowler(path: str, account_id: str, refresh: bool = False) -> int:
    file = Path(path)
    if not file.is_file():
        raise SystemExit(f"No such file: {path}")
    try:
        parsed = parse_file(file)
        engine = make_engine(Settings().database_url)
        with make_session_factory(engine)() as session:
            if refresh:
                result = refresh_parsed(session, parsed, account_id, file.name)
            else:
                result = import_parsed(session, parsed, account_id, file.name)
    except ImportRejected as exc:
        raise SystemExit(f"Not imported: {exc}") from exc

    if refresh:
        print(f"Refreshed: {result['refreshed']}")
        print(f"Not found among stored findings: {result['not_found']}")
        return 0
    for key, label in LABELS:
        print(f"{label}: {result['counts'][key]}")
    print(f"AWS account in the file: {mask(parsed.external_account_id)}")
    if result["counts"]["unknown_severity"]:
        print(f"Severity unknown, treated as INFO: {result['counts']['unknown_severity']}")
    if result["warning"]:
        print(f"Warning: {result['warning']}")
    return 0


def main(argv: list[str] | None = None, load_env: bool = True) -> int:
    if load_env:
        load_env_file()
    parser = argparse.ArgumentParser(prog="python -m cloudshield.imports")
    commands = parser.add_subparsers(dest="command", required=True)
    prowler = commands.add_parser("prowler", help="import a Prowler JSON-OCSF output file")
    prowler.add_argument("file")
    prowler.add_argument("--account-id", default=ACCOUNT_ID)
    prowler.add_argument(
        "--refresh",
        action="store_true",
        help="re-apply parsing to findings that already exist, even for an imported file",
    )
    args = parser.parse_args(argv)
    return import_prowler(args.file, args.account_id, args.refresh)


if __name__ == "__main__":
    raise SystemExit(main())
