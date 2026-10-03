import argparse
from pathlib import Path

from cloudshield.config import Settings, load_env_file
from cloudshield.db.models import ACCOUNT_ID, FixRow
from cloudshield.db.session import make_engine, make_session_factory
from cloudshield.fixes.ai_check import run_ai_check
from cloudshield.fixes.export import explanation_line, write_fix_files


def export_fix(finding_id: str, directory: str) -> int:
    engine = make_engine(Settings().database_url)
    with make_session_factory(engine)() as session:
        fix = session.get(FixRow, (ACCOUNT_ID, finding_id))
    if fix is None:
        raise SystemExit(
            f"No stored fix for {finding_id}. Request one first with "
            f"POST /api/findings/{finding_id}/fix."
        )

    skipped = fix.explanation.get("skipped_reason")
    note = explanation_line(fix.generated_by, fix.model, skipped)
    written = write_fix_files(finding_id, fix.patches, Path(directory), note)
    if not written:
        print("This finding has no patch files. Its guidance is in the API response.")
    for path in written:
        print(path)
    print("Review the files before you run anything. Nothing has been run.")
    return 0


def main(argv: list[str] | None = None, load_env: bool = True) -> int:
    if load_env:
        load_env_file()
    parser = argparse.ArgumentParser(prog="python -m cloudshield.fixes")
    commands = parser.add_subparsers(dest="command", required=True)
    export = commands.add_parser("export", help="write a stored fix to files")
    export.add_argument("finding_id")
    export.add_argument("--dir", default="fixes-out", help="output directory")
    commands.add_parser("ai-check", help="check the Gemini settings with one small live call")
    args = parser.parse_args(argv)

    if args.command == "ai-check":
        lines = run_ai_check(Settings())
        print("\n".join(lines))
        return 1 if any("FAILED" in line or "No call made" in line for line in lines) else 0
    return export_fix(args.finding_id, args.dir)


if __name__ == "__main__":
    raise SystemExit(main())
