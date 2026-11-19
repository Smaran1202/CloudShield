import argparse
import sqlite3
from contextlib import closing
from pathlib import Path

from cloudshield.demo.seed import seed


def is_demo_database(path: Path) -> bool:
    """True only for a database whose scans are all labelled as demo data."""
    try:
        with closing(sqlite3.connect(path)) as db:
            unlabelled = db.execute("select count(*) from scans where data_label is null")
            return unlabelled.fetchone()[0] == 0
    except sqlite3.DatabaseError:
        return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m cloudshield.demo")
    commands = parser.add_subparsers(dest="command", required=True)
    seed_command = commands.add_parser("seed", help="build a demo database on made-up data")
    seed_command.add_argument("--db", required=True, help="the new file, for example demo.db")
    seed_command.add_argument(
        "--force", action="store_true", help="replace an existing demo database"
    )
    args = parser.parse_args(argv)

    path = Path(args.db)
    if path.exists():
        if not args.force:
            raise SystemExit(f"{path} already exists. Use --force to replace a demo database.")
        # --force can never delete a real database: only one made by this command is replaced.
        if not is_demo_database(path):
            raise SystemExit(f"{path} is not a CloudShield demo database, so it is not replaced.")
        path.unlink()
    seed(path)
    print(f"Demo database written to {path}. Everything in it is made up.")
    print("To look at it, in PowerShell:")
    print(f'  $env:DATABASE_URL = "sqlite:///{path}"')
    print('  $env:FRONTEND_ORIGIN = "http://localhost:5173"')
    print("  python -m uvicorn cloudshield.api.app:create_app --factory --port 8000")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
