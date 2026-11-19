import argparse
from pathlib import Path

from cloudshield.config import Settings, load_env_file
from cloudshield.db.session import make_engine, make_session_factory
from cloudshield.db.store import utcnow
from cloudshield.report.numbers import build_tables, long_csv, markdown

EXPERIMENT_RESULTS = Path("experiments") / "results"
SQLITE_PREFIX = "sqlite:///"


def numbers(db: str | None, out: str, csv_path: str | None) -> int:
    settings = Settings()
    url = f"{SQLITE_PREFIX}{db}" if db else settings.database_url
    # A missing file would be created empty by SQLite, so it is checked first.
    if url.startswith(SQLITE_PREFIX) and not Path(url.removeprefix(SQLITE_PREFIX)).is_file():
        raise SystemExit(f"No such database: {url.removeprefix(SQLITE_PREFIX)}")
    engine = make_engine(url)
    with make_session_factory(engine)() as session:
        tables, aliases = build_tables(session, settings, utcnow(), EXPERIMENT_RESULTS)
    engine.dispose()

    text = markdown(tables, aliases)
    print(text)
    Path(out).write_text(text, encoding="utf-8")
    if csv_path:
        Path(csv_path).write_text(long_csv(tables, aliases), encoding="utf-8", newline="")
    return 0


def main(argv: list[str] | None = None, load_env: bool = True) -> int:
    if load_env:
        load_env_file()
    parser = argparse.ArgumentParser(prog="python -m cloudshield.report")
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("numbers", help="the numbers for the paper, from the database")
    command.add_argument("--db", help="a SQLite file; the default is DATABASE_URL")
    command.add_argument("--out", default="numbers.md", help="the Markdown file to write")
    command.add_argument("--csv", help="also write the numbers as a CSV file")
    args = parser.parse_args(argv)
    return numbers(args.db, args.out, args.csv)


if __name__ == "__main__":
    raise SystemExit(main())
