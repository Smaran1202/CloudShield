"""Runs E1 and E4, writes experiments/results/*.csv and prints the summary tables."""

import argparse
import platform
from importlib import metadata
from pathlib import Path

from experiments import e1, e4
from experiments.common import RESULTS

PACKAGES = ["boto3", "botocore", "moto", "SQLAlchemy", "PyYAML", "cfn-lint"]


def versions() -> str:
    found = []
    for name in PACKAGES:
        try:
            found.append(f"{name} {metadata.version(name)}")
        except metadata.PackageNotFoundError:
            found.append(f"{name} not installed")
    return f"Python {platform.python_version()}, " + ", ".join(found)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run E1 and E4")
    parser.add_argument("--out", type=Path, default=RESULTS)
    parser.add_argument("--terraform", action="store_true", help="also run terraform validate")
    args = parser.parse_args()
    print(versions())
    e1.print_summary(e1.run(args.out))
    print()
    e4.print_summary(e4.run(args.out, args.terraform))


if __name__ == "__main__":
    main()
