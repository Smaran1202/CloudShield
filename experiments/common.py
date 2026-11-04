import csv
import os
from collections import defaultdict
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from moto import mock_aws

RESULTS = Path(__file__).parent / "results"


@contextmanager
def fake_aws() -> Iterator[None]:
    """Every AWS call in an experiment goes to moto, never to a real account. The credential files
    are pointed at nothing, so even a profile on this machine cannot be picked up."""
    fake = {
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
        "AWS_DEFAULT_REGION": "us-east-1",
        "AWS_EC2_METADATA_DISABLED": "true",
        "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
        "AWS_CONFIG_FILE": os.devnull,
    }
    with patch.dict(os.environ, fake):
        for name in ("AWS_PROFILE", "AWS_SESSION_TOKEN"):
            os.environ.pop(name, None)
        with mock_aws():
            yield


def write_csv(path: Path, columns: list[str], rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def summarise(
    rows: list[dict], keys: list[str], sums: list[str], flags: dict[str, Callable] | None = None
) -> list[dict]:
    """One row for each combination of the key columns: how many rows, the sum of each column in
    sums, and for each flag how many rows it is true for."""
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for row in rows:
        groups[tuple(row[key] for key in keys)].append(row)
    summary = []
    for key in sorted(groups):
        members = groups[key]
        line = dict(zip(keys, key, strict=True))
        line["cases"] = len(members)
        for name in sums:
            line[name] = sum(int(member[name]) for member in members)
        for name, test in (flags or {}).items():
            line[name] = sum(bool(test(member)) for member in members)
        summary.append(line)
    return summary


def format_table(columns: list[str], rows: list[dict]) -> str:
    widths = [max(len(column), *(len(str(row[column])) for row in rows)) for column in columns]

    def line(values: list) -> str:
        return "  ".join(str(v).ljust(w) for v, w in zip(values, widths, strict=True))

    lines = [line(columns), line(["-" * width for width in widths])]
    lines += [line([row[column] for column in columns]) for row in rows]
    return "\n".join(lines)
