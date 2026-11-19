import re
import sqlite3
from contextlib import closing
from datetime import datetime

import pytest
from fastapi.testclient import TestClient

from cloudshield.api.app import create_app
from cloudshield.config import Settings
from cloudshield.db.session import make_engine, make_session_factory
from cloudshield.demo.__main__ import main
from cloudshield.demo.seed import DATA_LABEL, seed
from cloudshield.demo.synthetic import ACCOUNT
from cloudshield.report import numbers


@pytest.fixture(scope="module")
def demo_db(tmp_path_factory):
    # One seed for all the tests that only look. The seed uses moto, so nothing leaves the process.
    path = tmp_path_factory.mktemp("demo") / "demo.db"
    seed(path)
    return path


def lane_rows(path) -> dict:
    engine = make_engine(f"sqlite:///{path}")
    with make_session_factory(engine)() as session:
        tables, _ = numbers.build_tables(session, Settings(), datetime.now(), path.parent / "none")
    engine.dispose()
    return {title: rows for title, _, rows in tables}


def test_every_lane_has_findings(demo_db):
    lanes = {row[0]: row[3] for row in lane_rows(demo_db)["Findings per lane"]}

    for lane in ("Fix now", "Next", "Later", "Informational", "Done (resolved)"):
        assert lanes[lane] > 0, lane


def test_the_rescan_after_the_fix_resolves_the_three_findings_of_one_bucket(demo_db):
    resolved = lane_rows(demo_db)["Resolved findings"]

    assert [(row[0], row[1]) for row in resolved] == [
        ("own", "CIS-S3-001"),
        ("own", "CIS-S3-002"),
        ("own", "CIS-S3-003"),
    ]


def test_imported_file_has_merged_pairs_one_disagreement_and_imported_only_checks(demo_db):
    rows = lane_rows(demo_db)

    assert rows["Merged pairs and disagreements"] == [
        ["merged pairs", 3],
        ["tools disagree, own findings", 1],
        ["tools disagree, imported findings", 0],
    ]
    imported_open = {row[0]: row[1] for row in rows["Imported findings by severity"]}
    assert sum(imported_open.values()) == 5


def test_the_overview_data_has_a_guardrail_status_and_every_scan_is_labelled(demo_db):
    client = TestClient(create_app(database_url=f"sqlite:///{demo_db}", load_env=False))

    guardrails = client.get("/api/guardrails").json()
    scans = client.get("/api/scans").json()

    assert "active" in {g["status"] for g in guardrails}
    assert [s["data_label"] for s in scans] == [DATA_LABEL, DATA_LABEL]
    assert [s["status"] for s in scans] == ["completed", "completed"]


def test_the_account_id_is_the_fake_one_and_no_other_identifier_is_stored(demo_db):
    with closing(sqlite3.connect(demo_db)) as db:
        dump = "\n".join(db.iterdump())

    assert set(re.findall(r"\b\d{12}\b", dump)) == {ACCOUNT}
    assert "AKIA" not in dump


def test_the_seed_runs_offline_and_says_how_to_look_at_the_result(tmp_path, capsys):
    path = tmp_path / "demo.db"

    code = main(["seed", "--db", str(path)])

    printed = capsys.readouterr().out
    assert code == 0
    assert path.is_file()
    assert "DATABASE_URL" in printed
    assert "everything in it is made up" in printed.lower()


def test_it_refuses_to_overwrite_a_file_without_force(tmp_path):
    path = tmp_path / "demo.db"
    path.write_text("keep me", encoding="utf-8")

    with pytest.raises(SystemExit, match="already exists"):
        main(["seed", "--db", str(path)])

    assert path.read_text(encoding="utf-8") == "keep me"


def test_force_never_replaces_a_database_that_is_not_demo_data(tmp_path):
    path = tmp_path / "real.db"
    with closing(sqlite3.connect(path)) as db:
        db.execute("create table scans (id integer, data_label text)")
        db.execute("insert into scans values (1, null)")
        db.commit()

    with pytest.raises(SystemExit, match="not a CloudShield demo database"):
        main(["seed", "--db", str(path), "--force"])

    with closing(sqlite3.connect(path)) as db:
        assert db.execute("select count(*) from scans").fetchone()[0] == 1


def test_force_never_replaces_a_file_that_is_not_a_database(tmp_path):
    path = tmp_path / "notes.db"
    path.write_text("not sqlite", encoding="utf-8")

    with pytest.raises(SystemExit, match="not a CloudShield demo database"):
        main(["seed", "--db", str(path), "--force"])

    assert path.read_text(encoding="utf-8") == "not sqlite"


def test_force_replaces_an_earlier_demo_database(tmp_path):
    path = tmp_path / "demo.db"
    seed(path)

    code = main(["seed", "--db", str(path), "--force"])

    assert code == 0
    with closing(sqlite3.connect(path)) as db:
        assert db.execute("select count(*) from scans").fetchone()[0] == 2
