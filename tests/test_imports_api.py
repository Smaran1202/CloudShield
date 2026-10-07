from pathlib import Path

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from prowler_data import ACCOUNT, entry, to_bytes
from sqlalchemy import create_engine, text

from cloudshield.api.app import create_app
from cloudshield.db.models import Base
from cloudshield.db.session import make_engine
from cloudshield.imports.__main__ import main as import_main
from cloudshield.imports.__main__ import mask
from cloudshield.imports.importer import import_parsed
from cloudshield.imports.parser import parse_bytes

ROOT = Path(__file__).resolve().parents[1]
BUCKET = "F-PRW-s3_bucket_public_access-"


def make_client(tmp_path, transport=None) -> TestClient:
    url = f"sqlite:///{tmp_path / 'test.db'}"
    Base.metadata.create_all(make_engine(url))
    return TestClient(create_app(database_url=url, gemini_transport=transport, load_env=False))


def load(client, entries) -> None:
    with client.app.state.session_factory() as session:
        import_parsed(session, parse_bytes(to_bytes(entries)), "local")


def imported(client) -> dict:
    return client.get("/api/findings", params={"source": "prowler"}).json()[0]


def test_the_api_shows_the_source_and_import_time_of_an_imported_finding(tmp_path):
    client = make_client(tmp_path)
    load(client, [entry()])

    finding = imported(client)

    assert finding["source"] == "prowler"
    assert finding["rule_id"] == "PRW-s3_bucket_public_access"
    assert finding["last_scan_id"] is None
    assert finding["last_imported_at"] is not None
    assert finding["not_rechecked"] is False
    assert {i["certainty"] for i in finding["evidence"]["items"]} == {"reported"}


def test_the_source_filter_keeps_only_findings_from_that_source(tmp_path):
    client = make_client(tmp_path)
    load(client, [entry(), entry(check="c2")])

    assert len(client.get("/api/findings").json()) == 2
    assert len(client.get("/api/findings", params={"source": "prowler"}).json()) == 2
    assert client.get("/api/findings", params={"source": "cloudshield"}).json() == []
    assert client.get("/api/findings", params={"source": "other"}).status_code == 422


def test_a_finding_missing_from_the_newest_import_is_marked_not_rechecked(tmp_path):
    client = make_client(tmp_path)
    load(client, [entry()])
    load(client, [entry(check="c2")])

    by_rule = {f["rule_id"]: f for f in client.get("/api/findings").json()}
    detail = client.get(f"/api/findings/{by_rule['PRW-s3_bucket_public_access']['finding_id']}")

    assert by_rule["PRW-s3_bucket_public_access"]["not_rechecked"] is True
    assert by_rule["PRW-c2"]["not_rechecked"] is False
    assert detail.json()["not_rechecked"] is True


def test_a_resolved_finding_is_never_marked_not_rechecked(tmp_path):
    client = make_client(tmp_path)
    load(client, [entry()])
    load(client, [entry(status="PASS")])

    finding = imported(client)

    assert finding["status"] == "RESOLVED"
    assert finding["resolution_reason"] == "passed in a newer import"
    assert finding["not_rechecked"] is False


def test_the_detail_of_an_imported_finding_works_without_a_stored_resource(tmp_path):
    client = make_client(tmp_path)
    load(client, [entry()])

    detail = client.get(f"/api/findings/{imported(client)['finding_id']}")

    assert detail.status_code == 200
    assert detail.json()["resource"] is None


def test_the_schema_has_the_reported_certainty_and_the_source_field(tmp_path):
    client = make_client(tmp_path)

    schemas = client.get("/openapi.json").json()["components"]["schemas"]

    assert "reported" in schemas["EvidenceItem"]["properties"]["certainty"]["enum"]
    assert "reported" in schemas["RiskFactor"]["properties"]["certainty"]["enum"]
    assert schemas["FindingOut"]["properties"]["source"]["enum"] == ["cloudshield", "prowler"]
    assert "not_rechecked" in schemas["FindingOut"]["properties"]


def test_the_fix_of_an_imported_finding_is_guidance_with_unknown_blast_radius(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setenv("GEMINI_MODEL", "model-a")
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(500)

    client = make_client(tmp_path, httpx.MockTransport(handler))
    load(client, [entry()])

    response = client.post(f"/api/findings/{imported(client)['finding_id']}/fix")

    fix = response.json()
    assert response.status_code == 200
    assert calls == []
    assert fix["patches"] == []
    assert fix["blast_radius"]["level"] == "unknown"
    assert fix["blast_radius"]["factors"] == []
    assert fix["guidance"] == [
        "Fix s3_bucket_public_access like this.",
        "Reference: https://example.com/s3_bucket_public_access",
    ]
    assert fix["generated_by"] == "template"
    assert fix["model"] is None
    assert "no AI explanation" in fix["explanation"]["skipped_reason"]
    assert fix["explanation"]["cited"] == ["e1", "e2", "e3", "e4", "e5"]
    assert client.post(f"/api/findings/{imported(client)['finding_id']}/fix").json() == fix


def test_the_environment_score_and_summary_count_open_imported_findings(tmp_path):
    client = make_client(tmp_path)
    load(client, [entry(severity="Critical"), entry(check="c2", severity="Low")])

    summary = client.get("/api/risk/summary").json()

    assert summary["counts_by_severity"]["CRITICAL"] == 1
    assert summary["top_findings"][0]["source"] == "prowler"
    assert summary["top_findings"][0]["risk_score"] == 90


def test_the_import_command_prints_counts_and_masks_the_account(tmp_path, monkeypatch, capsys):
    url = f"sqlite:///{tmp_path / 'cli.db'}"
    Base.metadata.create_all(make_engine(url))
    monkeypatch.setenv("DATABASE_URL", url)
    path = tmp_path / "prowler-test.ocsf.json"
    path.write_bytes(to_bytes([entry(), entry(check="c2", status="PASS"), entry(status="MUTED")]))

    code = import_main(["prowler", str(path)], load_env=False)

    out = capsys.readouterr().out
    assert code == 0
    for line in ("Imported: 1", "Passed: 1", "Ignored: 1", "Already seen: 0", "Resolved: 0"):
        assert line in out
    assert "Rejected: 0" in out
    assert "********9012" in out
    assert ACCOUNT not in out


def test_the_import_command_refuses_the_same_file_twice(tmp_path, monkeypatch):
    url = f"sqlite:///{tmp_path / 'cli.db'}"
    Base.metadata.create_all(make_engine(url))
    monkeypatch.setenv("DATABASE_URL", url)
    path = tmp_path / "prowler-test.ocsf.json"
    path.write_bytes(to_bytes([entry()]))
    import_main(["prowler", str(path)], load_env=False)

    with pytest.raises(SystemExit, match="already imported"):
        import_main(["prowler", str(path)], load_env=False)


def test_the_import_command_says_why_a_file_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'cli.db'}")
    path = tmp_path / "prowler-test.ocsf.json"
    path.write_text("not json", encoding="utf-8")

    with pytest.raises(SystemExit, match="not valid JSON"):
        import_main(["prowler", str(path)], load_env=False)
    with pytest.raises(SystemExit, match="No such file"):
        import_main(["prowler", str(tmp_path / "missing.json")], load_env=False)


def test_the_account_id_is_masked_to_its_last_four_digits():
    assert mask("123456789012") == "********9012"
    assert mask(None) == "not in the file"


def test_the_imports_migration_keeps_earlier_data_and_imports_still_work(tmp_path, monkeypatch):
    url = f"sqlite:///{tmp_path / 'old.db'}"
    monkeypatch.setenv("DATABASE_URL", url)
    config = Config(str(ROOT / "alembic.ini"))
    migrations = ROOT / "src" / "cloudshield" / "db" / "migrations"
    config.set_main_option("script_location", str(migrations))
    command.upgrade(config, "0003")
    with create_engine(url).begin() as connection:
        connection.execute(
            text(
                "insert into scans (id, status, regions, resource_count, finding_count, "
                "error_count, errors) values (1, 'completed', '[]', 0, 1, 0, '[]')"
            )
        )
        connection.execute(
            text(
                "insert into findings (finding_id, rule_id, resource_id, resource_type, title, "
                "severity, category, status, details, first_seen_at, last_seen_at, last_scan_id) "
                "values ('F-CIS-S3-003-aaaaaaaa', 'CIS-S3-003', 'old-bucket', 'S3', 'Old', "
                "'MEDIUM', 'Storage', 'OPEN', '{}', '2026-10-01 00:00:00', "
                "'2026-10-01 00:00:00', 1)"
            )
        )

    command.upgrade(config, "head")

    client = TestClient(create_app(database_url=url, load_env=False))
    old = client.get("/api/findings").json()[0]
    assert old["finding_id"] == "F-CIS-S3-003-aaaaaaaa"
    assert old["source"] == "cloudshield"
    assert old["last_scan_id"] == 1
    assert old["last_imported_at"] is None
    load(client, [entry()])
    assert len(client.get("/api/findings").json()) == 2
