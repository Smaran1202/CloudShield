from pathlib import Path

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, text

from cloudshield.api.app import create_app
from cloudshield.db.models import Base

ROOT = Path(__file__).resolve().parents[1]


def alembic_setup(tmp_path, monkeypatch) -> tuple[str, Config]:
    url = f"sqlite:///{tmp_path / 'fresh.db'}"
    monkeypatch.setenv("DATABASE_URL", url)
    config = Config(str(ROOT / "alembic.ini"))
    migrations = ROOT / "src" / "cloudshield" / "db" / "migrations"
    config.set_main_option("script_location", str(migrations))
    return url, config


def test_alembic_upgrade_head_creates_the_tables_on_a_fresh_database(tmp_path, monkeypatch):
    url, config = alembic_setup(tmp_path, monkeypatch)

    command.upgrade(config, "head")

    engine = create_engine(url)
    tables = set(inspect(engine).get_table_names())
    with engine.connect() as connection:
        version = connection.execute(text("select version_num from alembic_version")).scalar()
    assert {"scans", "resources", "findings", "fixes"} <= tables
    assert version == "0005"


def test_migrated_schema_matches_the_models(tmp_path, monkeypatch):
    url, config = alembic_setup(tmp_path, monkeypatch)
    command.upgrade(config, "head")

    with create_engine(url).connect() as connection:
        context = MigrationContext.configure(connection)
        differences = compare_metadata(context, Base.metadata)

    assert differences == []


def test_account_id_defaults_to_local_in_the_database(tmp_path, monkeypatch):
    url, config = alembic_setup(tmp_path, monkeypatch)
    command.upgrade(config, "head")

    with create_engine(url).begin() as connection:
        connection.execute(
            text(
                "insert into scans (status, regions, resource_count, finding_count, "
                "error_count, errors) values ('queued', '[]', 0, 0, 0, '[]')"
            )
        )
        account_id = connection.execute(text("select account_id from scans")).scalar()

    assert account_id == "local"


def test_phase_3_data_survives_the_risk_migration_and_still_works(tmp_path, monkeypatch):
    url, config = alembic_setup(tmp_path, monkeypatch)
    command.upgrade(config, "0001")
    with create_engine(url).begin() as connection:
        connection.execute(
            text(
                "insert into scans (id, status, regions, resource_count, finding_count, "
                "error_count, errors, started_at, finished_at) values "
                "(1, 'completed', '[\"us-east-1\"]', 1, 1, 0, '[]', "
                "'2026-10-01 00:00:00', '2026-10-01 00:01:00')"
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
    finding = client.get("/api/findings").json()[0]
    scan = client.get("/api/scans/1").json()
    summary = client.get("/api/risk/summary").json()
    assert finding["finding_id"] == "F-CIS-S3-003-aaaaaaaa"
    assert finding["risk_score"] is None
    assert finding["risk_factors"] == []
    assert finding["evidence"] == {"items": []}
    assert scan["environment_score"] is None
    assert scan["severity_counts"] == {}
    assert client.get("/api/risk/trend").json() == []
    assert summary["counts_by_severity"]["MEDIUM"] == 1
    assert summary["top_findings"] == []


def test_phase_4_data_survives_the_fixes_migration_and_a_fix_can_be_made(tmp_path, monkeypatch):
    url, config = alembic_setup(tmp_path, monkeypatch)
    command.upgrade(config, "0002")
    with create_engine(url).begin() as connection:
        connection.execute(
            text(
                "insert into scans (id, status, regions, resource_count, finding_count, "
                "error_count, errors, environment_score, severity_counts) values "
                "(1, 'completed', '[\"us-east-1\"]', 1, 1, 0, '[]', 40.0, '{\"MEDIUM\": 1}')"
            )
        )
        connection.execute(
            text(
                "insert into resources (resource_id, resource_type, region, name, attributes, "
                "last_seen_scan_id) values ('old-bucket', 'S3', 'us-east-1', 'old-bucket', "
                '\'{"versioning": "Disabled"}\', 1)'
            )
        )
        connection.execute(
            text(
                "insert into findings (finding_id, rule_id, resource_id, resource_type, title, "
                "severity, category, status, details, evidence, risk_score, risk_factors, "
                "first_seen_at, last_seen_at, last_scan_id) values "
                "('F-CIS-S3-003-aaaaaaaa', 'CIS-S3-003', 'old-bucket', 'S3', 'Old', 'MEDIUM', "
                "'Storage', 'OPEN', '{\"versioning\": \"Disabled\"}', '{\"items\": []}', 40, "
                "'[]', '2026-10-01 00:00:00', '2026-10-01 00:00:00', 1)"
            )
        )

    command.upgrade(config, "head")

    client = TestClient(create_app(database_url=url, load_env=False))
    finding = client.get("/api/findings").json()[0]
    scan = client.get("/api/scans/1").json()
    before = client.get(f"/api/findings/{finding['finding_id']}/fix")
    created = client.post(f"/api/findings/{finding['finding_id']}/fix")
    assert finding["risk_score"] == 40
    assert scan["environment_score"] == 40.0
    assert before.status_code == 404
    assert created.status_code == 200
    assert "put-bucket-versioning --bucket old-bucket" in created.json()["patches"][2]["content"]
