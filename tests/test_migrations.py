from pathlib import Path

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect, text

from cloudshield.db.models import Base

ROOT = Path(__file__).resolve().parents[1]


def upgrade_fresh_database(tmp_path, monkeypatch) -> str:
    url = f"sqlite:///{tmp_path / 'fresh.db'}"
    monkeypatch.setenv("DATABASE_URL", url)
    config = Config(str(ROOT / "alembic.ini"))
    migrations = ROOT / "src" / "cloudshield" / "db" / "migrations"
    config.set_main_option("script_location", str(migrations))
    command.upgrade(config, "head")
    return url


def test_alembic_upgrade_head_creates_the_tables_on_a_fresh_database(tmp_path, monkeypatch):
    url = upgrade_fresh_database(tmp_path, monkeypatch)

    engine = create_engine(url)
    tables = set(inspect(engine).get_table_names())
    with engine.connect() as connection:
        version = connection.execute(text("select version_num from alembic_version")).scalar()

    assert {"scans", "resources", "findings"} <= tables
    assert version == "0001"


def test_migrated_schema_matches_the_models(tmp_path, monkeypatch):
    url = upgrade_fresh_database(tmp_path, monkeypatch)

    with create_engine(url).connect() as connection:
        context = MigrationContext.configure(connection)
        differences = compare_metadata(context, Base.metadata)

    assert differences == []


def test_account_id_defaults_to_local_in_the_database(tmp_path, monkeypatch):
    url = upgrade_fresh_database(tmp_path, monkeypatch)

    with create_engine(url).begin() as connection:
        connection.execute(
            text(
                "insert into scans (status, regions, resource_count, finding_count, "
                "error_count, errors) values ('queued', '[]', 0, 0, 0, '[]')"
            )
        )
        account_id = connection.execute(text("select account_id from scans")).scalar()

    assert account_id == "local"
