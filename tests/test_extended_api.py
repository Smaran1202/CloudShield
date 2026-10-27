import threading
import time
from pathlib import Path

from alembic import command
from alembic.config import Config
from fake_prowler import FakePopen, FakeProcess, Killer, results_file, settings_for
from fastapi.testclient import TestClient
from prowler_data import entry, to_bytes
from sqlalchemy import create_engine, select, text

from cloudshield.api.app import create_app
from cloudshield.db import store
from cloudshield.db.models import Base, ImportRow
from cloudshield.db.session import make_engine
from cloudshield.imports import __main__ as import_cli
from cloudshield.imports.runner import (
    PERMISSION_HINT,
    ExtendedError,
    RunnerStatus,
    RunOutput,
    StatusCache,
    run_prowler,
)
from cloudshield.scanner.common import make_resource

ROOT = Path(__file__).resolve().parents[1]
RUNNING = "Running extended checks (this can take several minutes)"


def bucket() -> dict:
    attributes = {
        "public_access_block": None,
        "encryption": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}],
        "versioning": "Enabled",
        "policy": None,
    }
    return make_resource("my-bucket", "S3", "ap-southeast-2", "my-bucket", attributes)


def read_resources(regions):
    return {"resources": [bucket()], "errors": []}


def output(content=None, permission_errors=False) -> RunOutput:
    return RunOutput(
        file_name="prowler-output-1.ocsf.json",
        content=results_file() if content is None else content,
        duration_seconds=12.5,
        services=["s3", "ec2", "iam"],
        regions=["ap-southeast-2"],
        saw_permission_errors=permission_errors,
    )


def make_client(tmp_path, extended=None, scan=read_resources, status=None) -> TestClient:
    url = f"sqlite:///{tmp_path / 'test.db'}"
    Base.metadata.create_all(make_engine(url))
    app = create_app(
        database_url=url,
        scan_function=scan,
        load_env=False,
        extended_function=extended,
        extended_status=status,
    )
    return TestClient(app)


def run_scan(client, extended=True) -> dict:
    body = {"regions": ["ap-southeast-2"], "extended": extended}
    started = client.post("/api/scans", json=body)
    assert started.status_code == 202
    return wait_for(client, started.json()["id"])


def wait_for(client, scan_id: int) -> dict:
    for _ in range(400):
        scan = client.get(f"/api/scans/{scan_id}").json()
        if scan["status"] in ("completed", "failed"):
            return scan
        time.sleep(0.01)
    raise AssertionError("the scan did not end")


def findings(client, source=None) -> list[dict]:
    params = {"source": source} if source else {}
    return client.get("/api/findings", params=params).json()


def test_a_full_scan_imports_the_extended_results_and_says_how_many(tmp_path):
    client = make_client(tmp_path, extended=lambda regions: output())

    scan = run_scan(client)

    assert scan["status"] == "completed"
    assert scan["extended_status"] == "ok"
    assert scan["extended_message"] == "Extended checks: 2 imported, 0 resolved, 1 passed"
    assert scan["extended_hint"] is None
    assert len(findings(client, "prowler")) == 2


def test_the_scan_reports_each_stage_in_order(tmp_path, monkeypatch):
    seen = []
    real = store.set_progress

    def record(session, scan_id, progress):
        seen.append(progress)
        real(session, scan_id, progress)

    monkeypatch.setattr(store, "set_progress", record)
    first = {}

    def read(regions):
        with client.app.state.session_factory() as session:
            first["progress"] = store.active_scan(session).progress
        return read_resources(regions)

    client = make_client(tmp_path, extended=lambda regions: output(), scan=read)

    run_scan(client)

    assert first["progress"] == "Reading resources"
    assert seen == ["Running CloudShield rules", RUNNING, "Importing results"]


def test_a_scan_without_the_extended_option_does_not_run_it(tmp_path):
    calls = []
    client = make_client(tmp_path, extended=lambda regions: calls.append(regions))

    scan = run_scan(client, extended=False)

    assert calls == []
    assert scan["status"] == "completed"
    assert scan["extended_status"] == "skipped"
    assert scan["extended_message"] is None
    assert findings(client, "prowler") == []


def test_the_scan_without_a_body_is_still_a_plain_scan(tmp_path):
    client = make_client(tmp_path, scan=read_resources)
    client.app.state.settings.aws_region = "ap-southeast-2"

    started = client.post("/api/scans")

    assert wait_for(client, started.json()["id"])["extended_status"] == "skipped"


def test_the_extended_option_must_be_true_or_false(tmp_path):
    client = make_client(tmp_path)

    response = client.post("/api/scans", json={"regions": ["us-east-1"], "extended": "maybe"})

    assert response.status_code == 422


def test_a_failed_extended_stage_does_not_fail_the_scan(tmp_path):
    def failing(regions):
        raise ExtendedError("failed", "Prowler stopped with exit code 1.", "See the docs.")

    client = make_client(tmp_path, extended=failing)

    scan = run_scan(client)

    assert scan["status"] == "completed"
    assert scan["failure_message"] is None
    assert scan["extended_status"] == "failed"
    assert scan["extended_message"] == "Prowler stopped with exit code 1."
    assert scan["extended_hint"] == "See the docs."
    assert [f["rule_id"] for f in findings(client)] == ["CIS-S3-001"]


def test_an_unavailable_runner_is_recorded_as_unavailable(tmp_path):
    def missing(regions):
        raise ExtendedError("unavailable", "Prowler was not found.", "Set PROWLER_PYTHON.")

    client = make_client(tmp_path, extended=missing)

    scan = run_scan(client)

    assert scan["status"] == "completed"
    assert scan["extended_status"] == "unavailable"
    assert scan["extended_hint"] == "Set PROWLER_PYTHON."


def test_an_unexpected_error_in_the_extended_stage_still_leaves_a_completed_scan(tmp_path):
    def broken(regions):
        raise RuntimeError("secret detail AKIAABCDEFGHIJKLMNOP")

    client = make_client(tmp_path, extended=broken)

    scan = run_scan(client)

    assert scan["status"] == "completed"
    assert scan["extended_status"] == "failed"
    assert "RuntimeError" in scan["extended_message"]
    assert "AKIAABCDEFGHIJKLMNOP" not in str(scan)
    assert len(findings(client)) == 1


def test_a_rejected_results_file_is_a_failure_with_the_reason(tmp_path):
    client = make_client(tmp_path, extended=lambda regions: output(b"not json"))

    scan = run_scan(client)

    assert scan["status"] == "completed"
    assert scan["extended_status"] == "failed"
    assert "rejected" in scan["extended_message"]
    assert "not valid JSON" in scan["extended_message"]


def test_a_file_from_another_ocsf_version_is_rejected_cleanly(tmp_path):
    content = to_bytes([entry(version="2.0.0")])
    client = make_client(tmp_path, extended=lambda regions: output(content))

    scan = run_scan(client)

    assert scan["extended_status"] == "failed"
    assert "major version 2" in scan["extended_message"]


def test_an_identical_file_is_reported_as_already_imported_not_as_an_error(tmp_path):
    client = make_client(tmp_path, extended=lambda regions: output())
    run_scan(client)

    second = run_scan(client)

    assert second["extended_status"] == "ok"
    assert "already imported" in second["extended_message"]
    assert second["extended_hint"] is None
    with client.app.state.session_factory() as session:
        assert len(session.scalars(select(ImportRow)).all()) == 1


def test_permission_errors_in_the_run_give_the_permissions_hint_but_keep_the_results(tmp_path):
    client = make_client(tmp_path, extended=lambda regions: output(permission_errors=True))

    scan = run_scan(client)

    assert scan["extended_status"] == "ok"
    assert scan["extended_message"].endswith("Prowler reported errors.")
    assert scan["extended_hint"] == PERMISSION_HINT
    assert len(findings(client, "prowler")) == 2


def test_the_import_from_the_dashboard_records_how_it_was_made(tmp_path):
    client = make_client(tmp_path, extended=lambda regions: output())

    scan = run_scan(client)

    imported = client.get("/api/imports").json()[0]
    assert imported["origin"] == "dashboard"
    assert imported["duration_seconds"] == 12.5
    assert imported["services_used"] == ["s3", "ec2", "iam"]
    assert imported["regions_used"] == ["ap-southeast-2"]
    assert imported["scan_id"] == scan["id"]
    assert imported["file_name"] == "prowler-output-1.ocsf.json"


def test_findings_from_the_run_are_scored_against_this_scan(tmp_path):
    content = to_bytes([entry(check="s3_bucket_level_public_access_block")])
    client = make_client(tmp_path, extended=lambda regions: output(content))

    run_scan(client)

    ours = next(f for f in findings(client) if f["rule_id"] == "CIS-S3-001")
    assert [c["check_id"] for c in ours["corroborated_by"]] == [
        "s3_bucket_level_public_access_block"
    ]
    assert findings(client, "prowler") == []


def test_a_second_run_while_one_is_running_gets_409(tmp_path):
    started, release = threading.Event(), threading.Event()

    def slow(regions):
        started.set()
        release.wait(5)
        return output()

    client = make_client(tmp_path, extended=slow)
    first = client.post("/api/scans", json={"regions": ["ap-southeast-2"], "extended": True})
    assert started.wait(5)

    second = client.post("/api/scans", json={"regions": ["ap-southeast-2"], "extended": True})

    assert first.status_code == 202
    assert second.status_code == 409
    release.set()
    assert wait_for(client, first.json()["id"])["status"] == "completed"


def test_the_real_runner_with_a_fake_program_through_the_api_leaks_nothing(tmp_path, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "fake-gemini-secret")
    settings = settings_for(tmp_path)
    err = b"key AKIAABCDEFGHIJKLMNOP for account 123456789012"
    popen = FakePopen(FakeProcess(code=1, err=err))

    def runner(regions):
        return run_prowler(settings, regions, popen=popen, kill=Killer(), poll_seconds=0.01)

    client = make_client(tmp_path, extended=runner)

    scan = run_scan(client)

    shown = str(scan) + str(client.get("/api/scans").json())
    assert scan["extended_status"] == "failed"
    assert "AKIAABCDEFGHIJKLMNOP" not in shown
    assert "123456789012" not in shown
    assert "fake-gemini-secret" not in shown
    assert "fake-gemini-secret" not in str(popen.calls)


def test_the_real_runner_with_a_fake_program_imports_through_the_api(tmp_path):
    settings = settings_for(tmp_path)
    popen = FakePopen()

    def runner(regions):
        return run_prowler(settings, regions, popen=popen, kill=Killer(), poll_seconds=0.01)

    client = make_client(tmp_path, extended=runner)

    scan = run_scan(client)

    assert scan["extended_status"] == "ok"
    run_dir = Path(popen.calls[0]["cwd"]).resolve()
    assert popen.argv[-4:] == ["-o", str(run_dir), "-b", "-z"]
    assert list((tmp_path / "data" / "runs").iterdir()) == []


# status endpoint


def test_the_status_endpoint_says_whether_the_extended_checks_can_run(tmp_path):
    status = StatusCache(lambda: RunnerStatus(True, "Prowler 5.44.0", None, None))
    client = make_client(tmp_path, status=status)

    answer = client.get("/api/extended/status").json()

    assert answer == {
        "available": True,
        "version": "Prowler 5.44.0",
        "reason": None,
        "hint": None,
        "blocked": False,
        "install_command": "pip install prowler",
        "run_command": None,
    }


def test_the_status_endpoint_gives_the_reason_and_hint_when_it_cannot(tmp_path):
    unavailable = RunnerStatus(False, None, "Prowler was not found.", "Set PROWLER_PYTHON.")
    client = make_client(tmp_path, status=StatusCache(lambda: unavailable))

    answer = client.get("/api/extended/status").json()

    assert answer["available"] is False
    assert answer["reason"] == "Prowler was not found."
    assert answer["hint"] == "Set PROWLER_PYTHON."


def test_the_status_is_cached_for_a_minute_and_never_starts_a_scan(tmp_path):
    now = [0.0]
    asked = []
    scans = []

    def ask():
        asked.append(now[0])
        return RunnerStatus(True, "v", None, None)

    status = StatusCache(ask, 60, clock=lambda: now[0])
    client = make_client(tmp_path, status=status, scan=lambda regions: scans.append(regions))

    for at in (0, 10, 59):
        now[0] = at
        client.get("/api/extended/status")
    assert asked == [0]
    now[0] = 61
    client.get("/api/extended/status")

    assert asked == [0, 61]
    assert scans == []
    assert client.get("/api/scans").json() == []


# check-runner command


def test_check_runner_command_prints_the_version(monkeypatch, capsys):
    ready = RunnerStatus(True, "Prowler 5.44.0", None, None)
    monkeypatch.setattr(import_cli, "check_runner", lambda settings: ready)

    code = import_cli.main(["check-runner"], load_env=False)

    assert code == 0
    assert "Prowler 5.44.0" in capsys.readouterr().out


def test_check_runner_command_prints_the_reason_and_the_fix(monkeypatch, capsys):
    blocked = RunnerStatus(False, None, "blocked by a policy", "Use PROWLER_PYTHON, Docker or WSL.")
    monkeypatch.setattr(import_cli, "check_runner", lambda settings: blocked)

    code = import_cli.main(["check-runner"], load_env=False)

    out = capsys.readouterr().out
    assert code == 1
    assert "blocked by a policy" in out
    assert "Docker or WSL" in out


# migration


def test_the_migration_keeps_earlier_scans_and_imports(tmp_path, monkeypatch):
    url = f"sqlite:///{tmp_path / 'old.db'}"
    monkeypatch.setenv("DATABASE_URL", url)
    config = Config(str(ROOT / "alembic.ini"))
    migrations = ROOT / "src" / "cloudshield" / "db" / "migrations"
    config.set_main_option("script_location", str(migrations))
    command.upgrade(config, "0005")
    with create_engine(url).begin() as connection:
        connection.execute(
            text(
                "insert into scans (id, status, regions, resource_count, finding_count, "
                "error_count, errors) values (1, 'completed', '[]', 0, 0, 0, '[]')"
            )
        )
        connection.execute(
            text(
                "insert into imports (id, source, file_sha256, imported_at, counts, "
                "regions_covered, checks_covered) values (1, 'prowler', 'abc', "
                "'2026-10-02 00:00:00', "
                '\'{"imported": 2, "already_seen": 0, "resolved": 0, "rejected": 0, '
                "\"ignored\": 0}', '[]', '[]')"
            )
        )

    command.upgrade(config, "head")

    client = TestClient(create_app(database_url=url, load_env=False))
    scan = client.get("/api/scans/1").json()
    old = client.get("/api/imports").json()[0]
    assert scan["extended_status"] == "skipped"
    assert scan["extended_message"] is None
    assert old["origin"] == "file"
    assert old["duration_seconds"] is None
    assert old["scan_id"] is None
    assert client.get("/api/findings").json() == []
