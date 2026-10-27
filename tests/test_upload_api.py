import json

import pytest
from fastapi.testclient import TestClient
from prowler_data import entry, to_bytes

from cloudshield.api.app import create_app
from cloudshield.db import store
from cloudshield.db.models import Base
from cloudshield.db.session import make_engine
from cloudshield.imports.parser import MAX_BYTES
from cloudshield.imports.runner import BLOCKED_HINT, INSTALL_COMMAND, RunnerStatus, StatusCache
from cloudshield.imports.upload import clean_file_name

JSON = {"Content-Type": "application/json"}
# Text that is in the fixture and must never come back in a reply.
FIXTURE_TEXT = ("my-bucket", "Bucket does not block public access", "123456789012")


def make_client(tmp_path, **options) -> TestClient:
    url = f"sqlite:///{tmp_path / 'test.db'}"
    Base.metadata.create_all(make_engine(url))
    return TestClient(create_app(database_url=url, load_env=False, **options))


def fixture_file() -> bytes:
    return to_bytes([entry(), entry(check="c2", status="PASS"), entry(check="c3", uid=None)])


def upload(client, content, headers=None):
    return client.post("/api/imports/prowler", content=content, headers={**JSON, **(headers or {})})


def test_an_uploaded_file_is_imported_and_the_reply_has_counts_only(tmp_path):
    client = make_client(tmp_path)

    reply = upload(client, fixture_file(), {"X-Filename": "results.ocsf.json"})

    assert reply.status_code == 200
    assert reply.json()["counts"] == {
        "imported": 2,
        "passed": 1,
        "ignored": 0,
        "already_seen": 0,
        "resolved": 0,
        "rejected": 0,
    }
    assert [f["source"] for f in client.get("/api/findings").json()] == ["prowler", "prowler"]
    saved = client.get("/api/imports").json()[0]
    assert saved["origin"] == "upload"
    assert saved["file_name"] == "results.ocsf.json"
    assert saved["findings_added"] == 2


def test_the_reply_never_contains_text_from_the_file(tmp_path):
    client = make_client(tmp_path)

    reply = upload(client, fixture_file())

    for text in FIXTURE_TEXT:
        assert text not in reply.text


def test_an_error_reply_never_contains_text_from_the_file(tmp_path):
    client = make_client(tmp_path)
    secret = "my-bucket 123456789012 Bucket does not block public access"

    replies = [
        upload(client, secret.encode()),
        upload(client, to_bytes([entry(version="2.0.0", title=secret)])),
    ]

    assert [r.status_code for r in replies] == [422, 422]
    for reply in replies:
        for text in FIXTURE_TEXT:
            assert text not in reply.text


def test_a_file_that_is_not_json_is_refused_in_plain_words(tmp_path):
    client = make_client(tmp_path)

    reply = upload(client, b"this is not json")

    assert reply.status_code == 422
    assert "not valid JSON" in reply.json()["detail"]
    assert client.get("/api/imports").json() == []


def test_an_empty_body_is_refused(tmp_path):
    reply = upload(make_client(tmp_path), b"")

    assert reply.status_code == 422


def test_a_json_file_that_is_not_a_list_of_findings_is_refused(tmp_path):
    reply = upload(make_client(tmp_path), json.dumps({"a": 1}).encode())

    assert reply.status_code == 422
    assert "array" in reply.json()["detail"]


def test_a_file_with_another_ocsf_major_version_is_refused(tmp_path):
    client = make_client(tmp_path)

    reply = upload(client, to_bytes([entry(version="2.0.0")]))

    assert reply.status_code == 422
    assert "major version 2" in reply.json()["detail"]
    assert client.get("/api/imports").json() == []


def test_the_same_file_twice_is_refused_as_already_imported(tmp_path):
    client = make_client(tmp_path)
    upload(client, fixture_file())

    again = upload(client, fixture_file())

    assert again.status_code == 409
    assert "already imported" in again.json()["detail"]
    assert len(client.get("/api/imports").json()) == 1


def test_a_body_over_the_limit_is_refused_with_413_from_its_declared_size(tmp_path):
    client = make_client(tmp_path)

    reply = upload(client, b" " * (MAX_BYTES + 1))

    assert reply.status_code == 413
    assert client.get("/api/imports").json() == []


def test_a_streamed_body_over_the_limit_is_refused_with_413_while_reading(tmp_path):
    client = make_client(tmp_path)
    megabyte = b" " * 1024 * 1024

    def chunks():
        for _ in range(MAX_BYTES // len(megabyte) + 1):
            yield megabyte

    reply = upload(client, chunks())

    assert reply.status_code == 413


def test_a_second_import_while_one_is_running_is_refused_with_409(tmp_path):
    client = make_client(tmp_path)
    client.app.state.import_lock.acquire()

    reply = upload(client, fixture_file())

    assert reply.status_code == 409
    assert "Another import" in reply.json()["detail"]
    assert client.get("/api/imports").json() == []


def test_the_lock_is_released_after_a_refused_file(tmp_path):
    client = make_client(tmp_path)
    upload(client, b"not json")

    reply = upload(client, fixture_file())

    assert reply.status_code == 200


def test_an_import_while_a_scan_runs_is_refused_with_409(tmp_path):
    client = make_client(tmp_path)
    with client.app.state.session_factory() as session:
        store.create_scan(session, ["ap-southeast-2"])

    reply = upload(client, fixture_file())

    assert reply.status_code == 409
    assert "scan is running" in reply.json()["detail"]


def test_a_body_that_is_not_sent_as_json_is_refused_with_415(tmp_path):
    client = make_client(tmp_path)

    reply = client.post(
        "/api/imports/prowler", content=fixture_file(), headers={"Content-Type": "text/plain"}
    )

    assert reply.status_code == 415


@pytest.mark.parametrize(
    ("header", "name"),
    [
        ("report.json", "report.json"),
        ("C:\\Users\\me\\Desktop\\report.json", "report.json"),
        ("../../etc/passwd", "passwd"),
        ("..\\..\\evil\\run%201.json", "run 1.json"),
        ("%2E%2E%2Fsecret%2Frun.json", "run.json"),
        ("a\x00b\x1f.json", "ab.json"),
        ("/", None),
        ("..", None),
        ("", None),
        (None, None),
        ("x" * 300 + ".json", "x" * 100),
    ],
)
def test_the_file_name_is_cut_to_a_base_name(header, name):
    assert clean_file_name(header) == name


def test_the_stored_file_name_is_the_sanitised_base_name(tmp_path):
    client = make_client(tmp_path)

    upload(client, fixture_file(), {"X-Filename": "..%2F..%2Fsecret%2Frun.json"})

    assert client.get("/api/imports").json()[0]["file_name"] == "run.json"


def test_an_upload_resolves_a_finding_that_a_newer_file_shows_as_passing(tmp_path):
    client = make_client(tmp_path)
    upload(client, to_bytes([entry()]))

    reply = upload(client, to_bytes([entry(status="PASS")]))

    assert reply.json()["counts"]["resolved"] == 1
    assert client.get("/api/findings").json()[0]["status"] == "RESOLVED"


def test_the_browser_may_send_the_file_name_header(tmp_path):
    client = make_client(tmp_path)

    reply = client.options(
        "/api/imports/prowler",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type,x-filename",
        },
    )

    assert reply.status_code == 200
    assert "x-filename" in reply.headers["access-control-allow-headers"].lower()


def test_the_status_carries_the_blocked_flag_hint_and_the_commands(tmp_path, monkeypatch):
    monkeypatch.setenv("AWS_REGION", "ap-southeast-2")
    blocked = RunnerStatus(False, None, "Blocked.", BLOCKED_HINT, True)
    client = make_client(tmp_path, extended_status=StatusCache(lambda: blocked))

    answer = client.get("/api/extended/status").json()

    assert answer["blocked"] is True
    assert answer["hint"] == (
        "This computer blocks Prowler. Run it elsewhere, for example in AWS CloudShell, "
        "then import the file here."
    )
    assert answer["install_command"] == INSTALL_COMMAND == "pip install prowler"
    assert answer["run_command"] == (
        "prowler aws -f ap-southeast-2 --services s3 ec2 iam -M json-ocsf -o prowler-out -b -z"
    )
