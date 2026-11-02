import asyncio
import contextlib
import threading
import time

import pytest
from fastapi import Request
from fastapi.testclient import TestClient
from prowler_data import entry, to_bytes
from sqlalchemy.exc import OperationalError

from cloudshield.api import routes
from cloudshield.api.app import create_app
from cloudshield.api.jobs import JobLock, run_scan_job
from cloudshield.db import store
from cloudshield.db.models import Base, ScanRow
from cloudshield.db.session import make_engine, make_session_factory
from cloudshield.imports.runner import ExtendedError

REGIONS = ["ap-southeast-2"]
JSON = {"Content-Type": "application/json"}


def no_resources(regions):
    return {"resources": [], "errors": []}


def make_client(tmp_path, scan=no_resources) -> TestClient:
    url = f"sqlite:///{tmp_path / 'test.db'}"
    Base.metadata.create_all(make_engine(url))
    return TestClient(create_app(database_url=url, scan_function=scan, load_env=False))


def wait_until_free(lock: JobLock) -> None:
    for _ in range(500):
        if lock.holder is None:
            return
        time.sleep(0.01)
    raise AssertionError("the lock was not released")


def start_scan(client):
    return client.post("/api/scans", json={"regions": REGIONS})


def upload(client):
    return client.post("/api/imports/prowler", content=to_bytes([entry()]), headers=JSON)


def slow_scan():
    started, release = threading.Event(), threading.Event()

    def scan(regions):
        started.set()
        release.wait(5)
        return no_resources(regions)

    return scan, started, release


def run_job(tmp_path, scan_function, extended=None) -> JobLock:
    engine = make_engine(f"sqlite:///{tmp_path / 'job.db'}")
    Base.metadata.create_all(engine)
    factory = make_session_factory(engine)
    with factory() as session:
        scan = store.create_scan(session, REGIONS)
    lock = JobLock()
    assert lock.take("scan") is None
    run_scan_job(factory, scan.id, REGIONS, scan_function, extended, lock)
    return lock


def test_a_taken_lock_says_what_holds_it_and_is_free_again_after_release():
    lock = JobLock()

    assert lock.take("import") is None
    assert lock.take("scan") == "import"
    lock.release()

    assert lock.take("scan") is None


def test_eight_simultaneous_takes_let_exactly_one_win():
    lock = JobLock()
    barrier = threading.Barrier(8)
    results = []

    def grab():
        barrier.wait()
        results.append(lock.take("scan"))

    threads = [threading.Thread(target=grab) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert results.count(None) == 1


def test_two_simultaneous_scan_starts_let_exactly_one_win(tmp_path):
    scan, _, release = slow_scan()
    client = make_client(tmp_path, scan)
    other = TestClient(client.app)
    barrier = threading.Barrier(2)
    codes = []

    def start(test_client):
        barrier.wait()
        codes.append(start_scan(test_client).status_code)

    threads = [threading.Thread(target=start, args=(c,)) for c in (client, other)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(codes) == [202, 409]
    release.set()
    wait_until_free(client.app.state.job_lock)


def test_a_scan_cannot_start_while_an_upload_holds_the_lock(tmp_path):
    client = make_client(tmp_path)
    lock = client.app.state.job_lock
    assert lock.take("import") is None

    reply = start_scan(client)

    assert reply.status_code == 409
    assert reply.json()["detail"] == "An import is running."
    assert lock.holder == "import"
    lock.release()
    assert start_scan(client).status_code == 202
    wait_until_free(lock)


def test_an_upload_is_refused_while_a_scan_holds_the_lock(tmp_path):
    scan, started, release = slow_scan()
    client = make_client(tmp_path, scan)
    assert start_scan(client).status_code == 202
    assert started.wait(5)

    reply = upload(client)

    assert reply.status_code == 409
    assert reply.json()["detail"] == "A scan is running."
    assert client.get("/api/imports").json() == []
    release.set()
    wait_until_free(client.app.state.job_lock)
    assert upload(client).status_code == 200


def test_a_second_scan_is_refused_while_one_runs(tmp_path):
    scan, started, release = slow_scan()
    client = make_client(tmp_path, scan)
    assert start_scan(client).status_code == 202
    assert started.wait(5)

    reply = start_scan(client)

    assert reply.status_code == 409
    assert reply.json()["detail"] == "A scan is running."
    release.set()
    wait_until_free(client.app.state.job_lock)


def test_the_lock_is_free_after_an_upload_succeeds_and_after_one_is_refused(tmp_path):
    client = make_client(tmp_path)
    lock = client.app.state.job_lock

    assert upload(client).status_code == 200
    assert lock.holder is None

    client.post("/api/imports/prowler", content=b"not json", headers=JSON)
    assert lock.holder is None


def test_the_lock_is_free_after_a_scan_succeeds(tmp_path):
    assert run_job(tmp_path, no_resources).holder is None


def test_the_lock_is_free_after_a_scan_fails_with_an_error(tmp_path):
    def broken(regions):
        raise RuntimeError("no credentials")

    assert run_job(tmp_path, broken).holder is None


@pytest.mark.parametrize(
    "message",
    ["Prowler did not finish within 3600 seconds and was stopped.", "It was cancelled."],
)
def test_the_lock_is_free_after_the_extended_stage_times_out_or_is_cancelled(tmp_path, message):
    def stopped(regions):
        raise ExtendedError("failed", message, "")

    assert run_job(tmp_path, no_resources, stopped).holder is None


def test_the_lock_is_free_after_an_unexpected_error_in_the_extended_stage(tmp_path):
    def broken(regions):
        raise RuntimeError("boom")

    assert run_job(tmp_path, no_resources, broken).holder is None


def make_job(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'job.db'}")
    Base.metadata.create_all(engine)
    factory = make_session_factory(engine)
    with factory() as session:
        scan_id = store.create_scan(session, REGIONS).id
    lock = JobLock()
    assert lock.take("scan") is None
    return factory, scan_id, lock


def status_of(factory, scan_id) -> str:
    with factory() as session:
        return session.get(ScanRow, scan_id).status


def test_a_failure_in_mark_running_fails_the_scan_and_frees_the_lock(tmp_path, monkeypatch):
    factory, scan_id, lock = make_job(tmp_path)
    real = store.mark_running
    calls = []

    def broken(session, sid):
        calls.append(sid)
        raise OperationalError("update", {}, Exception("database is locked"))

    monkeypatch.setattr(store, "mark_running", broken)

    run_scan_job(factory, scan_id, REGIONS, no_resources, None, lock)

    assert calls == [scan_id]
    assert status_of(factory, scan_id) == "failed"
    assert lock.holder is None


def test_a_failure_in_mark_failed_still_fails_the_scan_and_frees_the_lock(tmp_path, monkeypatch):
    factory, scan_id, lock = make_job(tmp_path)
    real = store.mark_failed
    calls = []

    def fails_once(session, sid, message):
        calls.append(sid)
        if len(calls) == 1:
            raise OperationalError("update", {}, Exception("database is locked"))
        real(session, sid, message)

    def broken_scan(regions):
        raise RuntimeError("no credentials")

    monkeypatch.setattr(store, "mark_failed", fails_once)

    run_scan_job(factory, scan_id, REGIONS, broken_scan, None, lock)

    assert len(calls) == 2
    assert status_of(factory, scan_id) == "failed"
    assert lock.holder is None


def test_a_new_scan_works_after_a_failed_mark_running(tmp_path, monkeypatch):
    client = make_client(tmp_path)
    lock = client.app.state.job_lock
    real = store.mark_running

    def broken(session, sid):
        raise OperationalError("update", {}, Exception("database is locked"))

    monkeypatch.setattr(store, "mark_running", broken)
    assert start_scan(client).status_code == 202
    wait_until_free(lock)
    monkeypatch.setattr(store, "mark_running", real)

    assert start_scan(client).status_code == 202
    wait_until_free(lock)
    scans = client.get("/api/scans").json()
    assert sorted(s["status"] for s in scans) == ["completed", "failed"]


def test_startup_fails_leftover_queued_and_running_scans_and_a_new_scan_works(tmp_path):
    url = f"sqlite:///{tmp_path / 'test.db'}"
    Base.metadata.create_all(make_engine(url))
    factory = make_session_factory(make_engine(url))
    with factory() as session:
        queued = store.create_scan(session, REGIONS).id
        running = store.create_scan(session, REGIONS).id
        store.mark_running(session, running)

    app = create_app(database_url=url, scan_function=no_resources, load_env=False)
    with TestClient(app) as client:
        assert status_of(factory, queued) == "failed"
        assert status_of(factory, running) == "failed"
        assert start_scan(client).status_code == 202
        wait_until_free(app.state.job_lock)


def test_the_lock_is_held_until_the_import_ends_even_if_the_client_disconnects(
    tmp_path, monkeypatch
):
    client = make_client(tmp_path)
    app = client.app
    lock = app.state.job_lock
    started, finish = threading.Event(), threading.Event()

    def held_open(session_factory, raw, file_name):
        started.set()
        finish.wait(5)
        return {}

    monkeypatch.setattr(routes, "import_upload", held_open)
    body = to_bytes([entry()])

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    scope = {
        "type": "http",
        "method": "POST",
        "headers": [(b"content-type", b"application/json")],
        "app": app,
    }

    async def scenario():
        task = asyncio.create_task(routes.upload_prowler(Request(scope, receive), None))
        await asyncio.get_running_loop().run_in_executor(None, started.wait, 5)
        task.cancel()
        await asyncio.sleep(0.05)
        refused = start_scan(client).status_code
        holder = lock.holder
        finish.set()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        return refused, holder

    refused, holder = asyncio.run(scenario())

    assert refused == 409
    assert holder == "import"
    wait_until_free(lock)
    assert start_scan(client).status_code == 202
    wait_until_free(lock)
