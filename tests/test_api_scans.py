import threading
import time

import boto3
from fastapi.testclient import TestClient
from moto import mock_aws
from sqlalchemy import select

from cloudshield.api.app import create_app
from cloudshield.db import store
from cloudshield.db.models import Base, FindingRow, ResourceRow, ScanRow
from cloudshield.db.session import make_engine
from cloudshield.scanner.common import make_resource

ALL_ON = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}
AES = [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
OPEN_SSH = {
    "IpProtocol": "tcp",
    "FromPort": 22,
    "ToPort": 22,
    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
    "Ipv6Ranges": [],
}


def make_client(tmp_path, scan_function=None) -> TestClient:
    url = f"sqlite:///{tmp_path / 'test.db'}"
    Base.metadata.create_all(make_engine(url))
    return TestClient(create_app(database_url=url, scan_function=scan_function))


def scan_returning(*results):
    queue = list(results)

    def scan(regions):
        return queue.pop(0)

    return scan


def result(resources, errors=()) -> dict:
    return {"resources": list(resources), "errors": list(errors)}


def bucket(name="my-bucket", versioning="Disabled", block=ALL_ON) -> dict:
    attributes = {
        "public_access_block": block,
        "encryption": AES,
        "versioning": versioning,
        "policy": None,
    }
    return make_resource(name, "S3", "us-east-1", name, attributes)


def open_group(region="ap-southeast-2") -> dict:
    attributes = {"vpc_id": "vpc-1", "inbound": [OPEN_SSH], "outbound": []}
    return make_resource("sg-1", "Security Group", region, "web", attributes)


def wait_for_scan(client, scan_id: int) -> dict:
    for _ in range(1000):
        scan = client.get(f"/api/scans/{scan_id}").json()
        if scan["status"] in ("completed", "failed"):
            return scan
        time.sleep(0.01)
    raise AssertionError(f"scan {scan_id} did not finish")


def run_scan(client, regions=("us-east-1",)) -> dict:
    response = client.post("/api/scans", json={"regions": list(regions)})
    assert response.status_code == 202
    return wait_for_scan(client, response.json()["id"])


def findings_by_rule(client, rule_id: str, **params) -> list[dict]:
    return client.get("/api/findings", params={"rule_id": rule_id, **params}).json()


def test_scan_stores_resources_findings_and_counts(tmp_path):
    client = make_client(tmp_path, scan_returning(result([bucket(), open_group()])))

    scan = run_scan(client, ["us-east-1", "ap-southeast-2"])

    assert scan["status"] == "completed"
    assert scan["regions"] == ["us-east-1", "ap-southeast-2"]
    assert scan["resource_count"] == 2
    assert scan["finding_count"] == 3
    assert scan["error_count"] == 0
    assert scan["started_at"].endswith("Z")
    assert scan["finished_at"] is not None
    assert scan["failure_message"] is None
    assert len(client.get("/api/resources").json()) == 2


def test_scan_errors_are_stored_and_the_scan_still_completes(tmp_path):
    error = {"service": "ec2", "region": "us-east-1", "resource": None, "message": "AccessDenied"}
    client = make_client(tmp_path, scan_returning(result([bucket()], [error])))

    scan = run_scan(client)

    assert scan["status"] == "completed"
    assert scan["error_count"] == 1
    assert scan["errors"] == [error]


def test_rescan_resolves_a_finding_that_was_fixed(tmp_path):
    before_fix = result([bucket(versioning="Disabled")])
    after_fix = result([bucket(versioning="Enabled")])
    client = make_client(tmp_path, scan_returning(before_fix, after_fix))
    run_scan(client)
    before = findings_by_rule(client, "CIS-S3-003")[0]

    second = run_scan(client)

    after = client.get(f"/api/findings/{before['finding_id']}").json()
    assert before["status"] == "OPEN"
    assert after["status"] == "RESOLVED"
    assert after["resolution_reason"] == "no longer detected"
    assert after["resolved_at"] is not None
    assert after["last_scan_id"] == second["id"]


def test_rescan_resolves_a_finding_whose_resource_is_gone(tmp_path):
    client = make_client(tmp_path, scan_returning(result([bucket()]), result([])))
    run_scan(client)

    run_scan(client)

    finding = findings_by_rule(client, "CIS-S3-003")[0]
    assert finding["status"] == "RESOLVED"
    assert finding["resolution_reason"] == "resource not found"


def test_errored_service_does_not_resolve_its_findings(tmp_path):
    error = {"service": "s3", "region": None, "resource": None, "message": "AccessDenied"}
    client = make_client(tmp_path, scan_returning(result([bucket()]), result([], [error])))
    run_scan(client)

    run_scan(client)

    finding = findings_by_rule(client, "CIS-S3-003")[0]
    assert finding["status"] == "OPEN"
    assert finding["resolved_at"] is None


def test_error_in_another_service_does_not_block_resolving(tmp_path):
    error = {"service": "ec2", "region": "us-east-1", "resource": None, "message": "denied"}
    client = make_client(tmp_path, scan_returning(result([bucket()]), result([], [error])))
    run_scan(client)

    run_scan(client)

    assert findings_by_rule(client, "CIS-S3-003")[0]["status"] == "RESOLVED"


def test_finding_in_a_region_that_was_not_rescanned_stays_open(tmp_path):
    client = make_client(tmp_path, scan_returning(result([open_group()]), result([]), result([])))
    run_scan(client, ["ap-southeast-2"])

    run_scan(client, ["us-east-1"])
    still_open = findings_by_rule(client, "CIS-SG-001")[0]["status"]
    run_scan(client, ["ap-southeast-2"])
    resolved = findings_by_rule(client, "CIS-SG-001")[0]

    assert still_open == "OPEN"
    assert resolved["status"] == "RESOLVED"
    assert resolved["resolution_reason"] == "resource not found"


def test_finding_seen_again_stays_open_and_keeps_first_seen(tmp_path):
    client = make_client(tmp_path, scan_returning(result([bucket()]), result([bucket()])))
    run_scan(client)
    before = findings_by_rule(client, "CIS-S3-003")[0]

    second = run_scan(client)

    after = findings_by_rule(client, "CIS-S3-003")[0]
    assert after["status"] == "OPEN"
    assert after["finding_id"] == before["finding_id"]
    assert after["first_seen_at"] == before["first_seen_at"]
    assert after["last_seen_at"] >= before["last_seen_at"]
    assert after["last_scan_id"] == second["id"]


def test_finding_that_comes_back_is_reopened(tmp_path):
    broken = result([bucket()])
    fixed = result([bucket(versioning="Enabled")])
    client = make_client(tmp_path, scan_returning(broken, fixed, result([bucket()])))
    run_scan(client)
    first_seen = findings_by_rule(client, "CIS-S3-003")[0]["first_seen_at"]
    run_scan(client)

    run_scan(client)

    finding = findings_by_rule(client, "CIS-S3-003")[0]
    assert finding["status"] == "OPEN"
    assert finding["resolved_at"] is None
    assert finding["resolution_reason"] is None
    assert finding["first_seen_at"] == first_seen


def test_failed_scan_shows_the_real_message(tmp_path):
    def no_credentials(regions):
        raise RuntimeError("No AWS credentials found. Set AWS_PROFILE on the server.")

    client = make_client(tmp_path, no_credentials)

    scan = run_scan(client)

    assert scan["status"] == "failed"
    assert scan["failure_message"] == (
        "RuntimeError: No AWS credentials found. Set AWS_PROFILE on the server."
    )
    assert scan["finished_at"] is not None
    assert client.get("/api/findings").json() == []


def test_a_failed_scan_does_not_block_the_next_one(tmp_path):
    def broken(regions):
        raise RuntimeError("boom")

    client = make_client(tmp_path, broken)
    run_scan(client)

    response = client.post("/api/scans", json={"regions": ["us-east-1"]})

    assert response.status_code == 202
    wait_for_scan(client, response.json()["id"])


def test_second_scan_while_one_is_running_gets_409(tmp_path):
    release = threading.Event()

    def slow_scan(regions):
        release.wait(timeout=10)
        return result([])

    client = make_client(tmp_path, slow_scan)
    first = client.post("/api/scans", json={"regions": ["us-east-1"]})

    second = client.post("/api/scans", json={"regions": ["us-east-1"]})
    release.set()
    wait_for_scan(client, first.json()["id"])
    third = client.post("/api/scans", json={"regions": ["us-east-1"]})
    wait_for_scan(client, third.json()["id"])

    assert first.status_code == 202
    assert second.status_code == 409
    assert third.status_code == 202


def test_stale_running_scan_is_marked_failed_when_the_server_starts(tmp_path):
    client = make_client(tmp_path)
    with client.app.state.session_factory() as session:
        scan_id = store.create_scan(session, ["us-east-1"]).id

    with client:
        scan = client.get(f"/api/scans/{scan_id}").json()

    assert scan["status"] == "failed"
    assert "restarted" in scan["failure_message"]


def test_regions_default_to_aws_region_from_the_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("AWS_REGION", "ap-southeast-2")
    received = []

    def recording_scan(regions):
        received.append(regions)
        return result([])

    client = make_client(tmp_path, recording_scan)

    response = client.post("/api/scans")
    wait_for_scan(client, response.json()["id"])

    assert response.status_code == 202
    assert received == [["ap-southeast-2"]]


def test_scan_without_regions_and_without_aws_region_is_rejected(tmp_path, monkeypatch):
    monkeypatch.delenv("AWS_REGION", raising=False)
    client = make_client(tmp_path, scan_returning(result([])))

    no_body = client.post("/api/scans")
    empty_list = client.post("/api/scans", json={"regions": []})

    assert no_body.status_code == 422
    assert "AWS_REGION" in no_body.json()["detail"]
    assert empty_list.status_code == 422
    assert client.get("/api/scans").json() == []


def test_request_cannot_choose_the_aws_profile_or_send_bad_regions(tmp_path):
    client = make_client(tmp_path, scan_returning(result([])))

    with_profile = client.post("/api/scans", json={"regions": ["us-east-1"], "profile": "x"})
    bad_region = client.post("/api/scans", json={"regions": ["us-east-1/../x"]})

    assert with_profile.status_code == 422
    assert bad_region.status_code == 422


def test_scans_are_listed_newest_first_and_unknown_scan_is_404(tmp_path):
    client = make_client(tmp_path, scan_returning(result([]), result([])))
    first = run_scan(client)
    second = run_scan(client)

    listed = client.get("/api/scans").json()

    assert [s["id"] for s in listed] == [second["id"], first["id"]]
    assert client.get("/api/scans/999").status_code == 404


def test_findings_can_be_filtered(tmp_path):
    open_block = {**ALL_ON, "BlockPublicPolicy": False}
    client = make_client(
        tmp_path,
        scan_returning(
            result([bucket("a", "Disabled", open_block), bucket("b", "Enabled"), open_group()]),
            result([bucket("a", "Disabled", ALL_ON), bucket("b", "Enabled")]),
        ),
    )
    run_scan(client)
    run_scan(client, ["ap-southeast-2", "us-east-1"])

    def ids(**params) -> list[str]:
        return [f["rule_id"] for f in client.get("/api/findings", params=params).json()]

    assert ids(severity="HIGH", status="RESOLVED") == ["CIS-S3-001", "CIS-SG-001"]
    assert ids(severity="INFO") == ["CIS-S3-002", "CIS-S3-002"]
    assert ids(rule_id="CIS-S3-003") == ["CIS-S3-003"]
    assert ids(resource_type="Security Group") == ["CIS-SG-001"]
    assert ids(status="OPEN", resource_type="S3") == ["CIS-S3-003", "CIS-S3-002", "CIS-S3-002"]
    assert client.get("/api/findings", params={"severity": "BAD"}).status_code == 422
    assert client.get("/api/findings", params={"status": "BAD"}).status_code == 422


def test_resources_can_be_filtered_by_type(tmp_path):
    client = make_client(tmp_path, scan_returning(result([bucket(), open_group()])))
    run_scan(client, ["us-east-1", "ap-southeast-2"])

    buckets = client.get("/api/resources", params={"resource_type": "S3"}).json()
    groups = client.get("/api/resources", params={"resource_type": "Security Group"}).json()

    assert [r["resource_id"] for r in buckets] == ["my-bucket"]
    assert [r["resource_id"] for r in groups] == ["sg-1"]
    assert buckets[0]["attributes"]["versioning"] == "Disabled"


def test_finding_detail_includes_the_resource_attributes_as_evidence(tmp_path):
    client = make_client(tmp_path, scan_returning(result([bucket()])))
    run_scan(client)
    finding = findings_by_rule(client, "CIS-S3-003")[0]

    detail = client.get(f"/api/findings/{finding['finding_id']}").json()

    assert detail["details"] == {"versioning": "Disabled"}
    assert detail["resource"]["resource_id"] == "my-bucket"
    assert detail["resource"]["attributes"]["versioning"] == "Disabled"
    assert client.get("/api/findings/F-NOPE-00000000").status_code == 404


def test_every_row_has_account_id_local(tmp_path):
    client = make_client(tmp_path, scan_returning(result([bucket(), open_group()])))
    run_scan(client, ["us-east-1", "ap-southeast-2"])

    with client.app.state.session_factory() as session:
        rows = [
            *session.scalars(select(ScanRow)),
            *session.scalars(select(ResourceRow)),
            *session.scalars(select(FindingRow)),
        ]

    assert len(rows) >= 5
    assert {row.account_id for row in rows} == {"local"}


@mock_aws
def test_default_scanner_runs_against_mocked_aws(tmp_path):
    boto3.client("s3", region_name="us-east-1").create_bucket(Bucket="mock-bucket")
    client = make_client(tmp_path)

    scan = run_scan(client, ["us-east-1"])

    assert scan["status"] == "completed"
    assert scan["error_count"] == 0
    buckets = client.get("/api/resources", params={"resource_type": "S3"}).json()
    assert [r["resource_id"] for r in buckets] == ["mock-bucket"]
    assert findings_by_rule(client, "CIS-S3-001")[0]["resource_id"] == "mock-bucket"


def instance(state="running", groups=("sg-1",)) -> dict:
    attributes = {
        "state": state,
        "security_group_ids": list(groups),
        "has_public_ip": True,
        "instance_profile_arn": None,
    }
    return make_resource("i-1", "EC2", "ap-southeast-2", "i-1", attributes)


def attached_wildcard_policy() -> dict:
    document = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    attributes = {
        "document": document,
        "attached_to": {"users": [], "roles": ["app"], "groups": []},
    }
    return make_resource("arn:aws:iam::1:policy/p", "IAM Policy", None, "p", attributes)


def test_findings_include_risk_score_factors_and_evidence(tmp_path):
    open_block = {**ALL_ON, "BlockPublicPolicy": False}
    client = make_client(tmp_path, scan_returning(result([bucket("a", "Enabled", open_block)])))
    run_scan(client)

    finding = findings_by_rule(client, "CIS-S3-001")[0]
    detail = client.get(f"/api/findings/{finding['finding_id']}").json()
    info = findings_by_rule(client, "CIS-S3-002")[0]

    assert finding["risk_score"] == 85
    assert finding["risk_factors"][0]["factor"] == "exposure"
    assert finding["risk_factors"][0]["adjustment"] == 15
    assert detail["risk_score"] == 85
    assert detail["evidence"]["items"][2]["fact"] == "BlockPublicPolicy"
    assert detail["evidence"]["items"][2]["value"] is False
    assert detail["evidence"]["items"][2]["certainty"] == "verified"
    assert info["risk_score"] is None
    assert info["risk_factors"] == []


def test_scan_stores_the_environment_score_and_severity_counts(tmp_path):
    open_block = {**ALL_ON, "BlockPublicPolicy": False}
    client = make_client(tmp_path, scan_returning(result([bucket("a", "Enabled", open_block)])))

    scan = run_scan(client)

    assert scan["environment_score"] == 85.0
    assert scan["severity_counts"] == {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 1}


def test_resolved_finding_keeps_its_score_but_leaves_the_environment_score(tmp_path):
    open_block = {**ALL_ON, "BlockPublicPolicy": False}
    broken = result([bucket("a", "Enabled", open_block)])
    fixed = result([bucket("a", "Enabled", ALL_ON)])
    client = make_client(tmp_path, scan_returning(broken, fixed))
    run_scan(client)

    second = run_scan(client)

    resolved = findings_by_rule(client, "CIS-S3-001")[0]
    summary = client.get("/api/risk/summary").json()
    assert resolved["status"] == "RESOLVED"
    assert resolved["risk_score"] == 85
    assert second["environment_score"] == 0.0
    assert summary["environment_score"] == 0.0
    assert summary["counts_by_severity"]["HIGH"] == 0
    assert summary["top_findings"] == []


def test_trend_has_one_point_per_completed_scan(tmp_path):
    open_block = {**ALL_ON, "BlockPublicPolicy": False}
    broken = result([bucket("a", "Enabled", open_block)])
    fixed = result([bucket("a", "Enabled", ALL_ON)])
    client = make_client(tmp_path, scan_returning(broken, fixed))
    first = run_scan(client)
    second = run_scan(client)

    trend = client.get("/api/risk/trend").json()

    assert [point["scan_id"] for point in trend] == [first["id"], second["id"]]
    assert [point["environment_score"] for point in trend] == [85.0, 0.0]
    assert trend[0]["severity_counts"]["HIGH"] == 1
    assert trend[1]["severity_counts"]["HIGH"] == 0
    assert trend[0]["finished_at"].endswith("Z")


def test_trend_skips_scans_that_failed(tmp_path):
    calls = []

    def scan_once_then_fail(regions):
        if calls:
            raise RuntimeError("boom")
        calls.append(1)
        return result([bucket()])

    client = make_client(tmp_path, scan_once_then_fail)
    run_scan(client)
    run_scan(client)

    assert len(client.get("/api/risk/trend").json()) == 1


def test_risk_summary_has_the_environment_score_counts_and_top_five(tmp_path):
    resources = [
        bucket("a", "Disabled", {name: False for name in ALL_ON}),
        bucket("b", "Disabled", ALL_ON),
        open_group(),
        instance(),
        attached_wildcard_policy(),
    ]
    client = make_client(tmp_path, scan_returning(result(resources)))
    run_scan(client, ["us-east-1", "ap-southeast-2"])

    summary = client.get("/api/risk/summary").json()

    assert [f["risk_score"] for f in summary["top_findings"]] == [95, 85, 80, 80, 55]
    assert summary["top_findings"][0]["rule_id"] == "CIS-SG-001"
    assert summary["counts_by_severity"] == {
        "CRITICAL": 0,
        "HIGH": 4,
        "MEDIUM": 2,
        "LOW": 0,
        "INFO": 2,
    }
    assert summary["environment_score"] == 100.0


def test_risk_summary_with_no_scans_is_all_zero(tmp_path):
    client = make_client(tmp_path)

    summary = client.get("/api/risk/summary").json()

    assert summary["environment_score"] == 0.0
    assert set(summary["counts_by_severity"].values()) == {0}
    assert summary["top_findings"] == []
    assert client.get("/api/risk/trend").json() == []
