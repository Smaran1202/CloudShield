from datetime import date, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from prowler_data import ACCOUNT, POLICY_ARN, entry, to_bytes

from cloudshield.api.app import create_app
from cloudshield.config import Settings
from cloudshield.db import store
from cloudshield.db.models import Base, FindingRow
from cloudshield.db.session import make_engine
from cloudshield.imports.importer import import_parsed
from cloudshield.imports.parser import parse_bytes
from cloudshield.risk.scoring import score_findings
from cloudshield.rules import run_rules
from cloudshield.scanner.common import make_resource

REASON = "This is accepted on purpose."
AWS_POLICY = "arn:aws:iam::aws:policy/AdministratorAccess"
SERVICE_ROLE = f"arn:aws:iam::{ACCOUNT}:role/aws-service-role/support.amazonaws.com/Support"
OWN_USER = f"arn:aws:iam::{ACCOUNT}:user/cloudshield-scanner"


def make_client(tmp_path) -> TestClient:
    url = f"sqlite:///{tmp_path / 'test.db'}"
    Base.metadata.create_all(make_engine(url))
    return TestClient(create_app(database_url=url, load_env=False))


def load(client, entries) -> None:
    with client.app.state.session_factory() as session:
        import_parsed(session, parse_bytes(to_bytes(entries)), "local")


def one(client, severity="High") -> str:
    load(client, [entry(severity=severity)])
    return client.get("/api/findings").json()[0]["finding_id"]


def path(finding_id: str) -> str:
    return f"/api/findings/{finding_id}/disposition"


def accept(client, finding_id: str, **overrides):
    body = {"disposition": "accepted", "disposition_reason": REASON, **overrides}
    return client.patch(path(finding_id), json=body)


def set_until(client, finding_id: str, until: datetime) -> None:
    with client.app.state.session_factory() as session:
        row = session.get(FindingRow, ("local", finding_id))
        row.disposition_until = until
        session.commit()


def test_dismissing_a_finding_records_the_reason_and_the_time(tmp_path):
    client = make_client(tmp_path)
    finding_id = one(client)

    response = accept(client, finding_id)

    finding = response.json()
    assert response.status_code == 200
    assert finding["disposition"] == "accepted"
    assert finding["disposition_reason"] == REASON
    assert finding["disposition_at"] is not None
    assert finding["disposition_until"] is None
    assert finding["dismissed"] is True
    assert finding["status"] == "OPEN"


def test_a_dismissed_finding_leaves_the_risk_summary_but_stays_listed_with_its_reason(tmp_path):
    client = make_client(tmp_path)
    finding_id = one(client)
    before = client.get("/api/risk/summary").json()
    assert before["counts_by_severity"]["HIGH"] == 1

    accept(client, finding_id, disposition="not_applicable")

    summary = client.get("/api/risk/summary").json()
    assert summary["counts_by_severity"]["HIGH"] == 0
    assert summary["top_findings"] == []
    assert summary["environment_score"] == 0
    listed = client.get("/api/findings").json()
    assert [f["finding_id"] for f in listed] == [finding_id]
    assert listed[0]["dismissed"] is True
    assert listed[0]["disposition"] == "not_applicable"
    assert listed[0]["disposition_reason"] == REASON


def test_clearing_the_disposition_opens_the_finding_again(tmp_path):
    client = make_client(tmp_path)
    finding_id = one(client)
    accept(client, finding_id)

    response = client.delete(path(finding_id))

    finding = response.json()
    assert response.status_code == 200
    assert finding["disposition"] == "none"
    assert finding["disposition_reason"] is None
    assert finding["dismissed"] is False
    assert client.get("/api/risk/summary").json()["counts_by_severity"]["HIGH"] == 1


@pytest.mark.parametrize(
    "overrides",
    [
        {"disposition_reason": "too short"},
        {"disposition_reason": "         x         "},
        {"disposition_reason": ""},
        {"disposition": "none"},
        {"disposition": "ignored"},
        {"disposition_until": "2020-01-01"},
        {"disposition_until": "not a date"},
        {"extra": "field"},
    ],
)
def test_a_bad_disposition_is_refused(tmp_path, overrides):
    client = make_client(tmp_path)
    finding_id = one(client)

    response = accept(client, finding_id, **overrides)

    assert response.status_code == 422
    assert client.get(f"/api/findings/{finding_id}").json()["disposition"] == "none"


def test_a_reason_of_exactly_ten_characters_is_accepted(tmp_path):
    client = make_client(tmp_path)
    finding_id = one(client)

    assert accept(client, finding_id, disposition_reason="0123456789").status_code == 200


def test_the_reason_is_required(tmp_path):
    client = make_client(tmp_path)
    finding_id = one(client)

    response = client.patch(path(finding_id), json={"disposition": "accepted"})

    assert response.status_code == 422


def test_a_missing_finding_gives_404(tmp_path):
    client = make_client(tmp_path)

    assert accept(client, "F-nope").status_code == 404
    assert client.delete(path("F-nope")).status_code == 404


def test_only_an_open_finding_can_be_dismissed(tmp_path):
    client = make_client(tmp_path)
    finding_id = one(client)
    load(client, [entry(status="PASS")])

    response = accept(client, finding_id)

    assert response.status_code == 409
    assert "open" in response.json()["detail"]


def test_a_disposition_until_a_future_date_keeps_the_finding_dismissed(tmp_path):
    client = make_client(tmp_path)
    finding_id = one(client)
    tomorrow = (date.today() + timedelta(days=1)).isoformat()

    finding = accept(client, finding_id, disposition_until=tomorrow).json()

    assert finding["dismissed"] is True
    assert finding["disposition_until"].startswith(f"{tomorrow}T23:59:59")


def test_a_date_of_today_is_allowed_and_lasts_until_the_end_of_the_day(tmp_path):
    client = make_client(tmp_path)
    finding_id = one(client)

    finding = accept(client, finding_id, disposition_until=date.today().isoformat()).json()

    assert finding["dismissed"] is True


def test_an_expired_disposition_returns_the_finding_to_open(tmp_path):
    client = make_client(tmp_path)
    finding_id = one(client)
    accept(client, finding_id, disposition_until=(date.today() + timedelta(days=1)).isoformat())
    set_until(client, finding_id, store.utcnow() - timedelta(seconds=5))

    finding = client.get("/api/findings").json()[0]

    assert finding["dismissed"] is False
    assert finding["disposition"] == "none"
    assert finding["disposition_reason"] is None
    assert finding["disposition_until"] is None
    assert client.get("/api/risk/summary").json()["counts_by_severity"]["HIGH"] == 1
    assert client.get(f"/api/findings/{finding_id}").json()["dismissed"] is False


def test_a_dismissed_finding_is_left_out_of_the_environment_score_of_a_scan(tmp_path):
    client = make_client(tmp_path)
    bucket = make_resource(
        "my-bucket",
        "S3",
        "ap-southeast-2",
        "my-bucket",
        {"public_access_block": None, "encryption": None, "versioning": "Enabled", "policy": None},
    )
    result = {"resources": [bucket], "errors": []}

    def scan() -> dict:
        findings = score_findings(run_rules(result["resources"]), result, ["ap-southeast-2"])
        with client.app.state.session_factory() as session:
            created = store.create_scan(session, ["ap-southeast-2"])
            store.save_result(session, created.id, result, findings)
        return client.get(f"/api/scans/{created.id}").json()

    first = scan()
    assert first["environment_score"] > 0
    ours = next(f for f in client.get("/api/findings").json() if f["rule_id"] == "CIS-S3-001")
    finding_id = ours["finding_id"]
    accept(client, finding_id)

    second = scan()

    assert second["environment_score"] < first["environment_score"]
    assert second["severity_counts"].get("HIGH", 0) == 0


# Suggestions


def suggestion(client, uid: str, group="iam") -> dict | None:
    load(client, [entry(check="c", uid=uid, group=group)])
    finding = client.get("/api/findings").json()[0]
    return finding["suggested_not_applicable"]


def test_an_aws_managed_policy_gets_a_suggestion_and_is_not_dismissed(tmp_path):
    client = make_client(tmp_path)

    suggested = suggestion(client, AWS_POLICY)

    assert "AWS-managed" in suggested["reason"]
    finding = client.get("/api/findings").json()[0]
    assert finding["disposition"] == "none"
    assert finding["dismissed"] is False
    assert finding["status"] == "OPEN"


def test_a_service_linked_role_gets_a_suggestion(tmp_path):
    client = make_client(tmp_path)

    assert "service-linked" in suggestion(client, SERVICE_ROLE)["reason"]


def test_a_customer_policy_and_other_resources_get_no_suggestion(tmp_path):
    client = make_client(tmp_path)

    assert suggestion(client, POLICY_ARN) is None


def test_a_name_in_the_own_identities_setting_gets_a_suggestion(tmp_path, monkeypatch):
    monkeypatch.setenv("CLOUDSHIELD_OWN_IDENTITIES", "other-user, cloudshield-scanner")
    client = make_client(tmp_path)

    suggested = suggestion(client, OWN_USER)

    assert "CLOUDSHIELD_OWN_IDENTITIES" in suggested["reason"]


def test_without_the_setting_an_identity_gets_no_suggestion(tmp_path):
    client = make_client(tmp_path)

    assert suggestion(client, OWN_USER) is None


def test_a_dismissed_finding_no_longer_shows_a_suggestion(tmp_path):
    client = make_client(tmp_path)
    suggestion(client, AWS_POLICY)
    finding_id = client.get("/api/findings").json()[0]["finding_id"]

    finding = accept(client, finding_id, disposition="not_applicable").json()

    assert finding["suggested_not_applicable"] is None


def test_the_own_identities_setting_is_in_the_env_example_and_in_config():
    example = (Path(__file__).resolve().parents[1] / ".env.example").read_text(encoding="utf-8")

    assert "CLOUDSHIELD_OWN_IDENTITIES=" in example
    assert Settings().cloudshield_own_identities == ""


def test_the_browser_may_use_patch_and_delete(tmp_path):
    client = make_client(tmp_path)
    headers = {
        "Origin": "http://localhost:5173",
        "Access-Control-Request-Method": "PATCH",
        "Access-Control-Request-Headers": "content-type",
    }

    response = client.options("/api/findings/x/disposition", headers=headers)

    assert "PATCH" in response.headers["access-control-allow-methods"]
    assert "DELETE" in response.headers["access-control-allow-methods"]
