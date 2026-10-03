import json

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from cloudshield.api.app import create_app
from cloudshield.db import store
from cloudshield.db.models import Base, FixRow
from cloudshield.db.session import make_engine
from cloudshield.fixes.__main__ import main as export_main
from cloudshield.risk.scoring import score_findings
from cloudshield.rules import run_rules
from cloudshield.scanner.common import make_resource

REGIONS = ["us-east-1", "ap-southeast-2"]
ALL_OFF = {
    "BlockPublicAcls": False,
    "IgnorePublicAcls": False,
    "BlockPublicPolicy": False,
    "RestrictPublicBuckets": False,
}
AES = [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
OPEN_SSH = {
    "IpProtocol": "tcp",
    "FromPort": 22,
    "ToPort": 22,
    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
    "Ipv6Ranges": [],
}
GOOD = {
    "why_it_matters": "Anyone on the internet can try to reach this resource.",
    "what_changes": "The risky setting is changed by the patch.",
    "what_could_break": "Impact depends on the blast radius, which may be unknown.",
    "cited": ["e1"],
}


def bucket(block=ALL_OFF) -> dict:
    attributes = {
        "public_access_block": block,
        "encryption": AES,
        "versioning": "Disabled",
        "policy": None,
    }
    return make_resource("my-bucket", "S3", "us-east-1", "my-bucket", attributes)


def group() -> dict:
    attributes = {"vpc_id": "vpc-1", "inbound": [OPEN_SSH], "outbound": []}
    return make_resource("sg-0abc123", "Security Group", "ap-southeast-2", "web", attributes)


def running_instance() -> dict:
    attributes = {
        "state": "running",
        "security_group_ids": ["sg-0abc123"],
        "has_public_ip": True,
        "instance_profile_arn": None,
    }
    return make_resource("i-1", "EC2", "ap-southeast-2", "i-1", attributes)


def wildcard_policy() -> dict:
    document = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    attached = {"users": [], "roles": ["app"], "groups": []}
    attributes = {"document": document, "attached_to": attached}
    return make_resource("arn:aws:iam::123456789012:policy/p", "IAM Policy", None, "p", attributes)


def reply(explanation: dict) -> httpx.Response:
    text = json.dumps(explanation)
    return httpx.Response(200, json={"candidates": [{"content": {"parts": [{"text": text}]}}]})


def recording_transport(responses=None):
    queue = list(responses or [])
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return queue.pop(0) if queue else reply(GOOD)

    return httpx.MockTransport(handler), requests


def make_client(tmp_path, transport=None) -> TestClient:
    url = f"sqlite:///{tmp_path / 'test.db'}"
    Base.metadata.create_all(make_engine(url))
    return TestClient(create_app(database_url=url, gemini_transport=transport, load_env=False))


def seed(client, resources) -> None:
    result = {"resources": resources, "errors": []}
    findings = score_findings(run_rules(resources), result, REGIONS)
    with client.app.state.session_factory() as session:
        scan = store.create_scan(session, REGIONS)
        store.save_result(session, scan.id, result, findings)


def finding_id(client, rule_id: str) -> str:
    findings = client.get("/api/findings", params={"rule_id": rule_id}).json()
    return findings[0]["finding_id"]


def use_gemini(monkeypatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setenv("GEMINI_MODEL", "model-a")


def test_fix_for_the_open_ssh_group_has_patches_blast_radius_and_a_template_explanation(tmp_path):
    client = make_client(tmp_path)
    seed(client, [group(), running_instance()])
    fid = finding_id(client, "CIS-SG-001")

    response = client.post(f"/api/findings/{fid}/fix")

    fix = response.json()
    assert response.status_code == 200
    assert fix["finding_id"] == fid
    assert [p["format"] for p in fix["patches"]] == ["terraform", "cloudformation", "cli"]
    cli = fix["patches"][2]["content"]
    assert "aws ec2 revoke-security-group-ingress --group-id sg-0abc123" in cli
    assert fix["blast_radius"]["level"] == "medium"
    assert fix["blast_radius"]["factors"][0]["value"] == ["i-1"]
    assert fix["pre_checks"]
    assert "authorize-security-group-ingress" in fix["rollback"]
    assert fix["verify"] == "Rescan (POST /api/scans). This finding should resolve."
    assert fix["generated_by"] == "template"
    assert fix["model"] is None
    assert fix["explanation"]["cited"] == ["e1"]
    assert fix["created_at"].endswith("Z")


def test_fix_for_the_public_bucket_has_three_patches_and_unknown_blast_radius(tmp_path):
    client = make_client(tmp_path)
    seed(client, [bucket()])
    fid = finding_id(client, "CIS-S3-001")

    fix = client.post(f"/api/findings/{fid}/fix").json()

    assert [p["format"] for p in fix["patches"]] == ["terraform", "cloudformation", "cli"]
    assert fix["blast_radius"]["level"] == "unknown"
    assert "BlockPublicAcls=true" in fix["patches"][2]["content"]


def test_fix_for_an_iam_finding_is_guidance_only(tmp_path):
    client = make_client(tmp_path)
    seed(client, [wildcard_policy()])
    fid = finding_id(client, "CIS-IAM-001")

    fix = client.post(f"/api/findings/{fid}/fix").json()

    assert fix["patches"] == []
    assert len(fix["guidance"]) >= 3
    assert fix["blast_radius"]["level"] == "high"


def test_fix_for_kms_finding_marks_the_patch_as_needing_input(tmp_path):
    client = make_client(tmp_path)
    seed(client, [bucket()])
    fid = finding_id(client, "CIS-S3-002")

    fix = client.post(f"/api/findings/{fid}/fix").json()

    assert all(patch["needs_input"] for patch in fix["patches"])
    assert "REPLACE_WITH_YOUR_KMS_KEY_ARN" in fix["patches"][0]["content"]


def test_no_api_key_means_no_gemini_call(tmp_path):
    transport, requests = recording_transport()
    client = make_client(tmp_path, transport)
    seed(client, [bucket()])

    client.post(f"/api/findings/{finding_id(client, 'CIS-S3-001')}/fix")

    assert requests == []


def test_with_a_key_the_explanation_comes_from_gemini(tmp_path, monkeypatch):
    use_gemini(monkeypatch)
    transport, requests = recording_transport()
    client = make_client(tmp_path, transport)
    seed(client, [bucket()])

    fix = client.post(f"/api/findings/{finding_id(client, 'CIS-S3-001')}/fix").json()

    assert fix["generated_by"] == "gemini"
    assert fix["model"] == "model-a"
    assert fix["explanation"] == {**GOOD, "skipped_reason": None}
    assert fix["generation_ms"] >= 0
    assert len(requests) == 1


def test_a_rejected_gemini_answer_is_stored_as_a_template_explanation(tmp_path, monkeypatch):
    use_gemini(monkeypatch)
    transport, requests = recording_transport([reply({**GOOD, "cited": ["e99"]})])
    client = make_client(tmp_path, transport)
    seed(client, [bucket()])

    fix = client.post(f"/api/findings/{finding_id(client, 'CIS-S3-001')}/fix").json()

    assert fix["generated_by"] == "template"
    assert fix["model"] is None


def test_stored_fix_is_reused_while_the_evidence_is_unchanged(tmp_path, monkeypatch):
    use_gemini(monkeypatch)
    transport, requests = recording_transport()
    client = make_client(tmp_path, transport)
    seed(client, [bucket()])
    fid = finding_id(client, "CIS-S3-001")
    first = client.post(f"/api/findings/{fid}/fix").json()

    second = client.post(f"/api/findings/{fid}/fix").json()

    assert second == first
    assert len(requests) == 1


def test_a_rescan_with_the_same_evidence_still_reuses_the_stored_fix(tmp_path, monkeypatch):
    use_gemini(monkeypatch)
    transport, requests = recording_transport()
    client = make_client(tmp_path, transport)
    seed(client, [bucket()])
    fid = finding_id(client, "CIS-S3-001")
    first = client.post(f"/api/findings/{fid}/fix").json()
    seed(client, [bucket()])

    second = client.post(f"/api/findings/{fid}/fix").json()

    assert second["evidence_hash"] == first["evidence_hash"]
    assert len(requests) == 1


def test_changed_evidence_regenerates_the_fix(tmp_path, monkeypatch):
    use_gemini(monkeypatch)
    transport, requests = recording_transport()
    client = make_client(tmp_path, transport)
    seed(client, [bucket()])
    fid = finding_id(client, "CIS-S3-001")
    first = client.post(f"/api/findings/{fid}/fix").json()
    partly_fixed = {**ALL_OFF, "BlockPublicAcls": True}
    seed(client, [bucket(partly_fixed)])

    second = client.post(f"/api/findings/{fid}/fix").json()

    assert second["evidence_hash"] != first["evidence_hash"]
    assert "BlockPublicAcls=false" in first["rollback"]
    assert "BlockPublicAcls=true" in second["rollback"]
    assert len(requests) == 2


def test_refresh_regenerates_even_when_nothing_changed(tmp_path, monkeypatch):
    use_gemini(monkeypatch)
    transport, requests = recording_transport()
    client = make_client(tmp_path, transport)
    seed(client, [bucket()])
    fid = finding_id(client, "CIS-S3-001")
    first = client.post(f"/api/findings/{fid}/fix").json()

    second = client.post(f"/api/findings/{fid}/fix", params={"refresh": "true"}).json()

    assert second["evidence_hash"] == first["evidence_hash"]
    assert len(requests) == 2


def test_get_returns_the_stored_fix_or_404(tmp_path):
    client = make_client(tmp_path)
    seed(client, [bucket()])
    fid = finding_id(client, "CIS-S3-001")

    before = client.get(f"/api/findings/{fid}/fix")
    created = client.post(f"/api/findings/{fid}/fix").json()
    after = client.get(f"/api/findings/{fid}/fix")

    assert before.status_code == 404
    assert after.status_code == 200
    assert after.json() == created


def test_unknown_finding_is_404_for_both_methods(tmp_path):
    client = make_client(tmp_path)

    assert client.post("/api/findings/F-NOPE-00000000/fix").status_code == 404
    assert client.get("/api/findings/F-NOPE-00000000/fix").status_code == 404


def test_resolved_finding_without_a_stored_fix_is_409(tmp_path):
    client = make_client(tmp_path)
    seed(client, [bucket()])
    fid = finding_id(client, "CIS-S3-003")
    seed(client, [])

    response = client.post(f"/api/findings/{fid}/fix")

    assert client.get(f"/api/findings/{fid}").json()["status"] == "RESOLVED"
    assert response.status_code == 409


def test_resolved_finding_with_a_stored_fix_returns_it(tmp_path):
    client = make_client(tmp_path)
    seed(client, [bucket()])
    fid = finding_id(client, "CIS-S3-003")
    stored = client.post(f"/api/findings/{fid}/fix").json()
    seed(client, [])

    response = client.post(f"/api/findings/{fid}/fix")

    assert response.status_code == 200
    assert response.json() == stored


def test_hourly_limit_from_the_environment_gives_templates_beyond_it(tmp_path, monkeypatch):
    use_gemini(monkeypatch)
    monkeypatch.setenv("AI_MAX_CALLS_PER_HOUR", "1")
    transport, requests = recording_transport()
    client = make_client(tmp_path, transport)
    seed(client, [bucket()])

    first = client.post(f"/api/findings/{finding_id(client, 'CIS-S3-001')}/fix").json()
    second = client.post(f"/api/findings/{finding_id(client, 'CIS-S3-003')}/fix").json()

    assert first["generated_by"] == "gemini"
    assert second["generated_by"] == "template"
    assert len(requests) == 1


def test_export_writes_the_patch_files_with_a_review_header(tmp_path, monkeypatch, capsys):
    client = make_client(tmp_path)
    seed(client, [group(), running_instance()])
    fid = finding_id(client, "CIS-SG-001")
    client.post(f"/api/findings/{fid}/fix")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")
    out = tmp_path / "fixes-out"

    exit_code = export_main(["export", fid, "--dir", str(out)], load_env=False)

    script = (out / "fix.ps1").read_text(encoding="utf-8")
    terraform = (out / "fix.tf").read_text(encoding="utf-8")
    assert exit_code == 0
    assert sorted(p.name for p in out.iterdir()) == [
        "fix.ps1",
        "fix.tf",
        "fix.yaml",
        "sg-0abc123-rule1.json",
    ]
    assert "Review this file before you use it" in script
    assert f"finding {fid}" in script
    assert "aws ec2 revoke-security-group-ingress --group-id sg-0abc123" in script
    assert all(line.startswith("#") for line in terraform.splitlines() if line.strip())
    rule_file = (out / "sg-0abc123-rule1.json").read_text(encoding="utf-8")
    assert json.loads(rule_file)[0]["FromPort"] == 22
    assert "Nothing has been run" in capsys.readouterr().out


def test_export_writes_the_placeholder_json_for_the_kms_fix(tmp_path, monkeypatch):
    client = make_client(tmp_path)
    seed(client, [bucket()])
    fid = finding_id(client, "CIS-S3-002")
    client.post(f"/api/findings/{fid}/fix")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")
    out = tmp_path / "fixes-out"

    export_main(["export", fid, "--dir", str(out)], load_env=False)

    assert (out / "sse-kms-my-bucket.json").exists()
    assert "REPLACE_WITH_YOUR_KMS_KEY_ARN" in (out / "fix.tf").read_text(encoding="utf-8")
    assert not (out / "fix.yaml").exists()


def test_export_without_a_stored_fix_explains_what_to_do(tmp_path, monkeypatch):
    make_client(tmp_path)
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")

    with pytest.raises(SystemExit) as error:
        export_main(["export", "F-NOPE-00000000", "--dir", str(tmp_path / "out")], load_env=False)

    assert "POST /api/findings/F-NOPE-00000000/fix" in str(error.value)
    assert not (tmp_path / "out").exists()


def test_export_for_a_guidance_only_finding_writes_no_files(tmp_path, monkeypatch, capsys):
    client = make_client(tmp_path)
    seed(client, [wildcard_policy()])
    fid = finding_id(client, "CIS-IAM-001")
    client.post(f"/api/findings/{fid}/fix")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")

    export_main(["export", fid, "--dir", str(tmp_path / "out")], load_env=False)

    assert "no patch files" in capsys.readouterr().out


def test_fixes_are_stored_with_account_id_local(tmp_path):
    client = make_client(tmp_path)
    seed(client, [bucket()])
    client.post(f"/api/findings/{finding_id(client, 'CIS-S3-001')}/fix")

    with client.app.state.session_factory() as session:
        rows = list(session.scalars(select(FixRow)))

    assert [row.account_id for row in rows] == ["local"]


def test_the_response_says_why_gemini_was_skipped(tmp_path):
    client = make_client(tmp_path)
    seed(client, [bucket()])

    fix = client.post(f"/api/findings/{finding_id(client, 'CIS-S3-001')}/fix").json()

    assert fix["explanation"]["skipped_reason"] == "no GEMINI_API_KEY in this process"


def test_a_template_made_without_a_key_is_replaced_once_gemini_is_configured(tmp_path, monkeypatch):
    first_client = make_client(tmp_path)
    seed(first_client, [bucket()])
    fid = finding_id(first_client, "CIS-S3-001")
    before = first_client.post(f"/api/findings/{fid}/fix").json()
    use_gemini(monkeypatch)
    transport, requests = recording_transport()
    second_client = make_client(tmp_path, transport)

    after = second_client.post(f"/api/findings/{fid}/fix").json()

    assert before["generated_by"] == "template"
    assert after["generated_by"] == "gemini"
    assert after["explanation"]["skipped_reason"] is None
    assert len(requests) == 1


def test_a_template_made_after_gemini_failed_is_not_retried_on_every_request(tmp_path, monkeypatch):
    monkeypatch.setattr("cloudshield.fixes.explain.sleep", lambda seconds: None)
    use_gemini(monkeypatch)
    transport, requests = recording_transport([httpx.Response(503)] * 3)
    client = make_client(tmp_path, transport)
    seed(client, [bucket()])
    fid = finding_id(client, "CIS-S3-001")
    first = client.post(f"/api/findings/{fid}/fix").json()

    second = client.post(f"/api/findings/{fid}/fix").json()

    assert first["explanation"]["skipped_reason"].startswith("all Gemini attempts failed")
    assert second == first
    assert len(requests) == 3


def test_export_header_says_why_gemini_was_skipped(tmp_path, monkeypatch):
    client = make_client(tmp_path)
    seed(client, [group(), running_instance()])
    fid = finding_id(client, "CIS-SG-001")
    client.post(f"/api/findings/{fid}/fix")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")
    out = tmp_path / "fixes-out"

    export_main(["export", fid, "--dir", str(out)], load_env=False)

    for name in ("fix.ps1", "fix.tf", "fix.yaml"):
        header = (out / name).read_text(encoding="utf-8").splitlines()[:4]
        reason = "no GEMINI_API_KEY in this process"
        assert f"# Explanation: template text. Gemini was not used: {reason}" in header


def test_export_header_names_the_model_when_gemini_wrote_the_explanation(tmp_path, monkeypatch):
    use_gemini(monkeypatch)
    transport, requests = recording_transport()
    client = make_client(tmp_path, transport)
    seed(client, [group(), running_instance()])
    fid = finding_id(client, "CIS-SG-001")
    client.post(f"/api/findings/{fid}/fix")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")
    out = tmp_path / "fixes-out"

    export_main(["export", fid, "--dir", str(out)], load_env=False)

    assert "# Explanation: written by model-a" in (out / "fix.ps1").read_text(encoding="utf-8")
