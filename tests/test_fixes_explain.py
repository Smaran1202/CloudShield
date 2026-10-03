import json
import logging

import httpx
import pytest

from cloudshield.config import Settings
from cloudshield.fixes import explain
from cloudshield.fixes.blast import blast_radius
from cloudshield.fixes.explain import (
    HourlyLimit,
    build_payload,
    explain_fix,
    load_knowledge,
    redact,
    template_explanation,
)
from cloudshield.fixes.templates import build_fix
from cloudshield.rules.evidence import build_evidence

GOOD = {
    "why_it_matters": "Anyone on the internet can try to reach the SSH port of this group.",
    "what_changes": "The open rule is removed from the group.",
    "what_could_break": "People who connect through the rule lose access. Who connects is unknown.",
    "cited": ["e1"],
}


def settings(key="test-key", model="model-a", fallback=None) -> Settings:
    return Settings(
        gemini_api_key=key,
        gemini_model=model,
        gemini_fallback_model=fallback,
        ai_max_calls_per_hour=30,
    )


def context() -> dict:
    resource = {
        "resource_id": "sg-0abc123",
        "resource_type": "Security Group",
        "region": "ap-southeast-2",
        "attributes": {},
    }
    rule = {
        "exposes": "SSH (port 22)",
        "protocol": "tcp",
        "from_port": 22,
        "to_port": 22,
        "cidrs": ["0.0.0.0/0"],
    }
    details = {"rules": [rule]}
    finding = {
        "finding_id": "F-1",
        "rule_id": "CIS-SG-001",
        "resource_id": "sg-0abc123",
        "resource_type": "Security Group",
        "title": "Security group allows SSH or all traffic from the internet",
        "severity": "HIGH",
        "details": details,
        "evidence": build_evidence("CIS-SG-001", details, "Security Group"),
    }
    parts = build_fix(finding, resource)
    return {
        "finding": finding,
        "knowledge": load_knowledge("CIS-SG-001"),
        "blast_radius": blast_radius(finding, resource, []),
        "patches": parts["patches"],
        "guidance": parts["guidance"],
    }


def without_reason(explanation: dict) -> dict:
    return {k: v for k, v in explanation.items() if k != "skipped_reason"}


def reply(explanation: dict) -> httpx.Response:
    text = json.dumps(explanation)
    return httpx.Response(200, json={"candidates": [{"content": {"parts": [{"text": text}]}}]})


def transport_returning(*responses):
    queue = list(responses)
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        item = queue.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    return httpx.MockTransport(handler), requests


def run(transport, config=None, limit=None) -> dict:
    return explain_fix(context(), config or settings(), limit or HourlyLimit(30), transport)


@pytest.fixture
def sleeps(monkeypatch) -> list[float]:
    recorded = []
    monkeypatch.setattr(explain, "sleep", recorded.append)
    return recorded


def test_success_returns_the_model_text_and_names_the_model(sleeps):
    transport, requests = transport_returning(reply(GOOD))

    result = run(transport)

    assert result == {
        "explanation": {**GOOD, "skipped_reason": None},
        "generated_by": "gemini",
        "model": "model-a",
    }
    assert len(requests) == 1
    assert sleeps == []


def test_request_uses_the_configured_model_a_header_key_and_a_json_schema(sleeps):
    transport, requests = transport_returning(reply(GOOD))

    run(transport)

    request = requests[0]
    body = json.loads(request.content)
    assert request.url.path == "/v1beta/models/model-a:generateContent"
    assert request.headers["x-goog-api-key"] == "test-key"
    assert "test-key" not in str(request.url)
    config = body["generationConfig"]
    assert config["responseMimeType"] == "application/json"
    assert config["responseSchema"]["required"] == [
        "why_it_matters",
        "what_changes",
        "what_could_break",
        "cited",
    ]
    assert "do not write code" in body["systemInstruction"]["parts"][0]["text"].lower()


def test_prompt_has_the_knowledge_evidence_ids_blast_radius_and_patch_text(sleeps):
    transport, requests = transport_returning(reply(GOOD))

    run(transport)

    prompt = json.loads(requests[0].content)["contents"][0]["parts"][0]["text"]
    assert "Security group allows SSH or all traffic from the internet" in prompt
    assert '"id": "e1"' in prompt
    assert '"blast_radius"' in prompt
    assert "aws ec2 revoke-security-group-ingress --group-id sg-0abc123" in prompt
    assert "What the rule checks" in prompt


def test_payload_contains_only_the_allowed_sections():
    assert set(build_payload(context())) == {
        "finding",
        "evidence",
        "blast_radius",
        "patches",
        "guidance",
    }


def test_503_then_success_retries_with_backoff(sleeps):
    transport, requests = transport_returning(httpx.Response(503), reply(GOOD))

    result = run(transport)

    assert result["generated_by"] == "gemini"
    assert len(requests) == 2
    assert sleeps == [1.0]


def test_all_temporary_statuses_are_retried(sleeps):
    for status in (429, 500, 502, 503, 504):
        transport, requests = transport_returning(httpx.Response(status), reply(GOOD))

        result = run(transport)

        assert result["generated_by"] == "gemini", status
        assert len(requests) == 2, status


def test_timeout_then_success_is_retried(sleeps):
    timeout = httpx.ReadTimeout("slow")
    transport, requests = transport_returning(timeout, reply(GOOD))

    result = run(transport)

    assert result["generated_by"] == "gemini"
    assert len(requests) == 2


def test_503_exhausted_then_one_attempt_on_the_fallback_model(sleeps):
    failing = [httpx.Response(503)] * 3
    transport, requests = transport_returning(*failing, reply(GOOD))

    result = run(transport, settings(fallback="model-b"))

    paths = [r.url.path for r in requests]
    assert paths == [
        "/v1beta/models/model-a:generateContent",
        "/v1beta/models/model-a:generateContent",
        "/v1beta/models/model-a:generateContent",
        "/v1beta/models/model-b:generateContent",
    ]
    assert result["model"] == "model-b"
    assert result["generated_by"] == "gemini"
    assert sleeps == [1.0, 2.0]


def test_fallback_model_gets_only_one_attempt(sleeps):
    transport, requests = transport_returning(*[httpx.Response(503)] * 4)

    result = run(transport, settings(fallback="model-b"))

    assert len(requests) == 4
    assert result["generated_by"] == "template"
    assert result["model"] is None


def test_both_models_failing_gives_the_template(sleeps):
    transport, requests = transport_returning(*[httpx.Response(503)] * 4)

    result = run(transport, settings(fallback="model-b"))

    assert result["generated_by"] == "template"
    assert without_reason(result["explanation"]) == template_explanation(context())


@pytest.mark.parametrize("status", [400, 401, 403, 404])
def test_client_errors_are_not_retried(status, sleeps):
    transport, requests = transport_returning(httpx.Response(status))

    result = run(transport)

    assert len(requests) == 1
    assert sleeps == []
    assert result["generated_by"] == "template"


def test_no_api_key_means_no_network_call(sleeps):
    transport, requests = transport_returning()

    result = run(transport, settings(key=None))

    assert requests == []
    assert result["generated_by"] == "template"
    assert result["model"] is None


def test_no_model_name_means_no_network_call(sleeps):
    transport, requests = transport_returning()

    result = run(transport, settings(model=None))

    assert requests == []
    assert result["generated_by"] == "template"


def test_calls_beyond_the_hourly_limit_get_the_template(sleeps):
    transport, requests = transport_returning(reply(GOOD), reply(GOOD))
    limit = HourlyLimit(1)

    first = run(transport, limit=limit)
    second = run(transport, limit=limit)

    assert first["generated_by"] == "gemini"
    assert second["generated_by"] == "template"
    assert len(requests) == 1


def test_hourly_limit_frees_up_after_an_hour():
    now = [0.0]
    limit = HourlyLimit(2, clock=lambda: now[0])

    assert [limit.allow(), limit.allow(), limit.allow()] == [True, True, False]
    now[0] = 3601.0

    assert limit.allow() is True


def test_redaction_replaces_account_ids_keys_and_secrets():
    text = (
        "arn:aws:iam::123456789012:policy/p key AKIAIOSFODNN7EXAMPLE "
        "secret wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY "
        "aws_secret_access_key = abc123 port 22"
    )

    cleaned = redact(text)

    assert "123456789012" not in cleaned
    assert "AKIAIOSFODNN7EXAMPLE" not in cleaned
    assert "wJalrXUtnFEMI" not in cleaned
    assert "abc123" not in cleaned
    assert "<ACCOUNT_ID>" in cleaned
    assert "<AWS_ACCESS_KEY_ID>" in cleaned
    assert "port 22" in cleaned


def test_redaction_is_applied_to_what_is_sent(sleeps):
    data = context()
    data["finding"]["resource_id"] = "arn:aws:iam::123456789012:policy/p"
    transport, requests = transport_returning(reply(GOOD))

    explain_fix(data, settings(), HourlyLimit(30), transport)

    prompt = json.loads(requests[0].content)["contents"][0]["parts"][0]["text"]
    assert "123456789012" not in prompt
    assert "arn:aws:iam::<ACCOUNT_ID>:policy/p" in prompt


@pytest.mark.parametrize(
    "bad_text",
    [
        "Security group sg-0123456789abcdef0 is the problem.",
        "The rule also allows 10.9.8.7/24 to connect.",
        "It also exposes port 3389 to the internet.",
        "The group arn:aws:ec2:us-east-1:<ACCOUNT_ID>:security-group/sg-9 is affected.",
        "Account 123456789012 owns this.",
        "Run `aws ec2 revoke-security-group-ingress` to fix it.",
    ],
)
def test_guard_rejects_invented_identifiers_and_code(bad_text, sleeps):
    transport, requests = transport_returning(reply({**GOOD, "why_it_matters": bad_text}))

    result = run(transport)

    assert result["generated_by"] == "template"
    assert without_reason(result["explanation"]) == template_explanation(context())
    assert len(requests) == 1


def test_guard_rejects_an_invented_resource_id_in_any_text_field(sleeps):
    bad = {**GOOD, "what_could_break": "It could break i-0123456789abcdef0."}
    transport, requests = transport_returning(reply(bad))

    assert run(transport)["generated_by"] == "template"


def test_guard_rejects_a_cited_id_that_does_not_exist(sleeps):
    transport, requests = transport_returning(reply({**GOOD, "cited": ["e1", "e9"]}))

    result = run(transport)

    assert result["generated_by"] == "template"


def test_guard_accepts_identifiers_that_are_in_the_data(sleeps):
    fine = {**GOOD, "why_it_matters": "Group sg-0abc123 allows 0.0.0.0/0 on port 22."}
    transport, requests = transport_returning(reply(fine))

    result = run(transport)

    assert result["generated_by"] == "gemini"
    assert result["explanation"]["why_it_matters"] == fine["why_it_matters"]


def test_guard_rejection_does_not_try_the_fallback_model(sleeps):
    bad = {**GOOD, "cited": ["e9"]}
    transport, requests = transport_returning(reply(bad), reply(GOOD))

    result = run(transport, settings(fallback="model-b"))

    assert result["generated_by"] == "template"
    assert len(requests) == 1


@pytest.mark.parametrize(
    "text",
    ["not json", "[]", json.dumps({"why_it_matters": "x"}), json.dumps({**GOOD, "cited": "e1"})],
)
def test_malformed_model_output_gives_the_template(text, sleeps):
    body = {"candidates": [{"content": {"parts": [{"text": text}]}}]}
    transport, requests = transport_returning(httpx.Response(200, json=body))

    assert run(transport)["generated_by"] == "template"


def test_response_without_candidates_falls_back_to_the_template(sleeps):
    transport, requests = transport_returning(httpx.Response(200, json={"candidates": []}))

    assert run(transport)["generated_by"] == "template"


def test_template_explanation_uses_only_known_facts():
    result = template_explanation(context())

    assert "sg-0abc123" in result["why_it_matters"]
    assert "terraform, cloudformation, cli" in result["what_changes"]
    assert result["what_could_break"].startswith("Blast radius: unknown.")
    assert result["cited"] == ["e1"]


def test_every_rule_has_a_knowledge_document_without_external_ids():
    for rule_id in (
        "CIS-S3-001",
        "CIS-S3-002",
        "CIS-S3-003",
        "CIS-SG-001",
        "CIS-IAM-001",
        "SX-IAM-PRIVESC-001",
    ):
        text = load_knowledge(rule_id)

        assert len(text) > 400, rule_id
        assert "MITRE" not in text and "ATT&CK" not in text
        assert not any(token.startswith("T1") and token[1:5].isdigit() for token in text.split())


def google_failure(status: int, google_status: str, message: str) -> httpx.Response:
    body = {"error": {"code": status, "message": message, "status": google_status}}
    return httpx.Response(status, json=body)


def warnings_from(caplog) -> list[str]:
    records = [r for r in caplog.records if r.name == "cloudshield.fixes.explain"]
    return [r.getMessage() for r in records if r.levelno == logging.WARNING]


def test_no_api_key_gives_a_skipped_reason_and_one_warning(caplog, sleeps):
    transport, requests = transport_returning()

    with caplog.at_level(logging.WARNING):
        result = run(transport, settings(key=None))

    assert result["explanation"]["skipped_reason"] == "no GEMINI_API_KEY in this process"
    assert warnings_from(caplog) == ["Gemini was not used: no GEMINI_API_KEY in this process"]


def test_no_model_name_gives_a_skipped_reason(caplog, sleeps):
    transport, requests = transport_returning()

    with caplog.at_level(logging.WARNING):
        result = run(transport, settings(model=None))

    assert result["explanation"]["skipped_reason"] == "no GEMINI_MODEL set"
    assert warnings_from(caplog) == ["Gemini was not used: no GEMINI_MODEL set"]


def test_hourly_limit_gives_a_skipped_reason(caplog, sleeps):
    transport, requests = transport_returning(reply(GOOD))
    limit = HourlyLimit(1)
    run(transport, limit=limit)

    with caplog.at_level(logging.WARNING):
        result = run(transport, limit=limit)

    assert result["explanation"]["skipped_reason"] == "hourly AI call limit reached"
    assert warnings_from(caplog) == ["Gemini was not used: hourly AI call limit reached"]


def test_rejected_answer_names_the_check_that_failed(caplog, sleeps):
    transport, requests = transport_returning(reply({**GOOD, "cited": ["e9"]}))

    with caplog.at_level(logging.WARNING):
        result = run(transport)

    reason = result["explanation"]["skipped_reason"]
    assert reason.startswith("answer rejected: cites evidence that does not exist")
    assert warnings_from(caplog) == [f"Gemini was not used: {reason}"]


def test_answer_that_is_not_json_is_a_rejection_with_a_reason(sleeps):
    body = {"candidates": [{"content": {"parts": [{"text": "not json"}]}}]}
    transport, requests = transport_returning(httpx.Response(200, json=body))

    result = run(transport)

    assert result["explanation"]["skipped_reason"] == "answer rejected: not the expected JSON"


def test_all_attempts_failing_gives_a_reason_with_the_last_failure(sleeps):
    transport, requests = transport_returning(*[httpx.Response(503)] * 3)

    result = run(transport)

    reason = result["explanation"]["skipped_reason"]
    assert reason == "all Gemini attempts failed (last: HTTP 503 on model-a); see the server log"


def test_success_has_no_skipped_reason(sleeps):
    transport, requests = transport_returning(reply(GOOD))

    assert run(transport)["explanation"]["skipped_reason"] is None


def test_each_failed_attempt_logs_attempt_model_status_and_googles_message(caplog, sleeps):
    overloaded = google_failure(503, "UNAVAILABLE", "The model is overloaded.")
    transport, requests = transport_returning(overloaded, overloaded, reply(GOOD))

    with caplog.at_level(logging.WARNING):
        run(transport)

    assert warnings_from(caplog) == [
        "Gemini attempt 1 of 3 on model-a failed: HTTP 503 UNAVAILABLE: The model is overloaded.",
        "Gemini attempt 2 of 3 on model-a failed: HTTP 503 UNAVAILABLE: The model is overloaded.",
    ]


def test_a_client_error_logs_googles_status_and_message(caplog, sleeps):
    message = "API key not valid. Please pass a valid API key."
    bad_key = google_failure(400, "INVALID_ARGUMENT", message)
    transport, requests = transport_returning(bad_key)

    with caplog.at_level(logging.WARNING):
        run(transport)

    assert warnings_from(caplog)[0] == (
        "Gemini attempt 1 of 3 on model-a failed: "
        "HTTP 400 INVALID_ARGUMENT: API key not valid. Please pass a valid API key."
    )


def test_a_timeout_logs_the_attempt_and_the_error_type(caplog, sleeps):
    transport, requests = transport_returning(httpx.ReadTimeout("slow"), reply(GOOD))

    with caplog.at_level(logging.WARNING):
        run(transport)

    assert warnings_from(caplog) == ["Gemini attempt 1 of 3 on model-a failed: ReadTimeout"]


def test_an_error_body_that_is_not_json_is_logged_as_text(caplog, sleeps):
    transport, requests = transport_returning(httpx.Response(404, text="model not found"))

    with caplog.at_level(logging.WARNING):
        run(transport)

    assert warnings_from(caplog)[0].endswith("failed: HTTP 404 : model not found")


def test_logs_never_contain_the_key_or_headers(caplog, sleeps):
    message = "Bad request. Used key AKIAIOSFODNN7EXAMPLE and 123456789012."
    transport, requests = transport_returning(google_failure(400, "INVALID_ARGUMENT", message))

    with caplog.at_level(logging.DEBUG):
        run(transport, settings(key="super-secret-test-key"))

    everything = " ".join(r.getMessage() for r in caplog.records)
    assert "super-secret-test-key" not in everything
    assert "x-goog-api-key" not in everything.lower()
    assert "AKIAIOSFODNN7EXAMPLE" not in everything
    assert "123456789012" not in everything


def test_the_skipped_reason_carries_googles_message_for_a_failed_call(sleeps):
    message = "Invalid JSON payload received."
    transport, requests = transport_returning(google_failure(400, "INVALID_ARGUMENT", message))

    result = run(transport)

    assert result["explanation"]["skipped_reason"] == (
        "all Gemini attempts failed "
        "(last: HTTP 400 INVALID_ARGUMENT: Invalid JSON payload received. on model-a); "
        "see the server log"
    )
