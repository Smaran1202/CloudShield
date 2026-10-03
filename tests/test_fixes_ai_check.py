import httpx

from cloudshield.config import Settings
from cloudshield.fixes import __main__ as fixes_main
from cloudshield.fixes.ai_check import run_ai_check


def settings(key="secret-key-12345", model="model-a", fallback="model-b") -> Settings:
    return Settings(gemini_api_key=key, gemini_model=model, gemini_fallback_model=fallback)


def ok_reply(text="ok") -> httpx.Response:
    return httpx.Response(200, json={"candidates": [{"content": {"parts": [{"text": text}]}}]})


def failure(status: int, google_status: str, message: str) -> httpx.Response:
    body = {"error": {"code": status, "message": message, "status": google_status}}
    return httpx.Response(status, json=body)


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


def test_without_a_key_it_says_so_and_makes_no_call():
    transport, requests = transport_returning()

    lines = run_ai_check(settings(key=None), transport)

    assert lines[0] == "GEMINI_API_KEY: NOT set"
    assert "No call made" in lines[-1]
    assert requests == []


def test_without_a_model_it_says_so_and_makes_no_call():
    transport, requests = transport_returning()

    lines = run_ai_check(settings(model=None, fallback=None), transport)

    assert "GEMINI_MODEL: not set" in lines
    assert "GEMINI_FALLBACK_MODEL: not set" in lines
    assert "No call made" in lines[-1]
    assert requests == []


def test_it_reports_the_key_length_but_never_the_key():
    transport, requests = transport_returning(ok_reply(), ok_reply())

    lines = run_ai_check(settings(), transport)

    assert lines[0] == "GEMINI_API_KEY: set (length 16)"
    assert "secret-key-12345" not in "\n".join(lines)


def test_it_makes_one_small_call_to_each_model_and_prints_the_reply():
    transport, requests = transport_returning(ok_reply("ok"), ok_reply("OK."))

    lines = run_ai_check(settings(), transport)

    assert [r.url.path for r in requests] == [
        "/v1beta/models/model-a:generateContent",
        "/v1beta/models/model-b:generateContent",
    ]
    assert requests[0].headers["x-goog-api-key"] == "secret-key-12345"
    assert "GEMINI_MODEL: model-a" in lines
    assert "GEMINI_FALLBACK_MODEL: model-b" in lines
    assert lines[-2:] == ["model-a: ok, reply: ok", "model-b: ok, reply: OK."]


def test_it_prints_the_http_status_and_googles_message_for_a_failure():
    missing = failure(404, "NOT_FOUND", "models/model-a is not found for API version v1beta")
    transport, requests = transport_returning(missing, ok_reply())

    lines = run_ai_check(settings(), transport)

    assert lines[-2] == (
        "model-a: FAILED, HTTP 404 NOT_FOUND: models/model-a is not found for API version v1beta"
    )
    assert lines[-1] == "model-b: ok, reply: ok"


def test_it_does_not_retry_and_a_failure_on_one_model_does_not_stop_the_other():
    transport, requests = transport_returning(failure(503, "UNAVAILABLE", "busy"), ok_reply())

    lines = run_ai_check(settings(), transport)

    assert len(requests) == 2
    assert "model-a: FAILED, HTTP 503 UNAVAILABLE: busy" in lines


def test_a_network_error_is_reported_with_its_type():
    transport, requests = transport_returning(httpx.ConnectError("no route"), ok_reply())

    lines = run_ai_check(settings(), transport)

    assert lines[-2] == "model-a: FAILED, network error: ConnectError: no route"


def test_an_ok_status_without_text_is_a_failure():
    transport, requests = transport_returning(httpx.Response(200, json={"candidates": []}))

    lines = run_ai_check(settings(fallback=None), transport)

    assert lines[-1] == "model-a: FAILED, HTTP 200 but the answer had no text"


def test_the_same_model_twice_is_checked_once():
    transport, requests = transport_returning(ok_reply())

    run_ai_check(settings(fallback="model-a"), transport)

    assert len(requests) == 1


def test_secrets_in_googles_message_are_redacted():
    message = "Key AKIAIOSFODNN7EXAMPLE rejected for 123456789012"
    transport, requests = transport_returning(failure(403, "PERMISSION_DENIED", message))

    lines = run_ai_check(settings(fallback=None), transport)

    assert "AKIAIOSFODNN7EXAMPLE" not in lines[-1]
    assert "123456789012" not in lines[-1]


def test_the_command_prints_the_report_and_exits_non_zero_on_failure(monkeypatch, capsys):
    monkeypatch.setenv("GEMINI_API_KEY", "secret-key-12345")
    monkeypatch.setenv("GEMINI_MODEL", "model-a")
    transport, requests = transport_returning(failure(401, "UNAUTHENTICATED", "bad key"))
    monkeypatch.setattr(fixes_main, "run_ai_check", lambda c: run_ai_check(c, transport))

    exit_code = fixes_main.main(["ai-check"], load_env=False)

    output = capsys.readouterr().out
    assert exit_code == 1
    assert "GEMINI_API_KEY: set (length 16)" in output
    assert "model-a: FAILED, HTTP 401 UNAUTHENTICATED: bad key" in output
    assert "secret-key-12345" not in output


def test_the_command_exits_zero_when_every_model_answers(monkeypatch, capsys):
    monkeypatch.setenv("GEMINI_API_KEY", "secret-key-12345")
    monkeypatch.setenv("GEMINI_MODEL", "model-a")
    transport, requests = transport_returning(ok_reply())
    monkeypatch.setattr(fixes_main, "run_ai_check", lambda c: run_ai_check(c, transport))

    exit_code = fixes_main.main(["ai-check"], load_env=False)

    assert exit_code == 0
    assert "model-a: ok, reply: ok" in capsys.readouterr().out
