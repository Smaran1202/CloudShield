import httpx

from cloudshield.config import Settings
from cloudshield.fixes.explain import (
    GEMINI_URL,
    TIMEOUT_SECONDS,
    google_error,
    redact,
    response_text,
)

PROMPT = "Reply with the single word: ok"


def check_model(client: httpx.Client, model: str, api_key: str) -> tuple[bool, str]:
    body = {
        "contents": [{"role": "user", "parts": [{"text": PROMPT}]}],
        "generationConfig": {"temperature": 0},
    }
    url = GEMINI_URL.format(model=model)
    try:
        response = client.post(url, headers={"x-goog-api-key": api_key}, json=body)
    except httpx.TransportError as exc:
        return False, f"network error: {type(exc).__name__}: {redact(str(exc))[:200]}"
    if response.status_code != 200:
        status, message = google_error(response)
        label = f"HTTP {response.status_code} {status}".strip()
        return False, f"{label}: {message}"
    reply = response_text(response)
    if reply is None:
        return False, "HTTP 200 but the answer had no text"
    return True, reply.strip()[:80]


def run_ai_check(settings: Settings, transport: httpx.BaseTransport | None = None) -> list[str]:
    """Report lines for `ai-check`. The key itself is never included, only whether it is set."""
    key = settings.gemini_api_key
    lines = [f"GEMINI_API_KEY: set (length {len(key)})" if key else "GEMINI_API_KEY: NOT set"]
    lines.append(f"GEMINI_MODEL: {settings.gemini_model or 'not set'}")
    lines.append(f"GEMINI_FALLBACK_MODEL: {settings.gemini_fallback_model or 'not set'}")

    models = [m for m in (settings.gemini_model, settings.gemini_fallback_model) if m]
    if not key:
        lines.append("No call made. Set GEMINI_API_KEY in this window, then run this again.")
        return lines
    if not models:
        lines.append("No call made. Set GEMINI_MODEL in this window, then run this again.")
        return lines

    with httpx.Client(transport=transport, timeout=TIMEOUT_SECONDS) as client:
        for model in dict.fromkeys(models):
            ok, text = check_model(client, model, key)
            lines.append(f"{model}: ok, reply: {text}" if ok else f"{model}: FAILED, {text}")
    return lines
