import json
import logging
import re
import threading
import time
from collections import deque
from importlib.resources import files
from time import sleep

import httpx

from cloudshield.config import Settings

logger = logging.getLogger(__name__)

GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
RETRY_STATUSES = {429, 500, 502, 503, 504}
PRIMARY_ATTEMPTS = 3
BACKOFF_SECONDS = 1.0
TIMEOUT_SECONDS = 30.0

SYSTEM_INSTRUCTION = (
    "You explain one cloud security fix to an engineer. Use only the facts in the data you are "
    "given. Do not write code, commands or configuration. Do not mention any resource id, ARN, "
    "address range or port that is not in the data. Cite the evidence items you rely on by their "
    "ids (e1, e2, ...). If the blast radius is unknown, say that it is unknown; never say it is "
    "safe. Keep each field to two or three sentences."
)
RESPONSE_SCHEMA = {
    "type": "OBJECT",
    "properties": {
        "why_it_matters": {"type": "STRING"},
        "what_changes": {"type": "STRING"},
        "what_could_break": {"type": "STRING"},
        "cited": {"type": "ARRAY", "items": {"type": "STRING"}},
    },
    "required": ["why_it_matters", "what_changes", "what_could_break", "cited"],
}
TEXT_FIELDS = ("why_it_matters", "what_changes", "what_could_break")

ACCESS_KEY = re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{16}\b")
SECRET_ASSIGNMENT = re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*\S+")
SECRET_SHAPE = re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])")
ACCOUNT_ID = re.compile(r"(?<!\d)\d{12}(?!\d)")

ARN = re.compile(r"arn:aws[a-z-]*:[A-Za-z0-9:/_.*+=,@-]+")
RESOURCE_ID = re.compile(r"\b(?:sg|i|vpc|subnet|vol|ami|snap|eni|rtb|acl|igw|nat)-[0-9a-f]{8,17}\b")
IPV4_CIDR = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b")
IPV6_CIDR = re.compile(r"[0-9a-fA-F:]*:[0-9a-fA-F:]*/\d{1,3}")
PORT = re.compile(r"\bports?\s+(\d{1,5})(?:\s*(?:-|to)\s*(\d{1,5}))?", re.IGNORECASE)


class HourlyLimit:
    def __init__(self, max_calls: int, clock=time.monotonic):
        self.max_calls = max_calls
        self.clock = clock
        self.calls: deque[float] = deque()
        self.lock = threading.Lock()

    def allow(self) -> bool:
        with self.lock:
            now = self.clock()
            while self.calls and now - self.calls[0] >= 3600:
                self.calls.popleft()
            if len(self.calls) >= self.max_calls:
                return False
            self.calls.append(now)
            return True


def redact(text: str) -> str:
    text = ACCESS_KEY.sub("<AWS_ACCESS_KEY_ID>", text)
    text = SECRET_ASSIGNMENT.sub("aws_secret_access_key=<AWS_SECRET_ACCESS_KEY>", text)
    text = SECRET_SHAPE.sub("<AWS_SECRET_ACCESS_KEY>", text)
    return ACCOUNT_ID.sub("<ACCOUNT_ID>", text)


def load_knowledge(rule_id: str) -> str:
    if not re.fullmatch(r"[A-Z0-9-]+", rule_id):
        raise ValueError(f"Unexpected rule id: {rule_id!r}")
    path = files("cloudshield.ai").joinpath("knowledge", f"{rule_id}.md")
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def evidence_with_ids(evidence: dict) -> list[dict]:
    return [{"id": f"e{n}", **item} for n, item in enumerate(evidence.get("items", []), start=1)]


def build_payload(context: dict) -> dict:
    # This is everything the model sees besides the knowledge document. See docs/ai-data.md.
    finding = context["finding"]
    patches = [
        {"format": p["format"], "content": p["content"], "files": p["files"]}
        for p in context["patches"]
    ]
    return {
        "finding": {
            "rule_id": finding["rule_id"],
            "title": finding["title"],
            "severity": finding["severity"],
            "resource_type": finding["resource_type"],
            "resource_id": finding["resource_id"],
        },
        "evidence": evidence_with_ids(finding["evidence"]),
        "blast_radius": context["blast_radius"],
        "patches": patches,
        "guidance": context["guidance"],
    }


def build_request(context: dict) -> tuple[dict, str]:
    """Returns the request body and the redacted data text the model was given."""
    data = redact(json.dumps(build_payload(context), indent=2, sort_keys=True))
    prompt = f"Knowledge about this rule:\n{context['knowledge']}\nData:\n{data}\n"
    body = {
        "systemInstruction": {"parts": [{"text": SYSTEM_INSTRUCTION}]},
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {
            "responseMimeType": "application/json",
            "responseSchema": RESPONSE_SCHEMA,
            "temperature": 0.2,
        },
    }
    return body, data


WHY = {
    "CIS-S3-001": (
        "The public access block on bucket {resource} is missing or incomplete, so a policy "
        "or ACL could make its objects public."
    ),
    "CIS-S3-002": (
        "Bucket {resource} encrypts new objects with S3-managed keys, not with a KMS key you "
        "control. This is a hardening step, not an urgent exposure."
    ),
    "CIS-S3-003": (
        "Versioning is not enabled on bucket {resource}, so overwritten or deleted objects "
        "cannot be recovered."
    ),
    "CIS-SG-001": (
        "Security group {resource} has an inbound rule open to the internet on SSH or on all "
        "traffic, so anyone can try to reach those ports."
    ),
    "CIS-IAM-001": (
        "Policy {resource} allows all actions or all resources, which gives its holders more "
        "power than they need."
    ),
    "SX-IAM-PRIVESC-001": (
        "The permissions of {resource} match known privilege escalation methods. This is a "
        "heuristic: boundaries and service control policies are not checked."
    ),
}


def template_explanation(context: dict) -> dict:
    finding = context["finding"]
    blast = context["blast_radius"]
    why = WHY.get(finding["rule_id"], finding["title"]).format(resource=finding["resource_id"])
    patches = context["patches"]
    if patches:
        formats = ", ".join(p["format"] for p in patches)
        changes = f"The fix is available as: {formats}. Review the patch text before you apply it."
    else:
        changes = "No patch is generated. Follow the guidance and review the evidence."
    notes = " ".join(blast["notes"])
    cited = [item["id"] for item in evidence_with_ids(finding["evidence"])]
    return {
        "why_it_matters": why,
        "what_changes": changes,
        "what_could_break": f"Blast radius: {blast['level']}. {notes}".strip(),
        "cited": cited,
    }


def check_explanation(explanation: dict, evidence_ids: set[str], allowed: str) -> str | None:
    """Returns why the explanation is rejected, or None when it is acceptable."""
    cited = explanation["cited"]
    unknown_ids = [c for c in cited if c not in evidence_ids]
    if unknown_ids:
        return f"cites evidence that does not exist: {unknown_ids}"
    text = " ".join(explanation[name] for name in TEXT_FIELDS)
    if "`" in text:
        return "contains code"
    if ACCOUNT_ID.search(text):
        return "contains an account id"
    for pattern in (ARN, RESOURCE_ID, IPV4_CIDR, IPV6_CIDR):
        for token in pattern.findall(text):
            if token not in allowed:
                return f"names something that is not in the data: {token}"
    for match in PORT.finditer(text):
        for number in filter(None, match.groups()):
            if number not in allowed:
                return f"names a port that is not in the data: {number}"
    return None


def parse_explanation(text: str) -> dict | None:
    try:
        explanation = json.loads(text)
    except ValueError:
        return None
    if not isinstance(explanation, dict):
        return None
    for name in TEXT_FIELDS:
        if not isinstance(explanation.get(name), str) or not explanation[name].strip():
            return None
    cited = explanation.get("cited")
    if not isinstance(cited, list) or not all(isinstance(c, str) for c in cited):
        return None
    return {**{name: explanation[name] for name in TEXT_FIELDS}, "cited": cited}


def google_error(response: httpx.Response) -> tuple[str, str]:
    """Google's error status and message from a failed response, with secrets redacted."""
    try:
        error = response.json()["error"]
        status, message = str(error.get("status", "")), str(error.get("message", ""))
    except (ValueError, KeyError, TypeError, AttributeError):
        status, message = "", response.text
    return status, redact(message)[:300]


def response_text(response: httpx.Response) -> str | None:
    try:
        return response.json()["candidates"][0]["content"]["parts"][0]["text"]
    except (ValueError, KeyError, IndexError, TypeError):
        return None


def call_model(
    client: httpx.Client, model: str, api_key: str, body: dict, attempts: int
) -> tuple[str | None, str]:
    """Returns (text, failure). Only temporary failures are retried."""
    url = GEMINI_URL.format(model=model)
    failure = ""
    for attempt in range(1, attempts + 1):
        try:
            response = client.post(url, headers={"x-goog-api-key": api_key}, json=body)
        except httpx.TransportError as exc:
            failure = type(exc).__name__
            logger.warning(
                "Gemini attempt %d of %d on %s failed: %s", attempt, attempts, model, failure
            )
        else:
            if response.status_code == 200:
                text = response_text(response)
                if text is not None:
                    return text, ""
                logger.warning(
                    "Gemini attempt %d of %d on %s: no text in the answer",
                    attempt,
                    attempts,
                    model,
                )
                return None, "HTTP 200 with no text"
            status, message = google_error(response)
            failure = f"HTTP {response.status_code} {status}".strip()
            if message:
                failure += f": {message}"
            logger.warning(
                "Gemini attempt %d of %d on %s failed: HTTP %s %s: %s",
                attempt,
                attempts,
                model,
                response.status_code,
                status,
                message,
            )
            if response.status_code not in RETRY_STATUSES:
                return None, failure
        if attempt < attempts:
            sleep(BACKOFF_SECONDS * 2 ** (attempt - 1))
    return None, failure


def template_result(context: dict, reason: str) -> dict:
    logger.warning("Gemini was not used: %s", reason)
    explanation = {**template_explanation(context), "skipped_reason": reason}
    return {"explanation": explanation, "generated_by": "template", "model": None}


def explain_fix(
    context: dict,
    settings: Settings,
    limit: HourlyLimit,
    transport: httpx.BaseTransport | None = None,
) -> dict:
    """Returns {"explanation", "generated_by", "model"}. Falls back to the template."""
    models = [m for m in (settings.gemini_model, settings.gemini_fallback_model) if m]
    if not settings.gemini_api_key:
        return template_result(context, "no GEMINI_API_KEY in this process")
    if not models:
        return template_result(context, "no GEMINI_MODEL set")
    if not limit.allow():
        return template_result(context, "hourly AI call limit reached")

    body, allowed = build_request(context)
    evidence_ids = {item["id"] for item in evidence_with_ids(context["finding"]["evidence"])}
    attempts = [(models[0], PRIMARY_ATTEMPTS)]
    if len(models) > 1 and models[1] != models[0]:
        attempts.append((models[1], 1))
    last_failure = ""
    with httpx.Client(transport=transport, timeout=TIMEOUT_SECONDS) as client:
        for model, count in attempts:
            text, failure = call_model(client, model, settings.gemini_api_key, body, count)
            if text is None:
                last_failure = f"{failure} on {model}"
                continue
            explanation = parse_explanation(text)
            if explanation is None:
                return template_result(context, "answer rejected: not the expected JSON")
            reason = check_explanation(explanation, evidence_ids, allowed)
            if reason is not None:
                return template_result(context, f"answer rejected: {reason}")
            explanation["skipped_reason"] = None
            return {"explanation": explanation, "generated_by": "gemini", "model": model}
    reason = f"all Gemini attempts failed (last: {last_failure}); see the server log"
    return template_result(context, reason)
