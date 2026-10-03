# What is sent to the AI model

CloudShield can ask a Gemini model to explain a fix in plain language. The explanation is optional.
It never creates the fix: the patches, the pre-checks, the rollback and the blast radius are built
by fixed templates from stored scan data. The model only writes text around them.

## When nothing is sent

- `GEMINI_API_KEY` is not set.
- Neither `GEMINI_MODEL` nor `GEMINI_FALLBACK_MODEL` is set. Model names are never built into the
  code.
- More than `AI_MAX_CALLS_PER_HOUR` explanations were already requested in the past hour (default
  30, counted in memory by the server process). The explanation is then the fixed template text.
- A stored fix exists and its inputs have not changed. It is reused and nothing is sent.

## What is sent

One HTTPS request per attempt to `generativelanguage.googleapis.com`, with the API key in the
`x-goog-api-key` header (never in the URL). The request contains exactly:

1. A fixed system instruction: explain only from the given data, write no code, name no resource,
   address range or port that is not in the data, cite evidence ids, and never call an unknown
   blast radius safe.
2. The knowledge document for the rule (`src/cloudshield/ai/knowledge/<rule_id>.md`), written for
   this project. It describes the rule in general and contains no data from your account.
3. A JSON object with:
   - `finding`: rule id, title, severity, resource type and resource id (for example a bucket name
     or a security group id).
   - `evidence`: the evidence items of the finding, numbered `e1`, `e2`, ... Each has the fact, its
     value, the field it came from and its certainty. For IAM findings these are the matched
     statements and actions, never a whole policy document.
   - `blast_radius`: the level, its factors and notes. This can include the names of the users,
     roles and groups a policy is attached to, and the ids of the running instances that use a
     security group.
   - `patches`: the text of the generated patches, including any JSON files.
   - `guidance`: the review steps for findings that have no patch.
4. The response format: a JSON schema with `why_it_matters`, `what_changes`, `what_could_break` and
   `cited`.

## What is never sent

Credentials, access keys and secrets, the scan output file, other resources, whole policy
documents, bucket contents, CloudTrail data, and your AWS profile name.

## Redaction

Before sending, the whole data text is scanned and these are replaced:

- 12-digit numbers (account ids) become `<ACCOUNT_ID>`, including inside ARNs.
- Anything shaped like an AWS access key id (for example starting with `AKIA` or `ASIA`) becomes
  `<AWS_ACCESS_KEY_ID>`.
- `aws_secret_access_key = ...` and any 40-character secret-shaped string become
  `<AWS_SECRET_ACCESS_KEY>`.

Resource ids, bucket names, security group ids and IAM user, role and group names are not
redacted, because the explanation needs to talk about them. If that is a concern, leave
`GEMINI_API_KEY` unset and the template explanation is used.

## Checks on the answer

The answer is rejected, and the template explanation is used instead, if:

- it is not the expected JSON, or a text field is empty;
- `cited` names an evidence id that does not exist;
- the text contains code (a backtick) or a 12-digit number;
- the text names an ARN, a resource id (for example `sg-...`, `i-...`), a CIDR range or a port
  that does not appear in the data that was sent.

These checks cannot catch every invented name. For example, a made-up bucket name written in plain
words is not detected. The explanation is labelled with `generated_by` (`gemini` or `template`) and
the model name, and the evidence and patches next to it always come from the scan, not from the model.

## Retries

Temporary failures (HTTP 429, 500, 502, 503, 504, network errors and timeouts) are retried up to
three times on `GEMINI_MODEL` with a growing wait. Errors that retrying cannot fix (400, 401, 403,
404) are not retried. After the primary model fails, `GEMINI_FALLBACK_MODEL` gets one attempt. If
that fails too, or no model is set, the template explanation is used. A rejected answer is not
retried on the fallback model.

## Finding out why Gemini was not used

- Every fix response has `explanation.skipped_reason`. It is null when Gemini wrote the
  explanation. Otherwise it is one of: `no GEMINI_API_KEY in this process`, `no GEMINI_MODEL set`,
  `hourly AI call limit reached`, `answer rejected: <check>`, or `all Gemini attempts failed
  (last: ...)`. The same reason is logged once as a warning by the server, and written in the header
  of the exported files.
- Each failed attempt logs one warning with the attempt number, the model, the HTTP status and
  Google's own error status and message. Keys and headers are never logged, and secret-shaped text
  in Google's message is redacted.
- A fix stored while the key or model was missing is replaced the next time it is requested after
  they are set. A fix stored after a failed call or a rejected answer is kept; use `?refresh=true`
  to try again.
- `python -m cloudshield.fixes ai-check` prints whether `GEMINI_API_KEY` is set (and its length,
  never the key), the two model names, and makes one small call to each model. It prints the reply,
  or the HTTP status and Google's message. It is run by you, in the window where the variables are
  set, and uses the same `x-goog-api-key` header as the API.
