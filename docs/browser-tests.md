# Browser tests (Playwright)

There are two Playwright suites in `web/`. They open the real dashboard in your installed Google
Chrome or Microsoft Edge and download no browser. Windows is assumed: the Chrome and Edge paths and
the virtual environment path (`.venv\Scripts\python.exe`) are Windows ones. CI does not run them.

| Command | What it does | Touches AWS, Gemini or Docker? |
|---|---|---|
| `npm run e2e` | read-only tests against your local API and database | No (see the note on the Run scan menu) |
| `npm run e2e:actions` | tests that act: scan, fix, dismiss, import, full scan | **Yes** |

Type-check all of them with `npm run typecheck:e2e`.

## Read-only (`npm run e2e`)

If the API (127.0.0.1:8000) and the dev server (localhost:5173) are not running, the command starts
them with `.venv\Scripts\python.exe` and stops them afterwards; servers that are already running
are reused. The tests read the data that is in your database and skip a test, with the reason, when
the data it needs is missing (for example no imported finding).

They only read. Every request to `/api` that is not a GET is stopped and fails the test with its
URL, and any console error, page error or failed request fails it too. They never press Run scan,
Run full scan, Generate fix, Dismiss or the upload.

What they do not cover (the action tests below cover some of it):

- The text of an imported fix ("What to do", "Plain words", the formatted guidance) and the stored
  fix of a CloudShield finding. The page shows them only after Generate fix, which sends a POST.
  That test is listed as skipped.
- Anything that writes: scans, dismissals, uploads, rescans.
- Visual design, screen sizes other than the default, and browsers other than Chrome or Edge.
- Opening the Run scan menu makes the API check the extended runner (`/api/extended/status`),
  which in Docker mode runs `docker version` and `docker image inspect`. It starts no scan and no
  container.

## Tests that act (`npm run e2e:actions`)

They are separate from the read-only tests, have their own config, and refuse to start unless you
confirm. Run them yourself, never from CI. **They do real work:**

- They scan the AWS account of the profile in your `.env` (read-only calls). A scan takes minutes.
- "Generate fix" calls Gemini when `GEMINI_API_KEY` and `GEMINI_MODEL` are set in your `.env`. That
  is a few calls, and they count against `AI_MAX_CALLS_PER_HOUR`.
- "Run full scan" runs Prowler, in Docker if `PROWLER_MODE=docker`, and the test waits up to 30
  minutes. It is skipped, with the reason, when `/api/extended/status` says it cannot run.
- They write only to a throwaway database, `e2e-actions.db` in the project folder, which is made
  from the migrations before the run and deleted before and after it. Your real `cloudshield.db`
  is never opened. They use their own API (port 8010) and web server (port 5183), which are never
  reused: if a port is busy the run stops.

```powershell
cd web
$env:CLOUDSHIELD_E2E_ACTIONS = "yes"
npm run e2e:actions
```

Without `CLOUDSHIELD_E2E_ACTIONS=yes` the command prints what the tests do and stops. To run one
test, add its name: `npm run e2e:actions -- -g "dismissing"`.

The tests run in order, one at a time, and each builds on the one before; after a failure the rest
are skipped.

1. The header says the API is online, on an empty database.
2. Run scan completes and the Overview shows findings.
3. The fix of a CIS-S3-001 finding has patches, "CloudShield did not check" and guardrail cards.
   Skipped if the scan found no such finding.
4. Dismissing a finding takes it out of the headline and lane counts, and undoing brings it back.
5. A synthetic results file (made up by the test, fake account `000000000000`) is imported, and the
   same file again is refused as already imported.
6. Run full scan adds a new import with the origin Dashboard.
7. Every test fails on a console error, a page error, a failed request or an error response (the
   expected "already imported" refusal is the only one allowed), and on any request to an API other
   than the test API.

They keep no screenshots, videos or traces. Because they use the real account and the real Gemini
key, run them on your own computer only. If a run is stopped halfway, delete `e2e-actions.db` by
hand.
