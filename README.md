# CloudShield

CloudShield is an AWS security platform. It discovers resources with read-only AWS access,
checks them against rules to produce findings, adjusts risk scores using context, finds attack
paths, and shows the results in a React dashboard. This repository currently contains the
foundation: a FastAPI service with a health endpoint and a web page that calls it.

## Setup

Requires Python 3.12 and Node 20 or newer.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"

cd web
npm ci
cd ..
```

Settings come from environment variables. The names are listed in `.env.example`. All of them
have defaults or are optional. The simplest way to set them is a `.env` file in the folder you run
the commands from:

```powershell
Copy-Item .env.example .env
```

Then fill in the values you need in `.env`. The API, `python -m cloudshield.scanner` and
`python -m cloudshield.fixes` read it when they start. A variable that is already set in your shell
wins over the file. `.env` is ignored by git, so keys in it are never committed. To set one for the
current PowerShell session instead:

```powershell
$env:FRONTEND_ORIGIN = "http://localhost:5173"
```

The web app reads `VITE_API_URL` (see `web/.env.example`). It defaults to `http://localhost:8000`.

## Run

Create or update the database (SQLite by default, in `cloudshield.db`). Run this once, and again
after pulling changes that add migrations:

```powershell
.\.venv\Scripts\Activate.ps1
python -m alembic upgrade head
```

To use PostgreSQL, set `DATABASE_URL` and install a driver such as `psycopg` first.

In one terminal, start the API. A scan uses the AWS profile named in `AWS_PROFILE` and the region
in `AWS_REGION`, or the regions sent with the scan request:

```powershell
.\.venv\Scripts\Activate.ps1
$env:AWS_PROFILE = "your-profile"
$env:AWS_REGION = "us-east-1"
python -m uvicorn cloudshield.api.app:create_app --factory --host 127.0.0.1 --port 8000
```

> **Warning: run the server only on localhost.** There is no login yet. Never use
> `--host 0.0.0.0` and never expose the port. Anyone who can reach it can start scans with the
> server's AWS credentials, read all findings, upload files and dismiss findings.

Start a scan and read the results:

```powershell
$scan = Invoke-RestMethod -Method Post http://localhost:8000/api/scans
Invoke-RestMethod http://localhost:8000/api/scans/$($scan.id)
Invoke-RestMethod http://localhost:8000/api/findings
```

Request a fix for a finding and export it to files you can review. CloudShield only writes text;
it never runs anything in your account:

```powershell
$id = (Invoke-RestMethod "http://localhost:8000/api/findings?status=OPEN")[0].finding_id
Invoke-RestMethod -Method Post "http://localhost:8000/api/findings/$id/fix"
python -m cloudshield.fixes export $id --dir fixes-out
```

The export also writes the guardrails for the finding, under `fixes-out/guardrails/`: ready-to-copy
files that stop the problem coming back, such as a GitHub Actions workflow or a setting for the
whole account. The Fix tab shows them under "Prevent it coming back", each with a status read from
your last scan. See `docs/guardrails.md`. The scan now also reads the account-wide S3 public access
block, so add `s3:GetAccountPublicAccessBlock` to your read-only policy
(`docs/aws-readonly-policy.json`).

An AI explanation is optional. Set `GEMINI_API_KEY`, `GEMINI_MODEL` and, if you want one,
`GEMINI_FALLBACK_MODEL` in the API's environment. Without them a fixed template explanation is
used. See `docs/ai-data.md` for exactly what is sent. To test the settings, run
`python -m cloudshield.fixes ai-check` in the same window where you set them.

In a second terminal, start the web app:

```powershell
cd web
npm run dev
```

Open http://localhost:5173. The header shows "API online v{version}" when the API is reachable,
the last scan, and the Run scan button. The dashboard has an Overview (a board of what to fix now,
next and later), Findings (with a detail page for each), Resources and Scans. It only reads from the
API and starts scans. It never changes anything in AWS.

Open the dashboard at that exact address. The API refuses a write (a scan, a dismissal, an upload,
a fix) that comes from any other web address, and `localhost` and `127.0.0.1` count as different
addresses: the dashboard opened at http://127.0.0.1:5173 cannot start scans. To use another
address, set `FRONTEND_ORIGIN` on the server to it. Scripts and `Invoke-RestMethod` send no origin
and are not affected.

The Overview headline reads "{N} fixed." and "{F} to fix now.". F counts the findings in the Fix
now lane (risk score 80 or more) that are open, not dismissed, not merged and not informational,
from CloudShield and from imported scans alike. Below it, the Next, Later, informational and
dismissed counts each open the matching Findings list.

The web app loads three fonts (Bricolage Grotesque, Public Sans and IBM Plex Mono) from Google Fonts,
so your browser contacts Google Fonts when the page opens. If that is blocked, the page falls back to
system fonts and works the same.

The web app's own tests, which use a mocked API, run with:

```powershell
cd web
npm test
```

## Import Prowler findings

Run Prowler yourself with JSON-OCSF output, then import the file:

```powershell
python -m alembic upgrade head
python -m cloudshield.imports prowler path\to\prowler-output.ocsf.json
```

Imported findings are marked with their source, and their evidence is labelled "reported". Three
imported checks (public access block, object versioning and KMS encryption of S3 buckets) test the
same thing as one of CloudShield's own rules, so when both fail on a bucket they are shown once.
See `docs/limitations.md` and `docs/third-party.md`.

To run the extended checks from the dashboard ("Run full scan"), install Prowler yourself and
check that CloudShield can start it:

```powershell
python -m cloudshield.imports check-runner
```

See `docs/extended-checks.md` for the install steps and the settings.

Instead of a local install, CloudShield can run the Prowler container: set `PROWLER_MODE=docker`
in `.env` (Docker Desktop must be running). The same `check-runner` command then checks Docker and
the image. Put `CLOUDSHIELD_DATA_DIR` outside OneDrive. See the Docker section of
`docs/extended-checks.md`.

If your computer blocks Prowler, run it somewhere else (for example AWS CloudShell) and import the
file from the dashboard: choose "Import a results file" in the Run scan menu. The window shows the
commands to run and takes the `.json` file. The same steps are in `docs/extended-checks.md`.

The fix page of an imported finding shows the scanner's advice formatted as it was meant, and, for
13 checks, a "What to do" section written by CloudShield from AWS documentation. Check those steps
against the AWS page they link to before you act.

## Checks

From the repository root, with the virtual environment active:

```powershell
pytest -q
```

Then in `web/`:

```powershell
npx prettier --check .
npm run build
npm test
```

Continuous integration also runs `ruff check` and `ruff format --check` on the Python code.

### Browser tests (read-only)

`web/e2e/` holds Playwright tests that open the real dashboard in your installed Google Chrome
(or Microsoft Edge) against the real local API. They download no browser. In `web/`:

```powershell
npm run e2e
```

If the API (127.0.0.1:8000) and the dev server (localhost:5173) are not running, the command starts
them with `.venv\Scripts\python.exe` and stops them afterwards; servers that are already running
are reused. The tests read the data that is in your database and skip a test, with the reason, when
the data it needs is missing (for example no imported finding). Type-check them with
`npm run typecheck:e2e`.

They only read. Every request to `/api` that is not a GET is stopped and fails the test with its
URL, and any console error, page error or failed request fails it too. They never press Run scan,
Run full scan, Generate fix, Dismiss or the upload.

What they do not cover:

- The text of an imported fix ("What to do", "Plain words", the formatted guidance) and the
  stored fix of a CloudShield finding. The page shows them only after Generate fix, which sends a
  POST. That test is listed as skipped.
- Anything that writes: scans, dismissals, uploads, rescans.
- Visual design, screen sizes other than the default, and browsers other than Chrome or Edge.
- Windows is assumed: the Chrome and Edge paths and the virtual environment path are Windows ones.
- Opening the Run scan menu makes the API check the extended runner (`/api/extended/status`),
  which in Docker mode runs `docker version` and `docker image inspect`. It starts no scan and
  no container.
