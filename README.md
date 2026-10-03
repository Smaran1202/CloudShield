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
python -m uvicorn cloudshield.api.app:create_app --factory --port 8000
```

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

An AI explanation is optional. Set `GEMINI_API_KEY`, `GEMINI_MODEL` and, if you want one,
`GEMINI_FALLBACK_MODEL` in the API's environment. Without them a fixed template explanation is
used. See `docs/ai-data.md` for exactly what is sent. To test the settings, run
`python -m cloudshield.fixes ai-check` in the same window where you set them.

In a second terminal, start the web app:

```powershell
cd web
npm run dev
```

Open http://localhost:5173. The page shows "API online (version x)" when the API is reachable.
The API health check is also at http://localhost:8000/api/health.

## Checks

From the repository root, with the virtual environment active:

```powershell
pytest -q
```

Then in `web/`:

```powershell
npx prettier --check .
npm run build
```

Continuous integration also runs `ruff check` and `ruff format --check` on the Python code.
