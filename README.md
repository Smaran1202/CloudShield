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
have defaults or are optional at this stage. To set one for the current PowerShell session:

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
