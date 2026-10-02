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

In one terminal, start the API:

```powershell
.\.venv\Scripts\Activate.ps1
uvicorn cloudshield.api.app:create_app --factory --port 8000
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
