# Reproducing the results

What you need to rebuild the numbers in the paper, and what you cannot rebuild without the author's
AWS account. Release 0.9.0.

## Versions

Read from the author's computer (Windows 11, PowerShell) when this file was written.

| What | Version |
|---|---|
| Python | 3.12.10 (the project needs 3.12 or newer) |
| Node | 24.16.0 and npm 11.13.0 here; the project needs Node 20 or newer, and CI uses Node 20 |
| boto3 and botocore | 1.43.107 |
| moto | 5.2.3 |
| SQLAlchemy | 2.1.2 |
| alembic | 1.20.0 |
| FastAPI | 0.142.2 |
| pydantic and pydantic-settings | 2.13.5 and 2.15.0 |
| PyYAML | 6.0.3 |
| cfn-lint (E4 only) | 1.59.0, pinned in `pyproject.toml` |
| Terraform (E4 only) | 1.9.8 with the AWS provider `~> 5.0`, as run in CI |
| Prowler | 5.44.0. This is the version whose output was checked (JSON-OCSF, OCSF 1.5.0). Other versions are accepted if their OCSF major version is 1, but were not checked |
| Docker image | `PROWLER_DOCKER_IMAGE` defaults to `toniblyx/prowler:latest`, which changes over time. For repeatable runs, pin a tag such as `toniblyx/prowler:5.44.0`. The image of each dashboard run is stored with its import (`run_image` in `GET /api/imports`) |
| React, Vite, vitest, TypeScript | the ranges in `web/package.json`; `web/package-lock.json` pins the exact versions, so use `npm ci` |

The Python packages above are the ones installed in the author's environment. `pyproject.toml`
does not pin them, except cfn-lint, so a fresh install may get newer ones.

### AI model settings

The names of the settings are `GEMINI_MODEL`, `GEMINI_FALLBACK_MODEL` and `EMBEDDING_MODEL`
(`EMBEDDING_MODEL` is only recorded: nothing reads it yet). The values used for a run are printed
in the "AI model settings" table of the numbers report (`python -m cloudshield.report numbers`).
The key (`GEMINI_API_KEY`) is never printed or stored. The AI text is optional and is not part of
any measured result.

## Rebuild the results

From the repository root, in PowerShell, with the virtual environment active and
`pip install -e ".[dev]"` done. None of these commands calls AWS, Gemini or Docker, and none needs
a network.

```powershell
# The demo database: a made-up account, built with moto
python -m cloudshield.demo seed --db demo.db --force

# The numbers, from that database. Account ids and resource names become aliases.
python -m cloudshield.report numbers --db demo.db --out numbers.md --csv numbers.csv

# Experiments E1 and E4 (E1 takes about 40 seconds). They rewrite experiments/results/
python -m experiments.run_all

# The tests
python -m pytest -q
cd web
npm ci
npx prettier --check .
npm run build
npm test
```

E4 also needs cfn-lint (`pip install -e ".[experiments]"`), and its Terraform rows need
`python -m experiments.run_all --terraform`, `terraform` on the PATH and a network (the CI job
`experiments-e4` runs it). Without them those rows are `skipped`, never `yes`. See
`experiments/README.md`.

The demo, E1 and E4 give the same numbers on every run, apart from times, dates and the ids moto
makes up (security group ids, for example). The test counts in the numbers report are left for you
to fill in from your own `pytest` and `npm test` output.

## What you cannot reproduce without an AWS account

- **Scans of a real account.** Every real finding, score and resolution date comes from the author's
  account. The demo and the experiments use moto, which is not AWS.
- **What was checked against a real account.** The list is in `docs/limitations.md`: S3, security
  groups and customer-managed policies in one region. EC2 instances and IAM roles were checked with
  mocks only.
- **A real Prowler run, and its import.** It needs Prowler (or Docker) and AWS credentials. The
  hand-written import file in the demo is not a Prowler run. Docker mode was run by hand once, on
  Windows, and the tests use a fake docker program.
- **Gemini explanations.** They need a key, and the text changes from call to call.
- **The Playwright suites that act** (`npm run e2e:actions`). They scan your account and may call
  Gemini and Docker. Read `docs/browser-tests.md` before you run them.
- **The CloudShell commands** in the import window were not run in a real CloudShell.
- **Any number taken from a database of real scans.** Run `python -m cloudshield.report numbers`
  on your own database to get the same kind of table for your own account.
