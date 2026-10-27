# Extended checks (Prowler)

The extended checks run [Prowler](https://github.com/prowler-cloud/prowler) after CloudShield's
own scan, and import its results. Prowler is a separate program that you install yourself.
CloudShield does not bundle it. Its findings are labelled "Imported".

This works for the AWS account of this computer only. There is no login yet, so run the app on
localhost only.

## 1. Install Prowler in its own virtual environment

Keep Prowler away from CloudShield's environment, because the two need different packages.

```powershell
python -m venv C:\tools\prowler-venv
C:\tools\prowler-venv\Scripts\python.exe -m pip install prowler
C:\tools\prowler-venv\Scripts\python.exe -m prowler --version
```

## 2. Tell CloudShield where it is

Put the path of that Python in `.env` (names are listed in `.env.example`):

```
PROWLER_PYTHON=C:\tools\prowler-venv\Scripts\python.exe
```

CloudShield then runs `PROWLER_PYTHON -m prowler aws ...`. The other settings:

| Setting | Meaning | Default |
|---|---|---|
| `PROWLER_PYTHON` | Python that has Prowler installed | empty |
| `PROWLER_COMMAND` | JSON list used when `PROWLER_PYTHON` is empty | `["prowler"]` |
| `PROWLER_SERVICES` | services to check, separated by spaces | `s3 ec2 iam` |
| `PROWLER_TIMEOUT_SECONDS` | longest a run may take | `1800` |
| `CLOUDSHIELD_DATA_DIR` | where each run gets a temporary folder | `./data` |
| `KEEP_RAW_OUTPUT` | keep the results file after the import | `false` |

Regions come from the scan request or from `AWS_REGION`. Regions and services may only contain
`a-z`, `0-9` and `-`, and may not start with `-`.

## 3. Check it

```powershell
python -m cloudshield.imports check-runner
```

It prints the Prowler version, or the exact reason it cannot run and what to do. It does not
start a scan. Restart the API after changing `.env`.

## If Prowler cannot run

- **Blocked by the operating system.** A Windows application control policy can block a
  program from starting. The error is `WinError 4551` or `PermissionError`. CloudShield reports
  it as blocked, also when the policy blocks one of Prowler's libraries after it has started (an
  `ImportError: DLL load failed ... Application Control policy` in its output). Try a different
  Python for `PROWLER_PYTHON`, or use Docker, WSL or the file route below. The dashboard then says:
  "This computer blocks Prowler. Run it elsewhere, for example in AWS CloudShell, then import the
  file here." and keeps the full scan disabled.
- **Not found.** Set `PROWLER_PYTHON` to the full path, as in step 2.
- **Wrong Python.** The message says that module `prowler` is missing. Install it in that
  Python, or point `PROWLER_PYTHON` at the right one.
- **Docker.** Set `PROWLER_COMMAND` to a JSON list that starts your Prowler container. CloudShield
  adds `aws -f ... --services ... -M json-ocsf -o <folder> -b -z` after it, so the container
  must start Prowler with those arguments and have that folder available. This has not been
  tried here. If it does not fit, run Prowler yourself and import the file with
  `python -m cloudshield.imports prowler <file>`.
- **WSL.** Install Prowler inside WSL. A folder on the Windows side looks different from inside
  WSL, so importing the file you made there is simpler than setting `PROWLER_COMMAND`.

## Run it elsewhere and import the file (CloudShell)

This route works when Prowler cannot run on this computer, and it needs nothing installed here.
Choose "Import a results file" in the Run scan menu, or above the Imports table. The window shows
the two commands with copy buttons.

1. Open AWS CloudShell in the account to check, install Prowler there and run it. The run command
   is built from the same settings a dashboard run uses (`AWS_REGION` and `PROWLER_SERVICES` of
   the API), for example:

   ```
   pip install prowler
   prowler aws -f ap-southeast-2 --services s3 ec2 iam -M json-ocsf -o prowler-out -b -z
   ```

   If `AWS_REGION` is not set on the server, the window cannot show the run command; set it and
   open the window again.
2. Download the file that ends in `.ocsf.json` from the `prowler-out` folder.
3. Choose it in the window, or drop it there. Only `.json` files up to 50 MB are accepted.
4. The window shows "Imported N, M passed, K resolved", or the reason the file was refused.

The file is sent to this computer's CloudShield API only (`POST /api/imports/prowler`, sent as
`application/json`, with the name in the `X-Filename` header; only the base name is kept). The
reply holds counts only and never repeats anything from the file. The same rules apply as for the
command line import: a file is refused if it was imported before, if its OCSF major version is not
1, or if it mixes accounts. One import runs at a time, and an import is refused while a scan is
running. The import is listed with the origin "Upload".

## Permissions

Prowler needs read access to the account. Attach the AWS managed policies `SecurityAudit` and
`ViewOnlyAccess` to the scanner user. Without them Prowler reports errors, and CloudShield says
so next to the results it did import. Nothing is ever changed in the account.

## Time and cost

- A run takes from a few minutes to much longer, depending on the account. The dashboard says
  "this can take several minutes" and has no percentage, because Prowler reports none.
- A run is stopped after `PROWLER_TIMEOUT_SECONDS`, together with everything it started.
- Prowler is built to read only, and CloudShield asks for read access only. Check the pricing of
  the AWS services in your account for anything that may be billed. A large account can reach
  API rate limits, which slows the run.
- Only one run can happen at a time.

## What stays private

Prowler is started with a short list of environment variables only: the path, the temporary
folders, and the AWS profile and region settings. The Gemini key and other secrets are not
passed. No credentials are put on the command line. Output that is shown in the dashboard is
cut to the last few lines, and key-shaped text and 12-digit account numbers are hidden.
