# Experiments

Measurements for the research paper. They run on **synthetic data only**: fake AWS accounts made
with moto, hand-written import files and hand-written resources. Nothing here touches a real AWS
account, and nothing here changes how the product behaves. The results in `results/` are
committed because they hold no real data.

| Experiment | Question |
| --- | --- |
| E1 unknown handling | When a scan or import could not confirm something, does the resolver keep the finding open? |
| E4 patch validity | Are the patches CloudShield writes valid for the tool that will run them? |

## Run

From the repository root, in PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
python -m experiments.run_all
```

This runs E1 and E4, rewrites the files in `results/` and prints the summary tables. To run one:
`python -m experiments.e1` or `python -m experiments.e4`. Add `--out some\folder` to write the
files somewhere else. The tests are in `tests/test_experiments_e1.py` and
`tests/test_experiments_e4.py` and run with the rest of the suite (`python -m pytest -q`).

E1 takes about 40 seconds. The output is the same on every run.

Two validators for E4 need extra tools. Without them their rows are `skipped`, not `yes`:

- CloudFormation is checked with cfn-lint (licence MIT-0, which allows this use). Install it with
  `pip install -e ".[experiments]"`. It is run as the `cfn-lint` command that pip installs
  (`cfn-lint --format json template.yaml`); version 1.59.0 has no `python -m cfnlint`. Exit code 0
  is clean, 2 is an error, 4 a warning and 8 an informational message (added together); only an
  error makes a patch invalid, and any other exit code stops the run with an error.
- Terraform is checked with `terraform validate`. It is only run when you add `--terraform`
  (`python -m experiments.run_all --terraform`), needs `terraform` on the PATH and the network
  (`terraform init` runs once and downloads the AWS provider; `terraform validate -json` then runs
  for each patch). It may be blocked on some machines, so the CI job
  `experiments-e4` in `.github/workflows/ci.yml` runs it and uploads `e4.csv` as the artifact
  `e4-results`. Use that file for the Terraform and CloudFormation numbers in the paper.

## Versions used

The committed results were made with Python 3.12.10, boto3 and botocore 1.43.107, moto 5.2.3,
SQLAlchemy 2.1.2 and PyYAML 6.0.3. cfn-lint is pinned to 1.59.0 in `pyproject.toml`. CI runs
Terraform 1.9.8 with the AWS provider `~> 5.0`. `run_all` prints the versions it found.

## E1: unknown handling

Starts from a fake account that breaks every CloudShield rule (9 open findings: 3 on one S3 bucket,
1 on a security group, 4 on two IAM policies, 1 on an IAM role). Then it scans again with one
fault, and saves the scan with two resolvers. The account was not fixed, so every finding that is
resolved afterwards is resolved wrongly.

Resolvers:

- `cloudshield`: the product code, unchanged (`cloudshield.db.store.resolve_fixed`).
- `naive`: the baseline, in `naive.py`. It treats missing data and scanner errors as passing: a
  finding that the scan or import does not report again is called fixed. It is used only here. It
  replaces the product resolver inside the experiment process and cannot be reached from the API or
  the dashboard.

Scenarios (the `scenario` column):

- `scan_fault`: one fault on each of the 18 calls the scanner makes (`faults.py`; a test checks the
  list against a real scan). Faults: `access_denied`, `throttling` (the error is raised after
  botocore's own retries, so it is the error a scan sees when retries run out), and `missing_key`
  (the call works but its response lacks the key the scanner reads). A `missing_key` response
  stops the scan with a `KeyError`; no result is saved, so no resolver runs. Those cases are
  counted in `scans_crashed` and are identical for both resolvers.
- `silent_drop`: not a scanner behaviour. An attribute that a rule reads is removed from the scan
  result with no error recorded. The scanner never does this, because it records an error whenever
  it leaves an attribute out. This probes whether the resolver depends on that. The first run of
  E1 found that it did: CloudShield wrongly resolved 10 of 63 findings. The resolver now also
  keeps a finding open when the attribute its rule reads is absent from the stored resource
  (`rules/unknown.py`), and the committed results show 0 wrong resolutions for it. The naive
  resolver's numbers did not change.
- `import_newer`: a first import opens 3 findings; a newer import then leaves the check out
  (`check_absent`), reports it as MANUAL, which is neither PASS nor FAIL (`ignored_status`), or
  reports it for another resource (`resource_absent`). The import files are synthetic.
- `control_fixed`: the bucket is really fixed (`check_passes` does the same for imports). A
  resolver that never resolved anything would also have no wrong resolutions, so these cases show
  that real fixes are still resolved. One control also denies a call at the same time.

`e1.csv` has one row for each case and resolver:

| Column | Meaning |
| --- | --- |
| `scenario` | The group of cases, as above |
| `service` | The AWS service the fault was on (`import` for import cases) |
| `fault` | The kind of fault, or the kind of newer import |
| `detail` | The API operation, the attribute that was dropped, or a short description |
| `resolver` | `cloudshield` or `naive` |
| `findings_open_before` | Open findings from the same source before the case |
| `truly_fixed` | How many of them were really fixed in the case (0 except in controls) |
| `wrongly_resolved` | Resolved, but not really fixed. The number that matters |
| `correctly_resolved` | Resolved, and really fixed |
| `correctly_kept_open` | Still open, and not really fixed |
| `wrongly_kept_open` | Still open, but really fixed |
| `scan_outcome` | `completed`, `imported`, or `crashed: ...` |
| `errors_recorded` | Errors the scan recorded (the scan's `errors` list) |

`e1_summary.csv` adds up the rows for each `scenario`, `fault` and `resolver`: `cases`, the sums of
the five counts, `cases_with_wrong_resolve` (cases with `wrongly_resolved` above 0) and
`scans_crashed`.

Limits: moto is not AWS, and the fake account is small. The injected errors use codes that we
chose for each service. `findings_open_before` counts findings, so cases with more findings weigh
more.

## E4: patch validity

Generates every patch CloudShield can write: the fixes of the four rules that have a patch template
(CIS-S3-001, CIS-S3-002, CIS-S3-003, CIS-SG-001) from the hand-written fixtures in
`e4_fixtures.py` (5 buckets with odd names, regions and settings; 8 security groups with IPv4,
IPv6, port ranges, protocol `-1`, protocol `6`, several rules and mixed ranges), and the patches of
every guardrail. The IAM rules have guidance only, no patch. The rules run on the fixtures, so the
details come from the real rule code.

Validators:

- `cli`: offline, against botocore's service model (`botocore.loaders`, files on this machine).
  The operation must exist, every `--option` must be a parameter of it, required parameters must be
  given, and values and the JSON files they point to must fit the parameter's shape and enum
  values. Placeholders such as `REPLACE_WITH_ROOT_ID` are not checked against patterns (the patch
  says an input is needed). A command that passes is well formed; it is not proof that AWS would
  accept it for your account. The AWS CLI names `s3api` and `configservice` differently from
  botocore (`s3` and `config`); that mapping is from our knowledge of the AWS CLI and was not run
  against it.
- `cloudformation`: cfn-lint. Only a message of level Error makes a patch invalid.
- `terraform`: `terraform validate` with the AWS provider.
- `github_actions` (guardrails): valid YAML with a trigger and jobs that have a runner and steps.
  This is weaker than a workflow linter such as actionlint.
- Patches that are instructions in words (`instructions_only`) have no code to check and are
  `skipped` with the validator `none`.

`e4.csv` has one row for each patch:

| Column | Meaning |
| --- | --- |
| `rule` | The rule the patch is for. A guardrail shared by two rules lists both, joined with `+` |
| `fixture` | The fixture name, or the guardrail id |
| `source` | `fix` or `guardrail` |
| `format` | `terraform`, `cloudformation`, `cli` or `github_actions` |
| `patch` | The title of the patch |
| `validator` | Which check ran |
| `valid` | `yes`, `no`, or `skipped` (the validator was not run) |
| `error` | The first problem found, or why it was skipped |

`e4_summary.csv` counts `yes`, `no` and `skipped` for each `source`, `format` and `validator`.
