# Changelog

CloudShield is a student capstone project. Each entry says in plain words what was added.

## 0.9.0 - 2026-11-17

The release candidate. The final audit comes after it.

- **Numbers command.** `python -m cloudshield.report numbers` reads the database and writes a
  Markdown table of findings by rule, severity and lane, merged pairs and disagreements, resolved
  findings, scans, imports, guardrail statuses, versions and the experiment summaries. Account ids
  and resource names become aliases, so the output is safe to share.
- **Demo data.** `python -m cloudshield.demo seed --db demo.db` builds a made-up AWS account with
  moto, runs the real scanner and rules on it, scans again after a simulated fix, and imports a
  hand-written file. Scans in it carry a data label, and the dashboard shows it as a banner.
- **README rewrite**, `docs/reproduce.md`, `docs/browser-tests.md`, and a one-line explanation for
  every setting in `.env.example`.

## Before 0.9.0

In the order they were built:

- **Foundation, scanner, rules, database and API.** Read-only discovery of S3 buckets, security
  groups, EC2 instances and IAM policies and roles, six rules, and a FastAPI service with SQLite
  storage and migrations.
- **Risk scoring and evidence.** A score from the severity plus context (exposure, attachment,
  privilege), with the evidence behind it and how sure each fact is.
- **Fix generation.** Patches as text (AWS CLI, Terraform, CloudFormation), checks to make first,
  what CloudShield did not look at, an optional Gemini explanation, and an export to files.
- **Dashboard.** Overview, Findings, Resources, Scans and a fix page, in React.
- **Prowler import.** Import of a results file, imported findings shown truthfully as reported,
  dismissals, and merging of the three imported checks that test the same thing as one of our rules.
- **Running Prowler from the dashboard**, locally and in Docker mode, plus plain-language guidance
  for 13 imported checks.
- **One lock for scans and imports**, so they never run together.
- **"N to fix now" headline** and the merge of the KMS check.
- **Guardrails** ("Prevent it coming back") with statuses read from the last scan.
- **Review fixes.** An origin check on writes, and limits on the size and shape of an imported file.
- **Account-wide block awareness.** A bucket is not marked as exposed when the account-wide public
  access block is on.
- **Account id masking** in the dashboard.
- **Playwright tests**, read-only and acting.
- **Noise reduction** (phases 13 and 13b). Later grouped by check, a shorter fix page, bulk
  dismissal of AWS-managed items, and a decluttered Findings list.
- **Experiments E1 and E4.** E1 measures whether the resolver keeps findings open when something
  could not be read; it found one real weakness, which was fixed. E4 checks that the patches are
  valid for the tool that runs them. E2, E3 and E5 have not been run.
- **Login lock**, then removed again: an optional owner and viewer password was built and later
  deleted, so there is no login now.

Removed on purpose: the blast radius. Fixes list the checks to make first and what CloudShield did
not look at instead.
