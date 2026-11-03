# Guardrails: "Prevent it coming back"

A fix repairs what is wrong now. A guardrail makes it harder for the same problem to appear
again. CloudShield never applies a guardrail. Like a fix, each one is text for you to read and
apply yourself. Every AWS name, command and setting below was read in the AWS documentation on
2026-11-02, and each guardrail links to the page it came from.

Own findings only. Imported findings show no guardrails.

## Kinds and scope

| Kind | What it is |
|---|---|
| `account_setting` | A setting inside AWS that stops the problem |
| `pipeline_check` | A check in your own build pipeline that rejects the problem before it is deployed |
| `detective_rule` | An AWS Config rule that reports the problem after it appears. It does not block anything |
| `organization_policy` | A policy applied from your AWS Organization |

Scope says how much one guardrail covers: one resource, the whole account, or the whole
organization.

## Status

The status is read from the last completed scan each time you look. It is never stored as a claim.

| Status | Meaning |
|---|---|
| Active | A scan read the setting and found it on. Only the account-wide S3 public access block can be active |
| Not active | A scan read the account and the setting is missing or off |
| Unknown | CloudShield cannot check it (your pipeline, AWS Config rules, permissions boundaries), or the read failed (missing permission, an error, no scan yet) |
| Needs organization admin | Only your organization's management account can apply or read it, so CloudShield cannot verify it |

"Active" is never shown without a verified read. An access error or a missing permission always
gives "unknown". For the account-wide setting, AWS documents that the value returned is the one
in effect for the account, so an organization policy can be the reason it is on.

## What each rule gets

| Rule | Guardrails |
|---|---|
| CIS-S3-001 (public bucket) | Account-wide block public access; organization block public access |
| CIS-S3-003 (no versioning) | Pipeline check for versioning; AWS Config rule |
| CIS-SG-001 (open SSH) | Pipeline check for open SSH; AWS Config rule |
| CIS-IAM-001 (wildcard policy) | Policy validation in the pipeline; permissions boundary; AWS Config rule |
| SX-IAM-PRIVESC-001 (privilege escalation) | Policy validation in the pipeline; permissions boundary |
| CIS-S3-002 (no KMS key) | None. It is informational |

## The guardrails

**Block public access for the whole account** (`s3-account-block-public-access`). Turns on all
four S3 Block Public Access settings for every bucket in the account, in all Regions. Terraform
(`aws_s3_account_public_access_block`) and AWS CLI (`aws s3control put-public-access-block`). There
is no CloudFormation patch, because the CloudFormation S3 resource list has no account-level
resource. It does not change existing policies or ACLs, and a bucket that needs public access, such
as a static website, stops serving it. Cost: check pricing. The scan reads this one, which needs
`s3:GetAccountPublicAccessBlock`.

**Block public access across the organization** (`s3-organization-block-public-access`). An AWS
Organizations S3 policy of type `S3_POLICY` with `"@@assign": "all"`. It overrides the account-level
settings of the accounts it is attached to. It needs the management account, an organization in
all features mode and the S3 policy type enabled. Terraform is not offered because its resource
for this policy type was not checked. Cost: check pricing.

**Reject buckets without versioning** (`pipeline-s3-versioning`) and **Reject open SSH**
(`pipeline-sg-no-open-ssh`). GitHub Actions workflows that install Checkov and run one check each:
`CKV_AWS_21` (S3 versioning) and `CKV_AWS_24` (security group ingress to port 22 from 0.0.0.0/0).
They scan the Terraform and CloudFormation in your repository, so anything made in the console or
with another tool is not seen. Checkov is open source under the Apache License 2.0 and free; your CI
provider bills its own minutes. Checkov is installed with `pip install checkov` without a pinned
version, so pin one yourself if you want repeatable builds. The `--hard-fail-on` option makes the
step fail, as its documentation describes. Checkov's source handles `::/0` as well as `0.0.0.0/0`
for Terraform; that was not checked for CloudFormation.

**Validate IAM policies** (`pipeline-iam-validate-policy`). A GitHub Actions workflow that runs
`aws accessanalyzer validate-policy` with `--policy-type IDENTITY_POLICY` on every JSON file under
`policies/` and fails on `ERROR` or `SECURITY_WARNING` findings. You must add the step that gives
the job AWS credentials and a Region. It reads JSON policy files, not Terraform or CloudFormation.
CloudShield has not checked that Access Analyzer flags every wildcard or privilege-escalation
pattern the rules look for. The AWS pricing page says policy validation is provided at no
additional charge.

**Set a permissions boundary** (`iam-permissions-boundary`). Caps what a role can ever do. You
write the boundary policy yourself, because a boundary grants nothing and a good one needs real
usage data. CLI (`aws iam put-role-permissions-boundary`), Terraform (`permissions_boundary`) and
CloudFormation (`PermissionsBoundary`); the last two are instructions to add one argument to your
existing role. It cannot be set on a service-linked role. Cost: check pricing.

**AWS Config rules** (`config-s3-bucket-versioning-enabled`, `config-incoming-ssh-disabled`,
`config-iam-no-admin-access`). Managed rules `S3_BUCKET_VERSIONING_ENABLED`,
`INCOMING_SSH_DISABLED` and `IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS`. They only report: they
block nothing. They need the AWS Config configuration recorder to be running. The admin-access rule
checks customer managed policies for `Action "*"` on `Resource "*"` only, so it is narrower than
`CIS-IAM-001`. The AWS Config pricing page lists $0.003 per continuous configuration item recorded
and $0.001 per rule evaluation for the first 100,000 (its examples use US East (N. Virginia)). Check
pricing for your Region.

## Left out, and why

- **AWS Config rules for the account-wide public access block** (such as the managed rule for
  account-level blocks): the exact rule identifier was not read.
- **Service control policies** that deny turning the account-wide block off: no AWS page was read
  that gives a tested statement for it.
- **A Terraform resource for the organization S3 policy:** its argument names were not checked.
- **Permissions boundary policy text:** a safe one needs your real usage data.
- **Detective or pipeline checks for KMS encryption** (`CIS-S3-002`): the rule is informational.

## Export

`python -m cloudshield.fixes export <finding_id> --dir fixes-out` writes the fix files and then
one folder per guardrail under `fixes-out/guardrails/<id>/`. A `workflow.yml` is a ready-to-copy
GitHub Actions file: save it as `.github/workflows/<name>.yml` in your repository. Every file except
the small JSON helper files starts with a review header, and nothing is run.
