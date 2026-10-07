# Limitations

## What has been verified against a real AWS account

- S3 buckets, security groups and customer-managed IAM policies were scanned in a real account
  with 0 errors.
- EC2 and security group data was verified against a real account only in `ap-southeast-2`.
  An organization rule in that account blocks EC2 in every other region, so no other region has
  been checked.
- EC2 instance data is verified only with mocks (moto). The instance fields (state, security
  groups, public IP, instance profile) have not been checked against real output.
- IAM roles are collected only for instance profiles attached to instances, so role collection
  is also verified only with mocks.

## Rules

- A missing key in a resource's `attributes` means a call failed and the value is unknown. Rules
  never report a finding for an unknown value.
- CIS-S3-002 is INFO and does not count toward risk. It reports buckets that do not use SSE-KMS.
  S3 encrypts every new bucket with SSE-S3 by default, so a bucket with no encryption at all is
  almost never real.
- CIS-IAM-001 only looks at customer-managed policies. Action "*" is HIGH. Resource "*" is
  MEDIUM and is flagged only when an allowed action is not read-only. Read-only means the action
  starts with Get, List or Describe, or is one of a short allowlist (`dynamodb:Query`,
  `dynamodb:Scan`, `dynamodb:BatchGetItem`, `logs:FilterLogEvents`, `cloudtrail:LookupEvents`).
  These Get actions are never read-only: `secretsmanager:GetSecretValue`, `ssm:GetParameter`,
  `ssm:GetParameters`, `ssm:GetParametersByPath`, `ec2:GetPasswordData` and `s3:GetObject`.
  A wildcard that includes one of them, such as `s3:Get*`, counts too. The list is short, so
  other Get actions that return sensitive data (for example `s3:GetObjectVersion`) are still
  treated as read-only. Statements that use `NotAction` or `NotResource` are skipped.
- SX-IAM-PRIVESC-001 gives one finding per policy or role, listing every matched method. It
  checks the 15 methods in its list from the Rhino Security Labs catalogue. The catalogue has 21
  methods; the rest (for example Glue, CloudFormation and Data Pipeline) are not checked. It does
  not evaluate permission boundaries, service control policies or resource policies. Only an
  unconditional Deny on all resources cancels a grant. A role is skipped when any of its policies
  could not be read. A policy with Action "*" is also reported by CIS-IAM-001, and its privesc
  finding says that a full wildcard implies all methods.

## Scans and stored results

- A finding is marked RESOLVED only when the scanner service for its resource type (`s3`, `ec2` or
  `iam`) returned no errors in that scan. One error anywhere in a service, in any region, stops
  all findings of that service from being resolved in that scan, even for resources that were
  scanned fine.
- Findings on EC2 instances and security groups are resolved only if the resource's region was
  part of the scan.
- A finding on an IAM role is never resolved as "resource not found", because roles are only
  found through instances. It can be resolved as "no longer detected" while the role is still
  returned by the scan.
- Resources that disappear are not deleted from the resources table; it keeps the latest known
  state, and `last_seen_scan_id` shows when it was last seen.
- Only one scan can run at a time. This is enforced inside one server process, so run a single
  API process. A scan left unfinished by a crash is marked failed when the server starts again.
- There are no accounts or logins yet; every row has `account_id` "local".

## Risk scores

- The attached factor only looks at EC2 instances. A security group used by a load balancer, a
  database or a Lambda function can still be reported as not attached.
- If any EC2 error occurs in a scan, or the group's region was not scanned, the attached factor is
  unknown for every security group in that scan.
- A policy attached only to a group counts as attached, because the group's members get its
  permissions. Whether the group has any members is not checked.
- Only customer-managed policies have attachment data. Roles get no privilege factor.
- Exposure is configuration only: route tables, network ACLs and other controls are not checked.
- Findings from a previous scan that were not detected again are not rescored. Findings stored
  before the risk migration have no score or evidence until the next scan sees them again.
- `severity_counts` counts every open finding, including INFO. The environment score does not.

## Fixes

- CloudShield never writes to AWS and never runs a generated command. A fix is text. The export
  command writes it to files for you to review and apply yourself.
- Patches use only values from the scan: bucket name, group id, region and the open rule. Names are
  checked against a strict pattern, and anything else is refused instead of being quoted.
- The Terraform and CloudFormation patches for S3 describe the setting for the named bucket. If
  the bucket is not managed by that tool, you have to import it or adapt the patch. For security
  groups they are instructions, not code, because the existing definition is not known.
- The AWS CLI patch for a security group uses a JSON file with the exact rule, so it works for
  port ranges, all protocols and IPv6. It removes only the open address range from that rule.
- Findings for IAM policies and roles have guidance only, no patch.
- Blast radius uses stored data only. Website hosting, ACLs, flow logs, CloudTrail and
  last-accessed data are not collected, so those parts are unknown, and unknown is never reported
  as low. Running instances are taken from the scan that last saw the finding.
- The AI explanation is optional text. It is checked against the data, but not every invented name
  can be detected. See `ai-data.md`.
- The hourly AI limit is counted in the memory of one server process and starts again when the
  server restarts.

## Imported findings (Prowler)

- Imported findings come from an output file that you produce. CloudShield did not collect the
  evidence, so every evidence item built from Prowler's text has the certainty "reported", and
  imported findings never show "verified".
- Only Prowler 5.44.0 output (JSON-OCSF, OCSF 1.5.0) has been checked, using one redacted sample
  with s3, ec2 and iam checks in `ap-southeast-2`. Other versions are accepted if their OCSF major
  version is 1, but their fields have not been checked.
- The base score comes from the severity alone (CRITICAL 90, HIGH 70, MEDIUM 40, LOW 20). Our own
  context (exposure, attachment, privilege) is added only when the same resource id is in our own
  scanned resources. Otherwise the finding has one risk factor, "context not available for
  imported findings", with adjustment 0 and certainty unknown. The lanes are unchanged, so an
  imported HIGH finding scores 70 and lands in Next unless our own context raises it. Imported
  INFO findings have no score. The score is worked out at import time and is not refreshed by a
  later scan.
- Resources are matched only for S3 buckets, security groups, EC2 instances, IAM policies and IAM
  roles. Account-level findings (the account, the root user, the password policy) get the type
  "Account" and are never matched.
- A finding is resolved only when a newer import shows the same check and resource as PASS.
  A finding that a newer import does not mention stays open and is labelled "not rechecked", with
  the date of the last import that covered it. The one exception is a resource our own latest
  completed scan, with no errors for that service, no longer finds. That resolves it with the
  reason "resource no longer exists". It is never applied to IAM roles, to policies owned by AWS,
  to a resource we never scanned, or to a security group in a region that scan did not cover.
- Imported findings have no patch templates and no AI explanation. The blast radius is always
  unknown. The fix view shows Prowler's remediation text and links.
- The title of an imported failure is the scanner's own failing statement, or "Failed: " and the
  check's title when there is none. The check's own title describes the passing state, so it is
  kept only in the details. All evidence from an import has the certainty "reported" and the
  source "imported scan output".
- Only two checks are treated as the same as one of our rules (see `imports/mapping.py`):
  `s3_bucket_level_public_access_block` with CIS-S3-001 and `s3_bucket_object_versioning` with
  CIS-S3-003. When both fail on the same resource, our finding stays and the imported one is
  merged into it: it is left out of every list, count and score, and ours shows "corroborated by"
  and an extra "also reported by an imported scan" evidence item. When the two disagree, both
  stay visible and are flagged `tools_disagree`. Our scan counts as "passing" when it stored the
  resource and has no open finding for the rule. When our side has no data, the two results are
  never compared: that is when the resource lacks the attribute the rule needs (the call that
  reads it failed), or when our latest completed scan reported an error for that service. Then
  nothing is merged or flagged, both findings stay, and each gets the evidence item "CloudShield
  could not read this setting, so the two results are not compared." The comparison is made
  again after the next scan that reads the setting. Partial matches, such as the IAM wildcard check, never merge. Every other pair of
  imported and own findings is shown twice, each with its source.
- A finding can be dismissed as accepted or not applicable, with a reason of at least 10
  characters and an optional end date (valid through the end of that day, UTC). It then leaves
  the lanes, the headline counts and the risk summary, and stays in the list with its reason. An
  expired disposition makes the finding open again. The environment score stored on a scan is
  fixed when the scan finishes, so a later dismissal changes it only in the live risk summary.
- CloudShield only suggests "not applicable" (AWS-managed policies, service-linked roles, and
  names in `CLOUDSHIELD_OWN_IDENTITIES`). It never dismisses anything by itself.
- `score_basis` says whether a score used our own context ("context adjusted") or the severity
  only. A security group and a policy are scored with context only when the same resource id is
  in our own scanned resources.
- Imported resources that we did not scan are listed at `GET /api/resources/imported`, separately
  from `GET /api/resources`.
- Each import keeps its file's base name, the tool name and version from the file, and its pass
  and fail counts. Imports made before this was added show these as empty.
- A file is identified by its SHA-256. The same file is refused for the same account id, but a
  file with one extra space is a different file.
