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
