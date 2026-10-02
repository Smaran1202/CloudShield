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
  Some Get actions can still expose sensitive data, for example `secretsmanager:GetSecretValue`
  or `s3:GetObject` on every bucket, and are not flagged. Statements that use `NotAction` or
  `NotResource` are skipped.
- SX-IAM-PRIVESC-001 gives one finding per policy or role, listing every matched method. It
  checks the 15 methods in its list from the Rhino Security Labs catalogue. The catalogue has 21
  methods; the rest (for example Glue, CloudFormation and Data Pipeline) are not checked. It does
  not evaluate permission boundaries, service control policies or resource policies. Only an
  unconditional Deny on all resources cancels a grant. A role is skipped when any of its policies
  could not be read. A policy with Action "*" is also reported by CIS-IAM-001, and its privesc
  finding says that a full wildcard implies all methods.
