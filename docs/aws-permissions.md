# AWS permissions for the scanner

The scanner only reads. The policy in `aws-readonly-policy.json` allows exactly the actions
below and nothing that creates, changes or deletes anything. It does not allow reading object
contents, and it does not allow `sts` calls beyond the default `sts:GetCallerIdentity`, which
needs no permission.

| Area | Boto3 call | IAM action | Used for |
|---|---|---|---|
| S3 | `list_buckets` | `s3:ListAllMyBuckets` | list the buckets |
| S3 | `get_bucket_location` | `s3:GetBucketLocation` | the bucket's region |
| S3 | `get_public_access_block` | `s3:GetBucketPublicAccessBlock` | public access block settings |
| S3 | `get_bucket_encryption` | `s3:GetEncryptionConfiguration` | default encryption |
| S3 | `get_bucket_versioning` | `s3:GetBucketVersioning` | versioning status |
| S3 | `get_bucket_policy` | `s3:GetBucketPolicy` | the bucket policy |
| EC2 | `describe_instances` | `ec2:DescribeInstances` | instances, their security groups, public IP, instance profile |
| EC2 | `describe_security_groups` | `ec2:DescribeSecurityGroups` | security group rules |
| IAM | `list_policies` (local only) | `iam:ListPolicies` | customer-managed policies |
| IAM | `get_policy_version` | `iam:GetPolicyVersion` | policy documents |
| IAM | `get_policy` | `iam:GetPolicy` | default version of policies attached to a role |
| IAM | `get_instance_profile` | `iam:GetInstanceProfile` | the roles inside an instance profile |
| IAM | `list_attached_role_policies` | `iam:ListAttachedRolePolicies` | managed policies on a role |
| IAM | `list_role_policies` | `iam:ListRolePolicies` | names of inline policies on a role |
| IAM | `get_role_policy` | `iam:GetRolePolicy` | inline policy documents |

If a call is denied the scanner does not stop. It records an error entry and the result shows
which action was missing, so a denied action is never reported as "nothing there".

## Create the user and profile

Do this yourself in your own AWS account. Run the commands in PowerShell, with an administrator
profile that can create IAM users.

1. Create the policy from the file in this folder:

   ```powershell
   aws iam create-policy --policy-name CloudShieldReadOnly --policy-document file://docs/aws-readonly-policy.json
   ```

   Note the policy `Arn` in the output.

2. Create the user and attach the policy (replace `ACCOUNT_ID` with your 12-digit account id):

   ```powershell
   aws iam create-user --user-name cloudshield-scanner
   aws iam attach-user-policy --user-name cloudshield-scanner --policy-arn arn:aws:iam::ACCOUNT_ID:policy/CloudShieldReadOnly
   ```

3. Create an access key. The output shows the secret once. Do not paste it anywhere, and do not
   commit it:

   ```powershell
   aws iam create-access-key --user-name cloudshield-scanner
   ```

4. Save it as a named profile. `aws configure` asks for the access key id, the secret and a
   default region:

   ```powershell
   aws configure --profile cloudshield
   ```

5. Check that the profile works:

   ```powershell
   aws sts get-caller-identity --profile cloudshield
   ```

   The `Arn` should end with `user/cloudshield-scanner`.

## Run a scan

```powershell
.\.venv\Scripts\Activate.ps1
python -m cloudshield.scanner --profile cloudshield --regions us-east-1 --out scan-output.json
```

`--regions` takes a comma separated list. Without it the scanner uses `AWS_REGION`, then the
profile's region. `scan-output*.json` is ignored by git because it contains real account details.