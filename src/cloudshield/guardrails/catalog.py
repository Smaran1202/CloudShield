import json

from cloudshield.fixes.templates import aws_command, patch

# What stops a finding coming back, for each of our own rules. Everything here is text for the
# owner to read and apply. Each AWS name, command and setting was read in the AWS documentation
# on 2026-11-02; the docs_url of a guardrail is the page it was read from. Anything that could not
# be checked is left out, and the notes say so where it matters.
#
# kind: account_setting, pipeline_check, detective_rule or organization_policy
# scope: resource, account or organization
# reads: the account setting our scan reads to say whether it is active, or None when CloudShield
# cannot see it.

ACCOUNT_ID_INPUT = "Your 12-digit AWS account id"
ACCOUNT_ID_PLACEHOLDER = "REPLACE_WITH_YOUR_ACCOUNT_ID"
BLOCK_ALL = (
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
)
CONFIG_COST = (
    "The AWS Config pricing page lists $0.003 per continuous configuration item recorded and "
    "$0.001 per rule evaluation for the first 100,000 evaluations (its examples use US East "
    "(N. Virginia)). Check pricing for your Region."
)
CONFIG_AFFECTS = (
    "Only reports resources that break the rule. It does not block or change anything. It "
    "needs the AWS Config configuration recorder to be running in the account."
)
CHECKOV_COST = (
    "Checkov is free open-source software (Apache-2.0). Your CI provider bills its own minutes."
)
CHECKOV_AFFECTS = (
    "A pull request that adds a resource breaking the check fails its build. It reads your "
    "Terraform and CloudFormation files only, so resources made in the console or with other "
    "tools are not seen."
)


def checkov_workflow(title: str, check_id: str) -> str:
    return (
        f"name: {title}\n"
        "on:\n"
        "  pull_request:\n"
        "jobs:\n"
        "  checkov:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - name: Install Checkov\n"
        "        run: pip install checkov\n"
        "      - name: Check the infrastructure code\n"
        f"        run: checkov -d . --check {check_id} --hard-fail-on {check_id}\n"
    )


VALIDATE_POLICY_WORKFLOW = (
    "name: Validate IAM policies\n"
    "on:\n"
    "  pull_request:\n"
    "jobs:\n"
    "  validate-policies:\n"
    "    runs-on: ubuntu-latest\n"
    "    steps:\n"
    "      - uses: actions/checkout@v4\n"
    "      # Add a step here that gives this job AWS credentials and a Region. Validation needs\n"
    "      # permission to call IAM Access Analyzer.\n"
    "      - name: Validate every policy file with IAM Access Analyzer\n"
    "        run: |\n"
    "          status=0\n"
    "          for file in policies/*.json; do\n"
    '            count=$(aws accessanalyzer validate-policy --policy-document "file://$file" '
    "--policy-type IDENTITY_POLICY --query "
    "\"length(findings[?findingType=='ERROR' || findingType=='SECURITY_WARNING'])\" "
    "--output text)\n"
    '            echo "$file: $count errors or security warnings"\n'
    '            if [ "$count" != "0" ]; then status=1; fi\n'
    "          done\n"
    "          exit $status\n"
)


def config_rule(slug: str, identifier: str, label: str, logical: str) -> list[dict]:
    file_name = f"config-rule-{slug}.json"
    document = {
        "ConfigRuleName": slug,
        "Source": {"Owner": "AWS", "SourceIdentifier": identifier},
    }
    terraform = (
        f'resource "aws_config_config_rule" "{label}" {{\n'
        f'  name = "{slug}"\n'
        "\n"
        "  source {\n"
        '    owner             = "AWS"\n'
        f'    source_identifier = "{identifier}"\n'
        "  }\n"
        "}\n"
    )
    cloudformation = (
        "Resources:\n"
        f"  {logical}:\n"
        "    Type: AWS::Config::ConfigRule\n"
        "    Properties:\n"
        f"      ConfigRuleName: {slug}\n"
        "      Source:\n"
        "        Owner: AWS\n"
        f"        SourceIdentifier: {identifier}\n"
    )
    cli = aws_command("configservice put-config-rule", {"config-rule": f"file://{file_name}"}, None)
    files = [{"name": file_name, "content": json.dumps(document, indent=2) + "\n"}]
    return [
        patch("terraform", "Add the AWS Config rule (Terraform)", terraform),
        patch("cloudformation", "Add the AWS Config rule (CloudFormation)", cloudformation),
        patch("cli", "Add the AWS Config rule (AWS CLI)", cli + "\n", files=files),
    ]


def account_block_patches() -> list[dict]:
    terraform = (
        'resource "aws_s3_account_public_access_block" "account" {\n'
        "  block_public_acls       = true\n"
        "  block_public_policy     = true\n"
        "  ignore_public_acls      = true\n"
        "  restrict_public_buckets = true\n"
        "}\n"
    )
    options = {
        "account-id": ACCOUNT_ID_PLACEHOLDER,
        "public-access-block-configuration": f'"{BLOCK_ALL}"',
    }
    cli = aws_command("s3control put-public-access-block", options, None)
    return [
        patch("terraform", "Block public access for the whole account (Terraform)", terraform),
        patch(
            "cli",
            "Block public access for the whole account (AWS CLI)",
            cli + "\n",
            inputs_needed=[ACCOUNT_ID_INPUT],
        ),
    ]


def organization_block_patches() -> list[dict]:
    file_name = "s3-block-public-access-policy.json"
    document = {"s3_attributes": {"public_access_block_configuration": {"@@assign": "all"}}}
    enable = aws_command(
        "organizations enable-policy-type",
        {"root-id": "REPLACE_WITH_ROOT_ID", "policy-type": "S3_POLICY"},
        None,
    )
    create = aws_command(
        "organizations create-policy",
        {
            "name": "block-public-access",
            "description": '"Block public access for S3"',
            "type": "S3_POLICY",
            "content": f"file://{file_name}",
        },
        None,
    )
    attach = aws_command(
        "organizations attach-policy",
        {"policy-id": "REPLACE_WITH_POLICY_ID", "target-id": "REPLACE_WITH_TARGET_ID"},
        None,
    )
    content = (
        "# Run the first command only if the S3 policy type is not enabled yet.\n"
        f"{enable}\n"
        f"{create}\n"
        "# Use the policy id that create-policy printed.\n"
        f"{attach}\n"
    )
    files = [{"name": file_name, "content": json.dumps(document, indent=2) + "\n"}]
    return [
        patch(
            "cli",
            "Block public access across the organization (AWS CLI)",
            content,
            files=files,
            inputs_needed=[
                "The id of the organization root",
                "The id of the organization, OU or account to attach the policy to",
            ],
        )
    ]


def boundary_patches() -> list[dict]:
    needed = ["The role to limit", "The ARN of the managed policy to use as the boundary"]
    cli = aws_command(
        "iam put-role-permissions-boundary",
        {
            "role-name": "REPLACE_WITH_ROLE_NAME",
            "permissions-boundary": "REPLACE_WITH_BOUNDARY_POLICY_ARN",
        },
        None,
    )
    terraform = (
        "Add this argument to the aws_iam_role resource of the role: "
        'permissions_boundary = "REPLACE_WITH_BOUNDARY_POLICY_ARN". Run terraform plan and check '
        "that only this change is made before applying.\n"
    )
    cloudformation = (
        "Add this property to the AWS::IAM::Role resource of the role: "
        "PermissionsBoundary: REPLACE_WITH_BOUNDARY_POLICY_ARN. Review the change set before "
        "executing it.\n"
    )
    return [
        patch(
            "terraform",
            "Set a permissions boundary (Terraform)",
            terraform,
            inputs_needed=needed,
            instructions_only=True,
        ),
        patch(
            "cloudformation",
            "Set a permissions boundary (CloudFormation)",
            cloudformation,
            inputs_needed=needed,
            instructions_only=True,
        ),
        patch(
            "cli",
            "Set a permissions boundary (AWS CLI)",
            cli + "\n",
            inputs_needed=needed,
        ),
    ]


def guardrail(
    id: str,
    title: str,
    kind: str,
    prevents: str,
    scope: str,
    patches: list[dict],
    affects: str,
    cost: str,
    docs_url: str,
    reads: str | None = None,
) -> dict:
    return {
        "id": id,
        "title": title,
        "kind": kind,
        "prevents": prevents,
        "scope": scope,
        "patches": patches,
        "affects": affects,
        "cost": cost,
        "docs_url": docs_url,
        "reads": reads,
    }


CONFIG_DOCS = "https://docs.aws.amazon.com/config/latest/developerguide"
IAM_DOCS = "https://docs.aws.amazon.com/IAM/latest/UserGuide"
S3_DOCS = "https://docs.aws.amazon.com/AmazonS3/latest/userguide"
ORGANIZATIONS_DOCS = "https://docs.aws.amazon.com/organizations/latest/userguide"

GUARDRAILS = {
    g["id"]: g
    for g in [
        guardrail(
            "s3-account-block-public-access",
            "Block public access for the whole account",
            "account_setting",
            "Stops any bucket in the account, current or future, from being made public by an "
            "ACL or a bucket policy, even if its own settings are off.",
            "account",
            account_block_patches(),
            "Applies to every bucket in the account, in all Regions. It does not change "
            "existing policies or ACLs, but a bucket that relies on public access, such as a "
            "static website, stops serving it.",
            "Check pricing.",
            f"{S3_DOCS}/access-control-block-public-access.html",
            reads="s3_public_access_block",
        ),
        guardrail(
            "s3-organization-block-public-access",
            "Block public access across the organization",
            "organization_policy",
            "Does the same for every selected account in an AWS Organization, and stops "
            "account-level changes from undoing it.",
            "organization",
            organization_block_patches(),
            "Overrides the account-level settings of the accounts it is attached to. It needs "
            "your organization's management account, and Block Public Access calls made at "
            "account level can then be refused.",
            "Check pricing.",
            f"{ORGANIZATIONS_DOCS}/orgs_manage_policies_s3.html",
        ),
        guardrail(
            "pipeline-s3-versioning",
            "Reject buckets without versioning in your pipeline",
            "pipeline_check",
            "Fails a pull request that adds a bucket without versioning.",
            "resource",
            [
                patch(
                    "github_actions",
                    "Check bucket versioning with Checkov (GitHub Actions)",
                    checkov_workflow("CloudShield check S3 versioning", "CKV_AWS_21"),
                )
            ],
            CHECKOV_AFFECTS,
            CHECKOV_COST,
            f"{CONFIG_DOCS}/s3-bucket-versioning-enabled.html",
        ),
        guardrail(
            "config-s3-bucket-versioning-enabled",
            "Report buckets without versioning (AWS Config)",
            "detective_rule",
            "Reports a bucket that has versioning off, so it is seen soon after it appears.",
            "account",
            config_rule(
                "s3-bucket-versioning-enabled",
                "S3_BUCKET_VERSIONING_ENABLED",
                "s3_bucket_versioning_enabled",
                "S3BucketVersioningEnabled",
            ),
            CONFIG_AFFECTS,
            CONFIG_COST,
            f"{CONFIG_DOCS}/s3-bucket-versioning-enabled.html",
        ),
        guardrail(
            "pipeline-sg-no-open-ssh",
            "Reject open SSH in your pipeline",
            "pipeline_check",
            "Fails a pull request that allows SSH (port 22) from 0.0.0.0/0 or ::/0.",
            "resource",
            [
                patch(
                    "github_actions",
                    "Check for open SSH with Checkov (GitHub Actions)",
                    checkov_workflow("CloudShield check open SSH", "CKV_AWS_24"),
                )
            ],
            CHECKOV_AFFECTS,
            CHECKOV_COST,
            f"{CONFIG_DOCS}/restricted-ssh.html",
        ),
        guardrail(
            "config-incoming-ssh-disabled",
            "Report open SSH (AWS Config)",
            "detective_rule",
            "Reports a security group that allows SSH from 0.0.0.0/0 or ::/0.",
            "account",
            config_rule(
                "restricted-ssh",
                "INCOMING_SSH_DISABLED",
                "restricted_ssh",
                "RestrictedSsh",
            ),
            CONFIG_AFFECTS,
            CONFIG_COST,
            f"{CONFIG_DOCS}/restricted-ssh.html",
        ),
        guardrail(
            "pipeline-iam-validate-policy",
            "Validate IAM policies in your pipeline",
            "pipeline_check",
            "Fails a pull request whose policy files have errors or overly permissive "
            "statements, as IAM Access Analyzer judges them.",
            "resource",
            [
                patch(
                    "github_actions",
                    "Validate policy files with IAM Access Analyzer (GitHub Actions)",
                    VALIDATE_POLICY_WORKFLOW,
                )
            ],
            "Reads JSON policy files under policies/ in your repository, not Terraform or "
            "CloudFormation. It needs AWS credentials in the pipeline. CloudShield has not "
            "checked that every wildcard or privilege escalation pattern is flagged.",
            "The AWS pricing page says policy validation is provided at no additional charge.",
            f"{IAM_DOCS}/access-analyzer-policy-validation.html",
        ),
        guardrail(
            "iam-permissions-boundary",
            "Set a permissions boundary on the role",
            "account_setting",
            "Caps the permissions a role can ever use, so a policy added later cannot grant "
            "more than the boundary allows.",
            "resource",
            boundary_patches(),
            "A boundary grants nothing by itself. You must write the boundary policy yourself, "
            "and anything outside it stops working for that role. It cannot be set on a "
            "service-linked role.",
            "Check pricing.",
            f"{IAM_DOCS}/access_policies_boundaries.html",
        ),
        guardrail(
            "config-iam-no-admin-access",
            "Report policies that allow everything (AWS Config)",
            "detective_rule",
            "Reports a customer managed policy that allows all actions on all resources.",
            "account",
            config_rule(
                "iam-policy-no-statements-with-admin-access",
                "IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS",
                "iam_policy_no_admin_access",
                "IamPolicyNoAdminAccess",
            ),
            "Only reports. It checks customer managed policies for Action * on Resource *, which "
            "is narrower than our rule: inline policies and AWS managed policies are not "
            "evaluated. " + CONFIG_AFFECTS,
            CONFIG_COST,
            f"{CONFIG_DOCS}/iam-policy-no-statements-with-admin-access.html",
        ),
    ]
}

IAM_RULE = [
    "pipeline-iam-validate-policy",
    "iam-permissions-boundary",
]

BY_RULE = {
    "CIS-S3-001": ["s3-account-block-public-access", "s3-organization-block-public-access"],
    "CIS-S3-003": ["pipeline-s3-versioning", "config-s3-bucket-versioning-enabled"],
    "CIS-SG-001": ["pipeline-sg-no-open-ssh", "config-incoming-ssh-disabled"],
    "CIS-IAM-001": [*IAM_RULE, "config-iam-no-admin-access"],
    "SX-IAM-PRIVESC-001": IAM_RULE,
}


def guardrails_for(rule_id: str) -> list[dict]:
    return [GUARDRAILS[guardrail_id] for guardrail_id in BY_RULE.get(rule_id, [])]
