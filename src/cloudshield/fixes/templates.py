import json
import re

# Values from a scan go into commands, so anything that is not a plain id, name or region is
# refused instead of quoted.
SAFE_VALUE = re.compile(r"^[A-Za-z0-9._-]+$")
PLACEHOLDER_KMS_KEY = "REPLACE_WITH_YOUR_KMS_KEY_ARN"
VERIFY = "Rescan (POST /api/scans). This finding should resolve."
BLOCK_NAMES = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


def safe(value: str) -> str:
    if not SAFE_VALUE.match(value):
        raise ValueError(f"Refusing to put this value in a command: {value!r}")
    return value


def terraform_label(name: str) -> str:
    label = re.sub(r"[^A-Za-z0-9_]", "_", name)
    return label if label[0].isalpha() or label[0] == "_" else f"bucket_{label}"


def logical_id(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "", name.title()) or "Bucket"


def aws_command(name: str, options: dict[str, str], region: str | None) -> str:
    # One line, no continuation characters: it has to work in PowerShell 5.1 and in bash.
    words = ["aws", name]
    for flag, value in options.items():
        words += [f"--{flag}", value]
    if region:
        words += ["--region", safe(region)]
    return " ".join(words)


def patch(
    kind: str,
    title: str,
    content: str,
    files: list[dict] | None = None,
    inputs_needed: list[str] | None = None,
    instructions_only: bool = False,
) -> dict:
    return {
        "format": kind,
        "title": title,
        "content": content,
        "files": files or [],
        "needs_input": bool(inputs_needed),
        "inputs_needed": inputs_needed or [],
        "instructions_only": instructions_only,
    }


def fix(patches: list[dict], guidance: list[str], pre_checks: list[str], rollback: str) -> dict:
    return {
        "patches": patches,
        "guidance": guidance,
        "pre_checks": pre_checks,
        "rollback": rollback,
        "verify": VERIFY,
    }


def public_access_block_fix(finding: dict, resource: dict) -> dict:
    bucket = safe(resource["resource_id"])
    region = resource["region"]
    label = terraform_label(bucket)
    terraform = (
        f'resource "aws_s3_bucket_public_access_block" "{label}" {{\n'
        f'  bucket                  = "{bucket}"\n'
        "  block_public_acls       = true\n"
        "  block_public_policy     = true\n"
        "  ignore_public_acls      = true\n"
        "  restrict_public_buckets = true\n"
        "}\n"
    )
    cloudformation = (
        "Resources:\n"
        f"  {logical_id(bucket)}:\n"
        "    Type: AWS::S3::Bucket\n"
        "    Properties:\n"
        f"      BucketName: {bucket}\n"
        "      PublicAccessBlockConfiguration:\n"
        "        BlockPublicAcls: true\n"
        "        BlockPublicPolicy: true\n"
        "        IgnorePublicAcls: true\n"
        "        RestrictPublicBuckets: true\n"
    )
    all_on = ",".join(f"{name}=true" for name in BLOCK_NAMES)
    cli = aws_command(
        "s3api put-public-access-block",
        {"bucket": bucket, "public-access-block-configuration": f'"{all_on}"'},
        region,
    )

    before = finding["details"]["public_access_block"]
    if before is None:
        undo = aws_command("s3api delete-public-access-block", {"bucket": bucket}, region)
        rollback = f"The bucket had no public access block. To remove it again: {undo}"
    else:
        old = ",".join(f"{name}={str(bool(before.get(name))).lower()}" for name in BLOCK_NAMES)
        undo = aws_command(
            "s3api put-public-access-block",
            {"bucket": bucket, "public-access-block-configuration": f'"{old}"'},
            region,
        )
        rollback = f"To restore the settings the bucket had before: {undo}"

    patches = [
        patch("terraform", "Block all public access (Terraform)", terraform),
        patch("cloudformation", "Block all public access (CloudFormation)", cloudformation),
        patch("cli", "Block all public access (AWS CLI)", cli + "\n"),
    ]
    pre_checks = [
        "Read the bucket policy and the blast radius: a public allow statement stops working "
        "once public policies are blocked.",
        "Check whether the bucket hosts a static website or is a public origin, because public "
        "reads will stop.",
        "Check that nothing relies on anonymous access to objects in this bucket.",
    ]
    return fix(patches, [], pre_checks, rollback)


def versioning_fix(finding: dict, resource: dict) -> dict:
    bucket = safe(resource["resource_id"])
    region = resource["region"]
    label = terraform_label(bucket)
    terraform = (
        f'resource "aws_s3_bucket_versioning" "{label}" {{\n'
        f'  bucket = "{bucket}"\n'
        "\n"
        "  versioning_configuration {\n"
        '    status = "Enabled"\n'
        "  }\n"
        "}\n"
    )
    cloudformation = (
        "Resources:\n"
        f"  {logical_id(bucket)}:\n"
        "    Type: AWS::S3::Bucket\n"
        "    Properties:\n"
        f"      BucketName: {bucket}\n"
        "      VersioningConfiguration:\n"
        "        Status: Enabled\n"
    )
    cli = aws_command(
        "s3api put-bucket-versioning",
        {"bucket": bucket, "versioning-configuration": "Status=Enabled"},
        region,
    )
    suspend = aws_command(
        "s3api put-bucket-versioning",
        {"bucket": bucket, "versioning-configuration": "Status=Suspended"},
        region,
    )
    rollback = (
        "Versioning cannot be switched off once it is enabled, only suspended: "
        f"{suspend} Versions that were already created are kept and keep using storage until "
        "they are deleted."
    )
    patches = [
        patch("terraform", "Enable versioning (Terraform)", terraform),
        patch("cloudformation", "Enable versioning (CloudFormation)", cloudformation),
        patch("cli", "Enable versioning (AWS CLI)", cli + "\n"),
    ]
    pre_checks = [
        "Plan a lifecycle rule for old versions, because every overwrite or delete keeps the "
        "old version and storage cost grows.",
        "Check that no tool using this bucket breaks when the bucket is versioned.",
    ]
    return fix(patches, [], pre_checks, rollback)


def kms_encryption_fix(finding: dict, resource: dict) -> dict:
    bucket = safe(resource["resource_id"])
    region = resource["region"]
    label = terraform_label(bucket)
    needed = ["The ARN of the KMS key to use for default encryption"]
    terraform = (
        f'resource "aws_s3_bucket_server_side_encryption_configuration" "{label}" {{\n'
        f'  bucket = "{bucket}"\n'
        "\n"
        "  rule {\n"
        "    apply_server_side_encryption_by_default {\n"
        '      sse_algorithm     = "aws:kms"\n'
        f'      kms_master_key_id = "{PLACEHOLDER_KMS_KEY}"\n'
        "    }\n"
        "  }\n"
        "}\n"
    )
    file_name = f"sse-kms-{bucket}.json"
    document = {
        "Rules": [
            {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "aws:kms",
                    "KMSMasterKeyID": PLACEHOLDER_KMS_KEY,
                }
            }
        ]
    }
    cli = aws_command(
        "s3api put-bucket-encryption",
        {"bucket": bucket, "server-side-encryption-configuration": f"file://{file_name}"},
        region,
    )
    files = [{"name": file_name, "content": json.dumps(document, indent=2) + "\n"}]
    patches = [
        patch(
            "terraform",
            "Use a KMS key for default encryption (Terraform)",
            terraform,
            inputs_needed=needed,
        ),
        patch(
            "cli",
            "Use a KMS key for default encryption (AWS CLI)",
            cli + "\n",
            files=files,
            inputs_needed=needed,
        ),
    ]
    pre_checks = [
        "Choose or create the KMS key, and check that every role and user that reads or writes "
        "this bucket is allowed to use it.",
        "Replace the placeholder with the key ARN before applying.",
    ]
    rollback = (
        "Set the default encryption back to SSE-S3 (AES256). Objects written while the KMS key "
        "was the default stay encrypted with that key."
    )
    return fix(patches, [], pre_checks, rollback)


def describe_rule(rule: dict) -> str:
    if rule["protocol"] == "-1":
        return "all ports and protocols"
    ports = f"{rule['from_port']}-{rule['to_port']}"
    if rule["from_port"] == rule["to_port"]:
        ports = str(rule["from_port"])
    return f"protocol {rule['protocol']}, port {ports}"


def permission_for(rule: dict) -> dict:
    permission = {"IpProtocol": rule["protocol"]}
    if rule["protocol"] != "-1":
        permission["FromPort"] = rule["from_port"]
        permission["ToPort"] = rule["to_port"]
    ipv4 = [cidr for cidr in rule["cidrs"] if ":" not in cidr]
    ipv6 = [cidr for cidr in rule["cidrs"] if ":" in cidr]
    if ipv4:
        permission["IpRanges"] = [{"CidrIp": cidr} for cidr in ipv4]
    if ipv6:
        permission["Ipv6Ranges"] = [{"CidrIpv6": cidr} for cidr in ipv6]
    return permission


def open_security_group_fix(finding: dict, resource: dict) -> dict:
    group = safe(resource["resource_id"])
    region = resource["region"]
    lines, undo_commands, files, summaries = [], [], [], []
    for number, rule in enumerate(finding["details"]["rules"], start=1):
        file_name = f"{group}-rule{number}.json"
        content = json.dumps([permission_for(rule)], indent=2) + "\n"
        files.append({"name": file_name, "content": content})
        options = {"group-id": group, "ip-permissions": f"file://{file_name}"}
        summary = f"{describe_rule(rule)} from {', '.join(rule['cidrs'])}"
        summaries.append(summary)
        lines.append(f"# Rule {number}: {summary}")
        lines.append(aws_command("ec2 revoke-security-group-ingress", options, region))
        undo_commands.append(aws_command("ec2 authorize-security-group-ingress", options, region))

    removing = "; ".join(summaries)
    terraform = (
        f"Remove these ingress rules from the Terraform that defines security group {group}: "
        f"{removing}. They are either ingress blocks inside the aws_security_group resource or "
        "aws_vpc_security_group_ingress_rule resources. Run terraform plan and check that only "
        "these rules are removed before applying.\n"
    )
    cloudformation = (
        "Remove these ingress rules from the CloudFormation template that defines security "
        f"group {group}: {removing}. They are either entries in SecurityGroupIngress of the "
        "AWS::EC2::SecurityGroup resource or AWS::EC2::SecurityGroupIngress resources. Review "
        "the change set and check that only these rules are removed before executing it.\n"
    )
    patches = [
        patch(
            "terraform",
            "Remove the open ingress rules (Terraform)",
            terraform,
            instructions_only=True,
        ),
        patch(
            "cloudformation",
            "Remove the open ingress rules (CloudFormation)",
            cloudformation,
            instructions_only=True,
        ),
        patch(
            "cli",
            "Remove the open ingress rules (AWS CLI)",
            "\n".join(lines) + "\n",
            files=files,
        ),
    ]
    pre_checks = [
        "Find out who connects to the instances today. Flow logs are not collected, so check "
        "them or ask the owners.",
        "Make sure there is another way in before removing the rule, such as SSM Session "
        "Manager, a VPN or a specific trusted address range.",
        "If a rule allows all ports and protocols, list what the attached instances serve "
        "before removing it.",
    ]
    rollback = "To add the rules back, using the same JSON files: " + " ".join(undo_commands)
    return fix(patches, [], pre_checks, rollback)


def wildcard_policy_guidance(finding: dict, resource: dict) -> dict:
    guidance = [
        "Open the policy and read the statements listed in the evidence.",
        "Find out which actions the users and roles that have this policy really use, from the "
        "last-accessed information in IAM and from CloudTrail, before removing anything.",
        'Replace Action "*" with the actions that are needed, and Resource "*" with specific '
        "resource ARNs where the service supports them.",
        "No patch is generated, because a safe least-privilege policy needs real usage data.",
    ]
    return fix([], guidance, [], "Nothing is generated, so there is nothing to roll back.")


def privilege_escalation_guidance(finding: dict, resource: dict) -> dict:
    guidance = [
        "For each method in the evidence, check whether the permissions are really needed.",
        "Remove a permission, or limit it to specific resources and add a condition. The "
        "evidence says which methods are already limited or conditional.",
        "Permission boundaries, service control policies and resource policies are not checked "
        "here, so see whether one of them already blocks the method.",
        "No patch is generated, because a safe least-privilege policy needs real usage data.",
    ]
    return fix([], guidance, [], "Nothing is generated, so there is nothing to roll back.")


BUILDERS = {
    "CIS-S3-001": public_access_block_fix,
    "CIS-S3-002": kms_encryption_fix,
    "CIS-S3-003": versioning_fix,
    "CIS-SG-001": open_security_group_fix,
    "CIS-IAM-001": wildcard_policy_guidance,
    "SX-IAM-PRIVESC-001": privilege_escalation_guidance,
}


def build_fix(finding: dict, resource: dict) -> dict:
    builder = BUILDERS.get(finding["rule_id"])
    if builder is None:
        guidance = ["No fix template exists for this rule yet."]
        return fix([], guidance, [], "Nothing to roll back.")
    return builder(finding, resource)
