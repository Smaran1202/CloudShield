# "What to do" steps for imported findings, written by CloudShield in its own words from the AWS
# documentation page named in each entry. They are a starting point, not the scanner's text, and
# they are not stored: they are read from here each time a fix is requested.
#
# Rules for every entry:
# - A command is one line and read-only (list, get, describe). Anything that changes AWS is
#   described in words and never given as a command.
# - A step that needs a console menu path we have not checked in the documentation states the goal
#   in words and points to the documentation page instead.
# - <placeholders> stand for values the person fills in.
# - docs_url is an https page on an AWS domain, and verified_on is the day the page was read.
VERIFIED_ON = "2026-10-09"
IAM_GUIDE = "https://docs.aws.amazon.com/IAM/latest/UserGuide"
VPC_GUIDE = "https://docs.aws.amazon.com/vpc/latest/userguide"
S3_GUIDE = "https://docs.aws.amazon.com/AmazonS3/latest/userguide"

LIST_ENTITIES = "aws iam list-entities-for-policy --policy-arn {arn}"


def step(text: str, command: str | None = None) -> dict:
    return {"text": text, "command": command}


def entry(check_id: str, summary: str, steps: list, before: list, docs_url: str) -> dict:
    return {
        "check_id": check_id,
        "summary": summary,
        "steps": steps,
        "before_you_apply": before,
        "docs_url": docs_url,
        "verified_on": VERIFIED_ON,
    }


# The six password policy checks share this block, so a wording fix is made once.
PASSWORD_POLICY = {
    "see": step(
        "See the password policy the account has now.", "aws iam get-account-password-policy"
    ),
    "where": step(
        "In the IAM console, choose Account settings, then Edit in the Password policy "
        "section. Choose Custom, select the option and save the changes."
    ),
    "when": step(
        "The new rule applies the next time a user changes their password. Existing passwords "
        "are not forced to change."
    ),
    "before_you_apply": [
        "Tell your users first: the rule applies the next time they change their password.",
        "The password policy does not apply to the root user password or to access keys.",
    ],
    "docs_url": f"{IAM_GUIDE}/id_credentials_passwords_account-policy.html",
}

PASSWORD_CHECKS = {
    "iam_password_policy_minimum_length_14": (
        "The account password policy allows short passwords. Set the minimum length to 14.",
        "Set the minimum password length to 14 or more. AWS allows 6 to 128.",
    ),
    "iam_password_policy_uppercase": (
        "The account password policy does not require an uppercase letter.",
        "Turn on the option that requires at least one uppercase letter (A to Z).",
    ),
    "iam_password_policy_lowercase": (
        "The account password policy does not require a lowercase letter.",
        "Turn on the option that requires at least one lowercase letter (a to z).",
    ),
    "iam_password_policy_number": (
        "The account password policy does not require a number.",
        "Turn on the option that requires at least one number.",
    ),
    "iam_password_policy_symbol": (
        "The account password policy does not require a symbol.",
        "Turn on the option that requires at least one non-alphanumeric character.",
    ),
    "iam_password_policy_reuse_24": (
        "The account password policy lets people reuse recent passwords.",
        "Turn on the option that prevents password reuse and set it to remember 24 passwords. "
        "AWS allows 1 to 24.",
    ),
}


def password_entry(check_id: str, summary: str, setting: str) -> dict:
    steps = [
        PASSWORD_POLICY["see"],
        step(setting),
        PASSWORD_POLICY["where"],
        PASSWORD_POLICY["when"],
    ]
    return entry(
        check_id,
        summary,
        steps,
        PASSWORD_POLICY["before_you_apply"],
        PASSWORD_POLICY["docs_url"],
    )


def network_acl_entry(check_id: str, port_name: str) -> dict:
    return entry(
        check_id,
        f"A network ACL rule lets the whole internet reach {port_name} on the subnets that use it.",
        [
            step(
                "See the rules of the network ACL.",
                "aws ec2 describe-network-acls --network-acl-ids <acl-id>",
            ),
            step(
                f"The goal is to allow {port_name} only from addresses you trust, or to remove the "
                "rule. Rules are checked from the lowest number up, and the first one that "
                "matches is applied, so read the rule numbers before you change anything."
            ),
            step(
                "Network ACLs are stateless: a reply is not allowed just because the request "
                "was. Look at the outbound rules as well as the inbound ones."
            ),
            step(
                "Changes apply to every subnet that uses the ACL, after a short delay. See the "
                "AWS page on network ACL rules for how to change them."
            ),
        ],
        [
            "Find out which subnets use this network ACL, because a change applies to all of them.",
            "Find out who connects on that port today.",
        ],
        f"{VPC_GUIDE}/nacl-rules.html",
    )


ENTRIES = [
    entry(
        "iam_aws_attached_policy_no_administrative_privileges",
        "The AWS managed policy AdministratorAccess allows everything in the account. Find who "
        "has it, give them narrower permissions first, then detach it.",
        [
            step(
                "Find the users, groups and roles that have the policy attached.",
                LIST_ENTITIES.format(arn="arn:aws:iam::aws:policy/AdministratorAccess"),
            ),
            step(
                "For each one, look at what it has used recently, so you know which permissions "
                "it really needs. The IAM console shows this as last accessed information."
            ),
            step(
                "Give each one narrower permissions first: create a customer managed policy "
                "with only the actions it needs, and attach it."
            ),
            step(
                "Then detach AdministratorAccess from that user, group or role. In the IAM "
                "console choose Policies, select the policy, then Actions, then Detach."
            ),
            step("Ask the owners to confirm their work still runs, then run the full scan again."),
        ],
        [
            "Check who the policy is attached to (step 1): detaching it removes everything it "
            "allowed from each of them.",
            "Look at what each identity used recently before you remove anything.",
        ],
        f"{IAM_GUIDE}/access_policies_manage-attach-detach.html",
    ),
    entry(
        "iam_customer_unattached_policy_no_administrative_privileges",
        "This customer managed policy allows everything but is not attached to anyone now. It "
        "could be attached by mistake later. Narrow it or delete it.",
        [
            step(
                "Check that nothing uses the policy. The result should list no users, groups "
                "or roles.",
                LIST_ENTITIES.format(arn="<policy-arn>"),
            ),
            step(
                "If nobody needs it, delete it. In the IAM console choose Policies, select the "
                "policy, then Actions, then Delete. Deleting a policy is permanent."
            ),
            step(
                "If you still need it, edit it so it allows only the actions and resources that "
                "are needed. See the AWS page on editing IAM policies."
            ),
        ],
        [
            "Check the policy is not attached to anything (step 1).",
            "Look at the last accessed information first: deleting a policy cannot be undone.",
        ],
        f"{IAM_GUIDE}/access_policies_manage-delete-console.html",
    ),
    *[password_entry(check, *texts) for check, texts in PASSWORD_CHECKS.items()],
    entry(
        "s3_account_level_public_access_blocks",
        "Block Public Access is not fully on for the account. Turning on all four settings "
        "blocks public access for every bucket in the account.",
        [
            step(
                "See the account-level settings now. Put your 12-digit account number in the "
                "placeholder.",
                "aws s3control get-public-access-block --account-id <your-account-id>",
            ),
            step(
                "The goal is to turn on all four account-level settings: BlockPublicAcls, "
                "IgnorePublicAcls, BlockPublicPolicy and RestrictPublicBuckets. See the AWS page "
                "on configuring block public access settings for your account."
            ),
            step(
                "The settings apply to every bucket in the account and to all Regions. They "
                "override the policies and ACLs on the buckets but do not change them."
            ),
        ],
        [
            "Check for buckets that must stay public, for example one that hosts a static website.",
            "Check that your applications work without public access.",
        ],
        f"{S3_GUIDE}/access-control-block-public-access.html",
    ),
    network_acl_entry("ec2_networkacl_allow_ingress_tcp_port_22", "SSH (port 22)"),
    network_acl_entry("ec2_networkacl_allow_ingress_tcp_port_3389", "remote desktop (port 3389)"),
    entry(
        "ec2_securitygroup_not_used",
        "This security group is not attached to anything. An unused group can be attached later "
        "with open rules by mistake.",
        [
            step(
                "Check that no network interface uses the group. The result should be empty.",
                "aws ec2 describe-network-interfaces --filters Name=group-id,Values=<sg-id>",
            ),
            step(
                "If nothing uses it, delete it. AWS does not allow deleting a group that is "
                "attached to a resource, that another group's rule refers to, or that is the "
                "default group of a VPC."
            ),
            step(
                "In the VPC console choose Security groups, select the group, then Actions, then "
                "Delete security groups."
            ),
        ],
        [
            "Check that nothing is attached (step 1).",
            "Check that no other security group has a rule that refers to this one.",
        ],
        f"{VPC_GUIDE}/deleting-security-groups.html",
    ),
    entry(
        "iam_user_hardware_mfa_enabled",
        "This user does not have a hardware MFA device. A security key is harder to phish than "
        "a code from an app.",
        [
            step(
                "In the IAM console choose Users and look at the MFA column to see what the "
                "user has now."
            ),
            step(
                "See the virtual MFA devices in the account.",
                "aws iam list-virtual-mfa-devices",
            ),
            step(
                "The goal is to register a passkey or security key for the user. This can only "
                "be done in the AWS console, not with the CLI. See the AWS page on MFA."
            ),
            step(
                "A user can have up to eight MFA devices, so adding a security key does not "
                "remove the ones the user has."
            ),
        ],
        [
            "The user needs the physical security key at hand, because it can only be "
            "registered in the console.",
        ],
        f"{IAM_GUIDE}/id_credentials_mfa.html",
    ),
]

STEPS_BY_CHECK = {item["check_id"]: item for item in ENTRIES}


def guidance_for(check_id: str | None) -> dict | None:
    return STEPS_BY_CHECK.get(check_id) if check_id else None
