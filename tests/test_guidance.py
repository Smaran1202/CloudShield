import re
from datetime import date
from urllib.parse import urlparse

import pytest

from cloudshield.imports import guidance
from cloudshield.imports.guidance import ENTRIES, PASSWORD_CHECKS, PASSWORD_POLICY, guidance_for

EXPECTED = {
    "iam_aws_attached_policy_no_administrative_privileges",
    "iam_customer_unattached_policy_no_administrative_privileges",
    "iam_password_policy_minimum_length_14",
    "iam_password_policy_uppercase",
    "iam_password_policy_lowercase",
    "iam_password_policy_number",
    "iam_password_policy_symbol",
    "iam_password_policy_reuse_24",
    "s3_account_level_public_access_blocks",
    "ec2_networkacl_allow_ingress_tcp_port_22",
    "ec2_networkacl_allow_ingress_tcp_port_3389",
    "ec2_securitygroup_not_used",
    "iam_user_hardware_mfa_enabled",
}
READ_ONLY_PREFIXES = (
    "aws iam list-",
    "aws iam get-",
    "aws s3control get-",
    "aws ec2 describe-",
)
WRITE_WORDS = re.compile(
    r"\b(create|delete|put|attach|detach|update|remove|add|set|enable|disable|tag|modify|"
    r"revoke|authorize|terminate|replace|associate|disassociate|deactivate|upload|import)\b",
    re.IGNORECASE,
)
# Parts of a command that could chain, redirect or substitute something.
SHELL_TRICKS = re.compile(r"[;|&<>$`\n\\]")
LOCKOUT_PHRASES = (
    "another way to sign in",
    "another way to reach",
    "one thing at a time",
)


def commands(item: dict) -> list[str]:
    return [s["command"] for s in item["steps"] if s["command"]]


def all_text(item: dict) -> str:
    texts = [item["summary"], *item["before_you_apply"]]
    texts += [s["text"] for s in item["steps"]]
    return " ".join(texts)


def test_there_is_an_entry_for_each_agreed_check_and_no_others():
    assert {item["check_id"] for item in ENTRIES} == EXPECTED
    assert len(ENTRIES) == len(EXPECTED)


def test_every_entry_has_all_its_parts():
    for item in ENTRIES:
        assert set(item) == {
            "check_id",
            "summary",
            "steps",
            "before_you_apply",
            "docs_url",
            "verified_on",
        }
        assert item["summary"].strip()
        assert item["steps"]
        assert item["before_you_apply"]
        for step in item["steps"]:
            assert set(step) == {"text", "command"}
            assert step["text"].strip()


def test_every_documentation_link_is_https_on_an_aws_domain():
    for item in ENTRIES:
        url = urlparse(item["docs_url"])
        assert url.scheme == "https", item["check_id"]
        assert url.netloc == "docs.aws.amazon.com", item["check_id"]
        assert url.path.endswith(".html"), item["check_id"]


def test_every_entry_says_the_day_its_page_was_read():
    for item in ENTRIES:
        assert date.fromisoformat(item["verified_on"]) <= date.today()


def test_every_command_is_one_line_and_read_only():
    found = [(item["check_id"], c) for item in ENTRIES for c in commands(item)]

    assert found
    for check_id, command in found:
        assert command.startswith(READ_ONLY_PREFIXES), (check_id, command)
        assert not SHELL_TRICKS.search(command.replace("<", "").replace(">", "")), command
        assert not WRITE_WORDS.search(command), (check_id, command)


def test_commands_hold_only_placeholders_never_real_ids():
    for item in ENTRIES:
        for command in commands(item):
            filled = re.sub(r"<[a-z-]+>", "", command)
            assert not re.search(r"\b\d{12}\b", filled), command
            assert "<" not in filled and ">" not in filled


def test_anything_that_changes_aws_is_described_in_words_and_not_given_as_a_command():
    changing = re.compile(r"\b(detach|delete|attach|enable|disable|update|put)-", re.IGNORECASE)
    for item in ENTRIES:
        assert not any(changing.search(c) for c in commands(item))


def test_no_entry_uses_lockout_wording():
    for item in ENTRIES:
        text = all_text(item).lower()
        for phrase in LOCKOUT_PHRASES:
            assert phrase not in text, (item["check_id"], phrase)


def test_no_entry_copies_the_scanner_markdown():
    for item in ENTRIES:
        assert "**" not in all_text(item)
        assert "`" not in all_text(item)


def test_steps_that_need_a_menu_path_we_did_not_check_use_goals_and_a_link_instead():
    by_id = {item["check_id"]: item for item in ENTRIES}

    s3 = all_text(by_id["s3_account_level_public_access_blocks"])
    nacl = all_text(by_id["ec2_networkacl_allow_ingress_tcp_port_22"])
    mfa = all_text(by_id["iam_user_hardware_mfa_enabled"])
    customer = all_text(by_id["iam_customer_unattached_policy_no_administrative_privileges"])

    assert "<your-account-id>" in commands(by_id["s3_account_level_public_access_blocks"])[0]
    assert "goal is to turn on all four" in s3
    assert "choose" not in nacl.lower()
    assert "only be done in the AWS console" in mfa
    assert "See the AWS page on editing IAM policies" in customer


def test_the_six_password_entries_share_one_block_of_wording():
    by_id = {item["check_id"]: item for item in ENTRIES}
    password = [by_id[check] for check in PASSWORD_CHECKS]

    assert len(password) == 6
    for item in password:
        assert item["steps"][0] == PASSWORD_POLICY["see"]
        assert item["steps"][2] == PASSWORD_POLICY["where"]
        assert item["steps"][3] == PASSWORD_POLICY["when"]
        assert item["before_you_apply"] == PASSWORD_POLICY["before_you_apply"]
        assert item["docs_url"] == PASSWORD_POLICY["docs_url"]
    assert len({item["steps"][1]["text"] for item in password}) == 6
    assert len({item["summary"] for item in password}) == 6


def test_the_password_ranges_in_the_wording_match_what_the_documentation_says():
    by_id = {item["check_id"]: item for item in ENTRIES}

    length = all_text(by_id["iam_password_policy_minimum_length_14"])
    reuse = all_text(by_id["iam_password_policy_reuse_24"])

    assert "6 to 128" in length
    assert "remember 24 passwords" in reuse
    assert "1 to 24" in reuse


def test_a_wording_fix_in_the_shared_block_reaches_all_six(monkeypatch):
    monkeypatch.setitem(PASSWORD_POLICY, "when", {"text": "Changed.", "command": None})

    rebuilt = [guidance.password_entry(check, *texts) for check, texts in PASSWORD_CHECKS.items()]

    assert all(item["steps"][3]["text"] == "Changed." for item in rebuilt)


def test_the_lookup_finds_an_entry_and_gives_nothing_for_other_checks():
    assert guidance_for("ec2_securitygroup_not_used")["check_id"] == "ec2_securitygroup_not_used"
    assert guidance_for("s3_bucket_cross_region_replication") is None
    assert guidance_for(None) is None
    assert guidance_for("") is None


def test_the_administrator_policy_entry_gives_the_agreed_command():
    item = guidance_for("iam_aws_attached_policy_no_administrative_privileges")

    assert commands(item) == [
        "aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
    ]
    texts = [s["text"] for s in item["steps"]]
    assert "narrower" in texts[2]
    assert "detach" in texts[3].lower()
    assert texts.index(texts[2]) < texts.index(texts[3])


@pytest.mark.parametrize("item", ENTRIES, ids=lambda item: item["check_id"])
def test_every_entry_text_is_plain_sentences(item):
    for text in [item["summary"], *item["before_you_apply"], *[s["text"] for s in item["steps"]]]:
        assert text.strip() == text
        assert text.endswith(".")
