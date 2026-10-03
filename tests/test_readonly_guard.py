import ast
from pathlib import Path

ALLOWED_PREFIXES = ("get_", "list_", "describe_", "head_")
SCANNER = Path(__file__).resolve().parents[1] / "src" / "cloudshield" / "scanner"


def boto3_violations(source: str) -> list[str]:
    """Names of boto3 operations in the source that do not start with an allowed prefix."""
    tree = ast.parse(source)
    clients = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            call = node.value
            if isinstance(call.func, ast.Attribute) and call.func.attr in ("client", "resource"):
                clients.update(t.id for t in node.targets if isinstance(t, ast.Name))

    used = []
    for node in ast.walk(tree):
        # s3.get_bucket_policy, whether it is called or passed along to be called later
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if node.value.id in clients:
                used.append(node.attr)
        # list_all(client, "list_policies", ...) and client.get_paginator("list_policies")
        if isinstance(node, ast.Call):
            name = node.func.id if isinstance(node.func, ast.Name) else None
            if name == "list_all" and len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
                used.append(node.args[1].value)
            method = node.func.attr if isinstance(node.func, ast.Attribute) else None
            is_paginator = method == "get_paginator"
            if is_paginator and node.args and isinstance(node.args[0], ast.Constant):
                used.append(node.args[0].value)
    return sorted({name for name in used if not name.startswith(ALLOWED_PREFIXES)})


def test_the_scanner_only_uses_read_only_boto3_operations():
    sources = sorted(SCANNER.glob("*.py"))

    violations = {path.name: boto3_violations(path.read_text(encoding="utf-8")) for path in sources}

    assert len(sources) >= 8
    assert {name: found for name, found in violations.items() if found} == {}


def test_the_guard_finds_the_operations_the_scanner_really_uses():
    source = (SCANNER / "iam.py").read_text(encoding="utf-8")
    nodes = ast.walk(ast.parse(source))
    tree_names = {node.attr for node in nodes if isinstance(node, ast.Attribute)}

    assert "get_policy_version" in tree_names
    assert boto3_violations(source) == []


def test_the_guard_catches_a_write_call_made_directly():
    source = 'iam = session.client("iam")\niam.put_role_policy(RoleName="r")\n'

    assert boto3_violations(source) == ["put_role_policy"]


def test_the_guard_catches_a_write_call_passed_as_a_function():
    source = 's3 = session.client("s3")\nattempt(errors, where, s3.delete_bucket, Bucket="b")\n'

    assert boto3_violations(source) == ["delete_bucket"]


def test_the_guard_catches_a_write_operation_named_in_a_paginator_or_list_all():
    source = (
        'iam = session.client("iam")\n'
        'list_all(iam, "create_user", "Users")\n'
        'iam.get_paginator("delete_things")\n'
    )

    assert boto3_violations(source) == ["create_user", "delete_things"]


def test_the_guard_allows_get_list_describe_and_head():
    source = (
        'ec2 = session.client("ec2")\n'
        "ec2.describe_instances()\n"
        "ec2.get_paginator\n"
        'list_all(ec2, "list_things", "Things")\n'
        "ec2.head_thing()\n"
    )

    assert boto3_violations(source) == []
