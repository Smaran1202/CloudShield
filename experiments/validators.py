"""Checks for the patches CloudShield writes (E4).

Each check returns an empty string when the patch is valid, or the first problem it found.
"""

import importlib.util
import json
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml
from botocore import xform_name
from botocore.exceptions import UnknownServiceError
from botocore.loaders import Loader
from botocore.model import ServiceModel, Shape

# The AWS CLI names two services differently from botocore.
CLI_SERVICE_NAMES = {"s3api": "s3", "configservice": "config"}
LOADER = Loader()
TERRAFORM_HEADER = """terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

"""


def check_cli(content: str, files: list[dict]) -> str:
    """Checks every command against botocore's service model, which is read from files on this
    machine. The operation must exist, every option must be a parameter of it, the required
    parameters must be there, and values (and the JSON files they point to) must fit the shape."""
    texts = {file["name"]: file["content"] for file in files}
    commands = [line for line in content.splitlines() if line.strip() and line[0] != "#"]
    if not commands:
        return "the patch has no command"
    for command in commands:
        error = check_command(command, texts)
        if error:
            return error
    return ""


def check_command(command: str, files: dict[str, str]) -> str:
    words = shlex.split(command)
    if len(words) < 3 or words[0] != "aws":
        return f"not an aws command: {command}"
    service = CLI_SERVICE_NAMES.get(words[1], words[1])
    try:
        description = LOADER.load_service_model(service, "service-2")
    except UnknownServiceError:
        return f"unknown service {words[1]}"
    model = ServiceModel(description, service_name=service)
    operations = {xform_name(name, "-"): name for name in model.operation_names}
    if words[2] not in operations:
        return f"{service} has no operation {words[2]}"
    shape = model.operation_model(operations[words[2]]).input_shape
    members = shape.members if shape else {}

    flags, values = words[3::2], words[4::2]
    if len(flags) != len(values) or not all(flag.startswith("--") for flag in flags):
        return f"cannot read the options of: {command}"
    options = {flag.removeprefix("--"): value for flag, value in zip(flags, values, strict=True)}
    names = {xform_name(name, "-"): name for name in members}
    for option, text in options.items():
        if option == "region":
            continue
        if option not in names:
            return f"--{option} is not a parameter of {words[2]}"
        error = check_value(members[names[option]], text, files)
        if error:
            return f"--{option}: {error}"
    required = shape.required_members if shape else []
    missing = [name for name in required if xform_name(name, "-") not in options]
    return f"missing required parameters: {missing}" if missing else ""


def check_value(shape: Shape, text: str, files: dict[str, str]) -> str:
    if text.startswith("file://"):
        name = text.removeprefix("file://")
        if name not in files:
            return f"{name} is not one of the files of the patch"
        if shape.type_name == "string":
            return ""
        try:
            data = json.loads(files[name])
        except json.JSONDecodeError as exc:
            return f"{name} is not valid JSON ({exc.msg})"
        return check_json(shape, data, name)
    if shape.type_name == "structure":
        return check_shorthand(shape, text)
    if shape.type_name == "string":
        return check_enum(shape, text)
    return f"a {shape.type_name} on the command line is not covered by this check"


def check_enum(shape: Shape, value: str) -> str:
    allowed = shape.enum
    return f"{value} is not one of {allowed}" if allowed and value not in allowed else ""


def check_shorthand(shape: Shape, text: str) -> str:
    """The Key=value,Key=value form of a structure with simple members."""
    given = set()
    for pair in text.split(","):
        key, equals, value = pair.partition("=")
        if not equals or key not in shape.members:
            return f"{key or pair} is not a member of {shape.name}"
        given.add(key)
        member = shape.members[key]
        if member.type_name == "boolean" and value not in ("true", "false"):
            return f"{key} must be true or false, not {value}"
        if member.type_name == "string":
            error = check_enum(member, value)
            if error:
                return error
    missing = [name for name in shape.required_members if name not in given]
    return f"{shape.name} is missing {missing}" if missing else ""


def check_json(shape: Shape, data, where: str) -> str:
    kind = shape.type_name
    if kind == "structure":
        if not isinstance(data, dict):
            return f"{where} must be an object"
        for key, value in data.items():
            if key not in shape.members:
                return f"{where}.{key} is not a member of {shape.name}"
            error = check_json(shape.members[key], value, f"{where}.{key}")
            if error:
                return error
        missing = [name for name in shape.required_members if name not in data]
        return f"{where} is missing {missing}" if missing else ""
    if kind == "list":
        if not isinstance(data, list):
            return f"{where} must be a list"
        for index, item in enumerate(data):
            error = check_json(shape.member, item, f"{where}[{index}]")
            if error:
                return error
        return ""
    if kind == "string":
        return check_enum(shape, data) if isinstance(data, str) else f"{where} must be a string"
    if kind == "boolean":
        return "" if isinstance(data, bool) else f"{where} must be true or false"
    if kind in ("integer", "long"):
        ok = isinstance(data, int) and not isinstance(data, bool)
        return "" if ok else f"{where} must be a whole number"
    return f"{where} has the type {kind}, which this check does not cover"


def cfn_lint_installed() -> bool:
    return importlib.util.find_spec("cfnlint") is not None


def check_cloudformation(content: str) -> str:
    # cfn-lint exits with 0 for nothing found, 1 when it could not run, and adds 2 for an error,
    # 4 for a warning and 8 for an informational message. Only an error makes the patch invalid.
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "template.yaml"
        path.write_text(content, encoding="utf-8")
        command = [sys.executable, "-m", "cfnlint", "--format", "json", str(path)]
        done = subprocess.run(command, capture_output=True, text=True, timeout=120)
    if done.returncode == 1:
        raise RuntimeError(f"cfn-lint could not run: {done.stderr.strip()}")
    if not done.returncode & 2:
        return ""
    messages = [m for m in json.loads(done.stdout) if m.get("Level") == "Error"]
    if not messages:
        return "cfn-lint reported an error"
    return f"{messages[0].get('Rule', {}).get('Id', '')} {messages[0].get('Message', '')}"


def run_terraform(arguments: list[str], folder: str, env: dict) -> subprocess.CompletedProcess:
    command = ["terraform", *arguments]
    return subprocess.run(command, cwd=folder, env=env, capture_output=True, text=True)


def check_terraform(content: str, plugin_cache: Path) -> str:
    """terraform init downloads the AWS provider, so this needs the network. The plugin cache
    makes it happen once for all the patches."""
    env = {**os.environ, "TF_PLUGIN_CACHE_DIR": str(plugin_cache), "TF_IN_AUTOMATION": "1"}
    with tempfile.TemporaryDirectory() as folder:
        (Path(folder) / "main.tf").write_text(TERRAFORM_HEADER + content, encoding="utf-8")
        done = run_terraform(["init", "-backend=false", "-input=false", "-no-color"], folder, env)
        if done.returncode != 0:
            raise RuntimeError(f"terraform init failed: {done.stdout} {done.stderr}")
        done = run_terraform(["validate", "-json", "-no-color"], folder, env)
    report = json.loads(done.stdout)
    if report["valid"]:
        return ""
    errors = [d for d in report["diagnostics"] if d["severity"] == "error"]
    return f"{errors[0]['summary']}: {errors[0].get('detail', '')}"


def check_workflow(content: str) -> str:
    """A GitHub Actions workflow: valid YAML with a trigger and jobs that have a runner and steps.
    This is weaker than a workflow linter such as actionlint, which is not used here."""
    try:
        workflow = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        return f"not valid YAML: {exc}"
    if not isinstance(workflow, dict):
        return "the workflow is not a mapping"
    # YAML 1.1 reads the key "on" as the boolean True.
    if "on" not in workflow and True not in workflow:
        return "the workflow has no trigger (on)"
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        return "the workflow has no jobs"
    for name, job in jobs.items():
        if not isinstance(job, dict) or "runs-on" not in job:
            return f"job {name} has no runs-on"
        steps = job.get("steps")
        if not isinstance(steps, list) or not steps:
            return f"job {name} has no steps"
        if not all(isinstance(s, dict) and ("uses" in s or "run" in s) for s in steps):
            return f"a step of job {name} has neither uses nor run"
    return ""


def verdict(error: str) -> tuple[str, str]:
    clean = " ".join(error.split())
    return ("no", clean) if clean else ("yes", "")


def validate(patch: dict, plugin_cache: Path | None = None) -> tuple[str, str, str]:
    """Returns (validator, valid, error). valid is yes, no or skipped. plugin_cache is set only
    when terraform should be run."""
    kind = patch["format"]
    if patch["instructions_only"]:
        return "none", "skipped", "instructions only, there is no code to check"
    if kind == "cli":
        return ("botocore", *verdict(check_cli(patch["content"], patch["files"])))
    if kind == "github_actions":
        return ("yaml structure", *verdict(check_workflow(patch["content"])))
    if kind == "cloudformation":
        if not cfn_lint_installed():
            return "cfn-lint", "skipped", 'not installed: pip install -e ".[experiments]"'
        return ("cfn-lint", *verdict(check_cloudformation(patch["content"])))
    if kind == "terraform":
        if plugin_cache is None:
            return "terraform validate", "skipped", "not run here; the CI job runs it"
        return ("terraform validate", *verdict(check_terraform(patch["content"], plugin_cache)))
    raise ValueError(f"No check exists for the patch format {kind}")
