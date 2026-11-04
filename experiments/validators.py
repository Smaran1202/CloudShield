"""Checks for the patches CloudShield writes (E4).

Each check returns an empty string when the patch is valid, or the first problem it found.
"""

import json
import os
import shlex
import shutil
import subprocess
import sysconfig
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
CFN_LINT_EXIT_CODES = (0, 2, 4, 6, 8, 10, 12, 14)
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


def cfn_lint_command() -> str | None:
    """The cfn-lint command that pip installs. cfn-lint 1.59.0 has no __main__ module, so
    `python -m cfnlint` does not work; its only entry point is this console script. It is in the
    folder where this interpreter keeps its scripts, which is not always on the PATH."""
    return shutil.which("cfn-lint", path=sysconfig.get_path("scripts")) or shutil.which("cfn-lint")


def cfn_lint_installed() -> bool:
    return cfn_lint_command() is not None


def check_cloudformation(content: str) -> str:
    """Runs `cfn-lint --format json template.yaml`. Its documented exit codes are 0 for nothing
    found, and the sum of 2 (an error), 4 (a warning) and 8 (an informational message) for what it
    found. Anything else, such as 1 for a bad configuration, means it could not run. Only an error
    makes the patch invalid."""
    command = cfn_lint_command()
    if command is None:
        raise RuntimeError('cfn-lint is not installed: pip install -e ".[experiments]"')
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "template.yaml"
        path.write_text(content, encoding="utf-8")
        arguments = [command, "--format", "json", str(path)]
        done = subprocess.run(arguments, capture_output=True, text=True, timeout=120)
    code = done.returncode
    if code not in CFN_LINT_EXIT_CODES:
        # cfn-lint prints its own failure messages to stdout.
        raise RuntimeError(f"cfn-lint could not run (exit {code}): {done.stdout} {done.stderr}")
    if not code & 2:
        return ""
    try:
        matches = json.loads(done.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"cfn-lint printed output that is not JSON: {done.stdout}") from exc
    errors = [match for match in matches if match["Level"] == "Error"]
    if not errors:
        raise RuntimeError(f"cfn-lint exit {code} but its output has no error: {done.stdout}")
    return f"{errors[0]['Rule']['Id']} {errors[0]['Message']}"


def run_terraform(arguments: list[str], folder: Path) -> subprocess.CompletedProcess:
    command = ["terraform", *arguments]
    env = {**os.environ, "TF_IN_AUTOMATION": "1"}
    return subprocess.run(command, cwd=folder, env=env, capture_output=True, text=True)


def prepare_terraform(folder: Path) -> None:
    """Writes the provider block and runs terraform init, once. It downloads the AWS provider, so
    it needs the network. validate then reuses the installed provider for every patch, because
    only main.tf changes between patches."""
    (folder / "main.tf").write_text(TERRAFORM_HEADER, encoding="utf-8")
    done = run_terraform(["init", "-backend=false", "-input=false", "-no-color"], folder)
    if done.returncode != 0:
        raise RuntimeError(f"terraform init failed (exit {done.returncode}): {done.stdout}")


def check_terraform(content: str, folder: Path) -> str:
    """Runs `terraform validate -json` in a folder that prepare_terraform has set up. The JSON
    report has `valid` and a list of `diagnostics` with a `severity` of error or warning, a
    `summary` and a `detail`. A warning does not make the configuration invalid."""
    (folder / "main.tf").write_text(TERRAFORM_HEADER + content, encoding="utf-8")
    done = run_terraform(["validate", "-json", "-no-color"], folder)
    try:
        report = json.loads(done.stdout)
    except json.JSONDecodeError as exc:
        message = f"terraform validate printed output that is not JSON (exit {done.returncode})"
        raise RuntimeError(f"{message}: {done.stdout} {done.stderr}") from exc
    if report["valid"]:
        return ""
    errors = [d for d in report["diagnostics"] if d["severity"] == "error"]
    if not errors:
        raise RuntimeError(f"terraform validate said invalid with no error: {done.stdout}")
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


def validate(patch: dict, terraform_dir: Path | None = None) -> tuple[str, str, str]:
    """Returns (validator, valid, error). valid is yes, no or skipped. terraform_dir is set only
    when terraform should be run (see prepare_terraform)."""
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
        if terraform_dir is None:
            return "terraform validate", "skipped", "not run here; the CI job runs it"
        return ("terraform validate", *verdict(check_terraform(patch["content"], terraform_dir)))
    raise ValueError(f"No check exists for the patch format {kind}")
