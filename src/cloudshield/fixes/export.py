import textwrap
from pathlib import Path

FILE_NAMES = {"terraform": "fix.tf", "cloudformation": "fix.yaml", "cli": "fix.ps1"}
GUARDRAIL_FILE_NAMES = {
    "terraform": "guardrail.tf",
    "cloudformation": "guardrail.yaml",
    "cli": "guardrail.ps1",
    "github_actions": "workflow.yml",
}
REVIEW = "# Review this file before you use it. CloudShield has not run anything in your account.\n"


def comment(text: str) -> str:
    return "".join(f"# {line}\n" for line in textwrap.wrap(text.strip(), 90))


def explanation_line(generated_by: str, model: str | None, skipped_reason: str | None) -> str:
    if generated_by == "gemini":
        return f"# Explanation: written by {model}\n"
    reason = skipped_reason or "no reason was recorded"
    return f"# Explanation: template text. Gemini was not used: {reason}\n"


def write_patches(
    patches: list[dict], directory: Path, file_names: dict[str, str], header: str
) -> list[Path]:
    directory.mkdir(parents=True, exist_ok=True)
    written = []
    for patch in patches:
        body = comment(patch["content"]) if patch["instructions_only"] else patch["content"]
        path = directory / file_names[patch["format"]]
        path.write_text(f"{header}# {patch['title']}\n\n{body}", encoding="utf-8", newline="\n")
        written.append(path)
        for file in patch["files"]:
            if Path(file["name"]).name != file["name"]:
                raise ValueError(f"Unexpected file name: {file['name']!r}")
            extra = directory / file["name"]
            extra.write_text(file["content"], encoding="utf-8", newline="\n")
            written.append(extra)
    return written


def write_fix_files(
    finding_id: str,
    patches: list[dict],
    directory: Path,
    explanation: str = "",
) -> list[Path]:
    header = f"# CloudShield fix for finding {finding_id}\n{REVIEW}{explanation}"
    return write_patches(patches, directory, FILE_NAMES, header)


def write_guardrail_files(guardrails: list[dict], directory: Path) -> list[Path]:
    """One folder per guardrail under directory/guardrails, with its patches as files. A GitHub
    Actions file is a ready-to-copy workflow for .github/workflows/ in the owner's repository."""
    written = []
    for guardrail in guardrails:
        header = (
            f"# CloudShield guardrail: {guardrail['title']}\n"
            f"{REVIEW}"
            f"{comment('What it prevents: ' + guardrail['prevents'])}"
            f"{comment('What it affects: ' + guardrail['affects'])}"
        )
        folder = directory / "guardrails" / guardrail["id"]
        written += write_patches(guardrail["patches"], folder, GUARDRAIL_FILE_NAMES, header)
    return written
