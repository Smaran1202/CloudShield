import textwrap
from pathlib import Path

FILE_NAMES = {"terraform": "fix.tf", "cloudformation": "fix.yaml", "cli": "fix.ps1"}


def comment(text: str) -> str:
    return "".join(f"# {line}\n" for line in textwrap.wrap(text.strip(), 90))


def explanation_line(generated_by: str, model: str | None, skipped_reason: str | None) -> str:
    if generated_by == "gemini":
        return f"# Explanation: written by {model}\n"
    reason = skipped_reason or "no reason was recorded"
    return f"# Explanation: template text. Gemini was not used: {reason}\n"


def write_fix_files(
    finding_id: str,
    patches: list[dict],
    directory: Path,
    explanation: str = "",
) -> list[Path]:
    directory.mkdir(parents=True, exist_ok=True)
    header = (
        f"# CloudShield fix for finding {finding_id}\n"
        "# Review this file before you use it. CloudShield has not run anything in your account.\n"
        f"{explanation}"
    )
    written = []
    for patch in patches:
        body = comment(patch["content"]) if patch["instructions_only"] else patch["content"]
        path = directory / FILE_NAMES[patch["format"]]
        path.write_text(f"{header}# {patch['title']}\n\n{body}", encoding="utf-8", newline="\n")
        written.append(path)
        for file in patch["files"]:
            if Path(file["name"]).name != file["name"]:
                raise ValueError(f"Unexpected file name: {file['name']!r}")
            extra = directory / file["name"]
            extra.write_text(file["content"], encoding="utf-8", newline="\n")
            written.append(extra)
    return written
